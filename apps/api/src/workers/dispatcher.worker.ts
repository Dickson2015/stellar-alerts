import https from "node:https";
import { Worker, type ConnectionOptions } from "bullmq";
import { redis, registerRedisCleanupTask } from "../lib/redis";
import { createLogger } from "../lib/logger";
import {
  QueueLaneManager,
  type QueueLane,
  QUEUE_LANE_CONFIGS,
  resolveLaneForAlert,
} from "../lib/queue-lanes";
import {
  fairShareQueueScheduler,
  SUBSCRIBER_TIERS,
} from "../lib/queue/fair-scheduler";
import {
  RedisCircuitBreaker,
  CircuitBreakerOpenError,
} from "../modules/alerts/circuit-breaker";
import { isChatSnoozed } from "../modules/telegram/commands/snooze";
import { webhookTelemetry } from "../modules/webhooks/webhook-telemetry";
import {
  ssrfFilter,
  SsrfFilter,
  SsrfBlockedError,
  type PinnedWebhookTarget,
} from "../modules/webhooks/ssrf-filter";
import { alertStormBundler } from "../modules/notifications/storm-bundler";
import { WorkerScaler } from "../lib/worker-scaler";

const log = createLogger({ module: "WebhookDispatcherWorker" });

export interface WebhookDispatchJobData {
  webhookId: string;
  url: string;
  payload: Record<string, any>;
  headers?: Record<string, string>;
  traceparent?: string;
  paymentId?: string;
  /** Priority lane hint. If omitted, lane is derived from severity metadata. */
  lane?: QueueLane;
  /** Severity of the underlying alert rule (critical/high/standard/bulk). */
  severity?: string;
  /** Tenant/subscriber ID for fair scheduling */
  tenantId?: string;
  /** Subscriber tier for rate limiting (free/professional/enterprise) */
  subscriberTier?: string;
  /** Rule ID for alert storm bundling */
  ruleId?: string;
  /** Alert metadata for bundling (amount, fromAddress, etc.) */
  alertData?: Record<string, any>;
  /** Per-webhook field masking policy applied before signing (#990). */
  maskingPolicy?: MaskingPolicy | null;
  /** Optional Matrix protocol room target for native Matrix alert dispatch (#1003). */
  matrixConfig?: MatrixDispatchTarget;
}

export interface WebhookDispatchResult {
  webhookId: string;
  status: "delivered" | "skipped" | "failed";
  statusCode?: number;
  durationMs?: number;
  reason?: string;
  pinnedIp?: string;
  lane?: QueueLane;
  eventId?: string;
  txnId?: string;
  retryAfterMs?: number;
}

export type WebhookTransportFn = (
  url: string,
  payload: string,
  headers: Record<string, string>,
  pinnedTarget?: PinnedWebhookTarget,
) => Promise<{ status: number; body?: string }>;

/**
 * Produces signature headers for the exact body that will be sent. Called
 * AFTER masking so the signature covers the masked bytes.
 */
export type WebhookSignerFn = (
  webhookId: string,
  body: string,
) => Promise<Record<string, string>>;

const SIGNATURE_HEADER_NAMES = ["x-stellar-signature", "x-signature-secondary"];

export class DispatcherWorker {
  private signer?: WebhookSignerFn;
  private circuitBreaker: RedisCircuitBreaker;
  private workers: Map<QueueLane, Worker<WebhookDispatchJobData>> = new Map();
  private transport: WebhookTransportFn;
  private ssrfFilter: SsrfFilter;
  private laneManager: QueueLaneManager;
  private scaler: WorkerScaler | null = null;

  constructor(
    circuitBreaker?: RedisCircuitBreaker,
    transport?: WebhookTransportFn,
    filter?: SsrfFilter,
    laneManager?: QueueLaneManager,
    signer?: WebhookSignerFn,
    customMatrixDispatcher?: MatrixDispatcher,
  ) {
    this.signer = signer;
    this.circuitBreaker = circuitBreaker || new RedisCircuitBreaker();
    this.transport = transport || this.defaultTransport.bind(this);
    this.ssrfFilter = filter || ssrfFilter;
    this.laneManager = laneManager || new QueueLaneManager();
    this.matrixDispatcher = customMatrixDispatcher || matrixDispatcher;
  }

  private async defaultTransport(
    url: string,
    payload: string,
    headers: Record<string, string>,
    pinnedTarget?: PinnedWebhookTarget,
  ) {
    const target =
      pinnedTarget ?? (await this.ssrfFilter.validateAndResolve(url));

    if (target.parsedUrl.protocol === "http:") {
      const res = await fetch(target.pinnedUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Host: target.hostHeader,
          "X-Validated-Egress-IP": target.pinnedIp,
          ...headers,
        },
        body: payload,
        redirect: "manual",
      });
      return { status: res.status, body: await res.text() };
    }

    return this.postHttpsPinned(target, payload, headers);
  }

  /** HTTPS POST that connects ONLY to the already-validated IP (stops DNS rebinding). */
  private postHttpsPinned(
    target: PinnedWebhookTarget,
    payload: string,
    headers: Record<string, string>,
  ): Promise<{ status: number; body?: string }> {
    return new Promise((resolve, reject) => {
      const { parsedUrl, pinnedIp } = target;
      const family = pinnedIp.includes(":") ? 6 : 4;

      const req = https.request(
        {
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || 443,
          path: parsedUrl.pathname + parsedUrl.search,
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(payload),
            ...headers,
          },
          // Always connect to the validated IP, never re-resolve DNS.
          lookup: (_host: string, opts: any, cb: any) => {
            if (opts && opts.all)
              return cb(null, [{ address: pinnedIp, family }]);
            return cb(null, pinnedIp, family);
          },
          timeout: 10000,
        },
        (res) => {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (chunk) => (body += chunk));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
        },
      );

      req.on("timeout", () =>
        req.destroy(new Error("Webhook request timed out")),
      );
      req.on("error", reject);
      req.write(payload);
      req.end();
    });
  }

  /**
   * Processes a single webhook dispatch job.
   * 1. Applies alert storm bundling to prevent fatigue during batch payouts.
   * 2. Checks fair scheduling limits per tenant.
   * 3. Checks circuit breaker state.
   * 4. Validates target URL and resolves/pins IP via SsrfFilter (rejecting private/internal IPs).
   * 5. Dispatches webhook with pinned IP target.
   */
  public async processJob(job: {
    data: WebhookDispatchJobData;
  }): Promise<WebhookDispatchResult> {
    const {
      webhookId,
      url,
      payload,
      headers = {},
      paymentId,
      tenantId,
      subscriberTier,
      ruleId,
      alertData,
      severity,
      maskingPolicy,
      matrixConfig,
    } = job.data;
    const lane: QueueLane = job.data.lane ?? resolveLaneForAlert(job.data);

    // Apply alert storm bundling if ruleId is present
    if (ruleId && alertData) {
      const stormResult = alertStormBundler.processAlert({
        ruleId,
        severity: severity || "standard",
        alert: alertData,
      });

      if (!stormResult.dispatch && stormResult.bundle) {
        // Alert exceeds threshold; defer for bundling
        log.debug(
          { webhookId, ruleId, totalCount: stormResult.bundle.totalCount },
          "Alert deferred: exceeds storm threshold, bundling with similar alerts",
        );
        return {
          webhookId,
          status: "skipped",
          reason: "deferred_for_bundling",
          lane,
        };
      }
    }

    // Fair scheduling check: prevent tenant monopolization
    if (tenantId) {
      const tierName = subscriberTier || "professional";
      const tier = SUBSCRIBER_TIERS[tierName] || SUBSCRIBER_TIERS.professional;

      const canSchedule = await fairShareQueueScheduler.canScheduleJob(
        tenantId,
        tierName,
        0,
      );

      if (!canSchedule.canProcess) {
        log.debug(
          { webhookId, tenantId, waitTimeMs: canSchedule.waitTimeMs, lane },
          "⏳ Webhook deferred due to subscriber rate limit",
        );
        // Defer this job with exponential backoff
        const delayMs = Math.min(canSchedule.waitTimeMs, 5000) + 100;
        throw new Error(`Rate limited, retry after ${delayMs}ms`);
      }
    }

    // Check circuit breaker state first
    const canSend = await this.circuitBreaker.canExecute(webhookId);
    if (!canSend) {
      log.warn(
        { webhookId, url, lane },
        `[DispatcherWorker] Circuit breaker OPEN for webhook ${webhookId}; skipping network call`,
      );
      return {
        webhookId,
        status: "skipped",
        reason: "circuit_breaker_open",
        lane,
      };
    }

    // Check if destination Telegram chat is currently snoozed (#896)
    const tgChatId =
      payload?.telegramChatId ||
      payload?.chat_id ||
      (job.data as any).telegramChatId;
    if (tgChatId && (await isChatSnoozed(String(tgChatId)))) {
      log.info(
        { webhookId, chatId: tgChatId, lane },
        "[DispatcherWorker] Telegram destination chat is snoozed; skipping delivery",
      );
      return {
        webhookId,
        status: "skipped",
        reason: "telegram_chat_snoozed",
        lane,
      };
    }

    const targetUrl = matrixConfig ? matrixConfig.homeserverUrl : url;
    let pinnedTarget: PinnedWebhookTarget;
    try {
      pinnedTarget = await this.ssrfFilter.validateAndResolve(targetUrl);
    } catch (err: any) {
      const statusCode = err instanceof SsrfBlockedError ? err.statusCode : 400;
      log.error(
        { webhookId, url: targetUrl, reason: err.reason ?? err.message, statusCode, lane },
        "[SECURITY_AUDIT] Blocked webhook dispatch due to SSRF egress policy",
      );
      return {
        webhookId,
        status: "failed",
        statusCode,
        reason: err.message,
        lane,
      };
    }

    // Native Matrix protocol room dispatch (#1003)
    if (matrixConfig) {
      const maskedPayload = applyMaskingPolicy(payload, maskingPolicy).payload;
      const matrixAlert: MatrixAlertPayload = {
        alertId: String(
          paymentId ?? maskedPayload.paymentId ?? maskedPayload.txHash ?? webhookId,
        ),
        title: typeof maskedPayload.title === "string" ? maskedPayload.title : undefined,
        severity: severity ?? (typeof maskedPayload.severity === "string" ? maskedPayload.severity : undefined),
        message: typeof maskedPayload.message === "string" ? maskedPayload.message : undefined,
        txHash: typeof maskedPayload.txHash === "string" ? maskedPayload.txHash : undefined,
        amount:
          typeof maskedPayload.amount === "string" || typeof maskedPayload.amount === "number"
            ? maskedPayload.amount
            : undefined,
        asset: typeof maskedPayload.asset === "string" ? maskedPayload.asset : undefined,
        fromAddress:
          typeof maskedPayload.fromAddress === "string" ? maskedPayload.fromAddress : undefined,
        walletId: typeof maskedPayload.walletId === "string" ? maskedPayload.walletId : undefined,
        memo: typeof maskedPayload.memo === "string" ? maskedPayload.memo : null,
        receivedAt:
          typeof maskedPayload.receivedAt === "string" ? maskedPayload.receivedAt : undefined,
      };

      try {
        const { result: matrixResult, durationMs } =
          await webhookTelemetry.measureDispatch(
            webhookId,
            matrixConfig.homeserverUrl,
            async () => {
              return await this.circuitBreaker.execute(webhookId, async () => {
                const res = await this.matrixDispatcher.dispatchAlert(
                  matrixConfig,
                  matrixAlert,
                );
                if (!res.success && (res.statusCode ?? 0) >= 500) {
                  const err: any = new Error(
                    res.error ?? `Matrix homeserver returned HTTP ${res.statusCode}`,
                  );
                  err.statusCode = res.statusCode;
                  throw err;
                }
                return res;
              });
            },
            paymentId,
          );

        if (!matrixResult.success) {
          return {
            webhookId,
            status: "failed",
            statusCode: matrixResult.statusCode,
            durationMs,
            reason: matrixResult.error,
            txnId: matrixResult.txnId,
            retryAfterMs: matrixResult.retryAfterMs,
            lane,
          };
        }

        return {
          webhookId,
          status: "delivered",
          statusCode: matrixResult.statusCode ?? 200,
          durationMs,
          pinnedIp: pinnedTarget.pinnedIp,
          eventId: matrixResult.eventId,
          txnId: matrixResult.txnId,
          lane,
        };
      } catch (err: any) {
        if (err instanceof CircuitBreakerOpenError) {
          log.warn(
            { webhookId, lane },
            "Fast-fail: circuit breaker opened during Matrix dispatch",
          );
          return {
            webhookId,
            status: "skipped",
            reason: "circuit_breaker_open",
            lane,
          };
        }
        log.error(
          { webhookId, lane, err: err.message },
          "Matrix alert delivery failed",
        );
        return {
          webhookId,
          status: "failed",
          reason: err.message,
          lane,
        };
      }
    }

    let payloadStr: string;
    let sendHeaders = headers;
    try {
      // Mask first, sign second: the signature must cover the masked bytes.
      const masked = applyMaskingPolicy(payload, maskingPolicy);
      payloadStr = JSON.stringify(masked.payload);
      if (masked.maskedCount > 0) {
        log.debug(
          { webhookId, maskedCount: masked.maskedCount, paths: masked.appliedPaths },
          "Applied webhook field masking policy",
        );
        const hasStaleSignature = Object.keys(headers).some((h) =>
          SIGNATURE_HEADER_NAMES.includes(h.toLowerCase()),
        );
        if (this.signer) {
          const fresh = await this.signer(webhookId, payloadStr);
          sendHeaders = {
            ...Object.fromEntries(
              Object.entries(headers).filter(
                ([h]) => !SIGNATURE_HEADER_NAMES.includes(h.toLowerCase()),
              ),
            ),
            ...fresh,
          };
        } else if (hasStaleSignature) {
          // Fail closed: never deliver a signature that no longer matches.
          throw new Error(
            "Masking policy changed the payload but no signer is configured to re-sign it",
          );
        }
      }
    } catch (err: any) {
      log.error({ webhookId, lane, err: err.message }, "Webhook masking/signing failed");
      return { webhookId, status: "failed", reason: err.message, lane };
    }

    try {
      const { result: res, durationMs } =
        await webhookTelemetry.measureDispatch(
          webhookId,
          url,
          async () => {
            return await this.circuitBreaker.execute(webhookId, async () => {
              const response = await this.transport(
                url,
                payloadStr,
                sendHeaders,
                pinnedTarget,
              );
              if (response.status >= 500) {
                const err: any = new Error(
                  `Server returned HTTP ${response.status}`,
                );
                err.statusCode = response.status;
                throw err;
              }
              return response;
            });
          },
          paymentId,
        );

      return {
        webhookId,
        status: "delivered",
        statusCode: res.status,
        durationMs,
        pinnedIp: pinnedTarget.pinnedIp,
        lane,
      };
    } catch (err: any) {
      if (err instanceof CircuitBreakerOpenError) {
        log.warn(
          { webhookId, lane },
          "Fast-fail: circuit breaker opened during dispatch",
        );
        return {
          webhookId,
          status: "skipped",
          reason: "circuit_breaker_open",
          lane,
        };
      }

      log.error(
        { webhookId, lane, err: err.message },
        "Webhook delivery failed",
      );
      return {
        webhookId,
        status: "failed",
        reason: err.message,
        lane,
      };
    }
  }

  /**
   * Starts dedicated workers for each priority lane.
   *
   * Each lane gets its own BullMQ Worker bound to its lane-specific queue name,
   * so critical jobs are never head-of-line blocked behind bulk jobs. The
   * concurrency for each lane is taken from QUEUE_LANE_CONFIGS, which guarantees
   * minimum capacity for critical/high lanes.
   */
  public start(baseQueueName = "webhook-dispatch") {
    for (const lane of Object.keys(QUEUE_LANE_CONFIGS) as QueueLane[]) {
      const config = QUEUE_LANE_CONFIGS[lane];
      const queueName = this.laneManager.getQueueName(lane, baseQueueName);
      const worker = new Worker<WebhookDispatchJobData>(
        queueName,
        async (job) => this.processJob(job),
        {
          connection: redis as unknown as ConnectionOptions,
          concurrency: config.concurrency,
        },
      );

      worker.on("failed", (job, error) => {
        log.error(
          { lane, jobId: job?.id, err: error.message },
          "Webhook dispatch job failed in lane",
        );
      });

      this.workers.set(lane, worker);
      log.info(
        { lane, queueName, concurrency: config.concurrency },
        "Started priority lane dispatcher worker",
      );
    }

    this.startAutoscaler(baseQueueName);

    registerRedisCleanupTask(async () => {
      this.scaler?.stop();
      this.scaler = null;
      await Promise.all(
        Array.from(this.workers.values()).map((w) => w.close()),
      );
      this.workers.clear();
    });

    return this.workers;
  }

  /**
   * Attaches the adaptive worker scaler (#915). The scaler watches queue
   * backlog, event-loop lag and heap pressure, then redistributes the new
   * total concurrency across lanes in proportion to their configured shares.
   */
  private startAutoscaler(baseQueueName: string): void {
    const lanes = Object.keys(QUEUE_LANE_CONFIGS) as QueueLane[];
    const baseTotal = lanes.reduce((sum, lane) => sum + QUEUE_LANE_CONFIGS[lane].concurrency, 0);
    const queueKeys = lanes.map(
      (lane) => `bull:${this.laneManager.getQueueName(lane, baseQueueName)}:wait`,
    );

    this.scaler = new WorkerScaler(redis as any, baseTotal, {
      workerName: "webhook-dispatcher",
      queueKeys,
    });

    this.scaler.on("scale", (_previous, next, direction, reason) => {
      let assigned = 0;
      lanes.forEach((lane, index) => {
        const worker = this.workers.get(lane);
        if (!worker) return;
        const share =
          index === lanes.length - 1
            ? Math.max(1, next - assigned)
            : Math.max(1, Math.round((next * QUEUE_LANE_CONFIGS[lane].concurrency) / baseTotal));
        assigned += share;
        worker.concurrency = share;
      });
      log.info(
        { totalConcurrency: next, direction, reason },
        "Adaptive worker scaler adjusted dispatcher lane concurrency",
      );
    });

    this.scaler.start();
  }

  /** Returns the worker for a specific lane (if started). */
  public getWorker(
    lane: QueueLane,
  ): Worker<WebhookDispatchJobData> | undefined {
    return this.workers.get(lane);
  }

  /** Returns the lane manager used by this worker (for metrics/integration tests). */
  public getLaneManager(): QueueLaneManager {
    return this.laneManager;
  }

  /** Returns the adaptive scaler attached to this dispatcher (if started). */
  public getWorkerScaler(): WorkerScaler | null {
    return this.scaler;
  }

  /** Returns fair scheduling statistics */
  public getFairSchedulingStats() {
    return fairShareQueueScheduler.getStats();
  }
}

export const dispatcherWorker = new DispatcherWorker();
