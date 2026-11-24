import { WalletDTO, PaymentDTO, SorobanEventDTO, isValidStellarPublicKey } from './types.js';
import { getCliConfig } from './config.js';
import { StreamHttpError } from './resilient-stream.js';

export class ApiClient {
  private baseUrl: string;
  private apiKey?: string;

  constructor(baseUrl?: string, apiKey?: string) {
    this.baseUrl = baseUrl || getCliConfig().STELLAR_ALERTS_API_URL;
    this.apiKey = apiKey || getCliConfig().STELLAR_ALERTS_API_KEY;
  }

  /**
   * Returns a new ApiClient instance with the given token applied.
   * The original instance is not mutated. Used by commands that resolve
   * the token via the auth precedence chain.
   */
  withToken(token: string | undefined): ApiClient {
    return new ApiClient(this.baseUrl, token);
  }

  /**
   * Returns a new ApiClient instance with the given base URL.
   */
  withBaseUrl(url: string): ApiClient {
    return new ApiClient(url, this.apiKey);
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }
    return headers;
  }

  async getWallets(): Promise<WalletDTO[]> {
    const response = await fetch(`${this.baseUrl}/wallets`, {
      headers: this.getHeaders(),
    });
    if (!response.ok) {
      throw new Error(`Failed to fetch wallets: ${response.statusText}`);
    }
    return response.json();
  }

  async addWallet(publicKey: string, label?: string): Promise<WalletDTO> {
    if (!isValidStellarPublicKey(publicKey)) {
      throw new Error('Invalid Stellar public key. Must start with G and be 56 characters.');
    }

    const response = await fetch(`${this.baseUrl}/wallets`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ publicKey, label }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: response.statusText }));
      throw new Error(error.message || 'Failed to add wallet');
    }

    return response.json();
  }

  async deleteWallet(id: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/wallets/${id}`, {
      method: 'DELETE',
      headers: this.getHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Failed to delete wallet: ${response.statusText}`);
    }
  }

  async getPayments(walletId?: string, limit?: number): Promise<PaymentDTO[]> {
    const params = new URLSearchParams();
    if (walletId) params.append('walletId', walletId);
    if (limit) params.append('limit', limit.toString());

    const response = await fetch(`${this.baseUrl}/payments?${params}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch payments: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Opens one connection to the NDJSON payment stream. `cursor` asks the server
   * to resume after that payment; servers that ignore it still work because the
   * CLI suppresses replayed ids client-side. The optional filter parameters let
   * capable servers narrow the stream; the CLI always re-checks every record
   * client-side as well.
   */
  async openPaymentStream(
    options: {
      cursor?: string;
      walletId?: string;
      asset?: string;
      minAmount?: number;
      contract?: string;
      signal?: AbortSignal;
    } = {}
  ): Promise<AsyncIterable<PaymentDTO>> {
    const params = new URLSearchParams();
    if (options.walletId) params.append('walletId', options.walletId);
    if (options.cursor) params.append('cursor', options.cursor);
    if (options.asset) params.append('asset', options.asset);
    if (options.minAmount !== undefined) params.append('minAmount', String(options.minAmount));
    if (options.contract) params.append('contract', options.contract);
    const query = params.toString();

    const response = await fetch(`${this.baseUrl}/payments/stream${query ? `?${query}` : ''}`, {
      headers: this.getHeaders(),
      signal: options.signal,
    });

    if (!response.ok) {
      throw new StreamHttpError(
        `Failed to connect to payment stream: ${response.statusText || response.status}`,
        response.status
      );
    }

    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error('Response body is not readable');
    }

    return readNdjsonLines(reader, isPaymentDTO);
  }

  /**
   * Opens the Soroban counterpart of the payment stream. Servers that do not
   * implement this endpoint cause a `StreamHttpError`, which `tail` reports as
   * a warning while it continues to show payments.
   */
  async openSorobanEventStream(
    options: {
      contract?: string;
      asset?: string;
      signal?: AbortSignal;
    } = {}
  ): Promise<AsyncIterable<SorobanEventDTO>> {
    const params = new URLSearchParams();
    if (options.contract) params.append('contract', options.contract);
    if (options.asset) params.append('asset', options.asset);
    const query = params.toString();

    const response = await fetch(`${this.baseUrl}/soroban/events/stream${query ? `?${query}` : ''}`, {
      headers: this.getHeaders(),
      signal: options.signal,
    });

    if (!response.ok) {
      throw new StreamHttpError(
        `Failed to connect to Soroban event stream: ${response.statusText || response.status}`,
        response.status
      );
    }

    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error('Response body is not readable');
    }

    return readNdjsonLines(reader, isSorobanEventDTO);
  }

  async streamPayments(
    onPayment: (payment: PaymentDTO) => void,
    signal?: AbortSignal
  ): Promise<void> {
    for await (const payment of await this.openPaymentStream({ signal })) {
      onPayment(payment);
    }
  }
}

function hasStringId(value: unknown): value is { id: string } {
  return typeof value === 'object' && value !== null && typeof (value as { id?: unknown }).id === 'string';
}

function isPaymentDTO(value: unknown): value is PaymentDTO {
  return hasStringId(value);
}

function isSorobanEventDTO(value: unknown): value is SorobanEventDTO {
  return hasStringId(value);
}

/**
 * Yields one record per newline-delimited JSON frame, buffering partial lines
 * across chunk boundaries. The reader is always cancelled on exit so the
 * underlying socket is released on abort, break, or error. Frames without a
 * string `id` (heartbeats, keepalives) are ignored.
 */
export async function* readNdjsonLines<T>(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  isValid: (value: unknown) => value is T
): AsyncGenerator<T> {
  const decoder = new TextDecoder();
  let buffer = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        buffer += decoder.decode();
        break;
      }
      buffer += decoder.decode(value, { stream: true });

      let newline: number;
      while ((newline = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        const record = parseNdjsonLine(line, isValid);
        if (record) yield record;
      }
    }

    const tail = parseNdjsonLine(buffer, isValid);
    if (tail) yield tail;
  } finally {
    await reader.cancel().catch(() => {});
  }
}

function parseNdjsonLine<T>(line: string, isValid: (value: unknown) => value is T): T | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  try {
    const parsed: unknown = JSON.parse(trimmed);
    return isValid(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** @deprecated Use `readNdjsonLines` with `isPaymentDTO` where available. */
export async function* readPaymentLines(
  reader: ReadableStreamDefaultReader<Uint8Array>
): AsyncGenerator<PaymentDTO> {
  yield* readNdjsonLines(reader, isPaymentDTO);
}

export const apiClient = new ApiClient();
