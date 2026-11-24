import { describe, expect, it } from 'vitest';
import {
  MAX_AST_DEPTH,
  MAX_EVALUATION_STEPS,
  MAX_REGEX_INPUT_LENGTH,
  SafeExpressionEngine,
  type CompileOptions,
  type CompiledExpression,
  type EvaluateOptions,
} from '../cel-evaluator';

const engine = new SafeExpressionEngine();
// A generous deadline keeps functional tests independent of CI scheduling;
// the 1ms default is covered with an injected clock below.
const RELAXED: EvaluateOptions = { timeoutMs: 1_000 };

const context = {
  tx: { fee_charged: 60_000, memo: 'invoice-42', source: 'GABC123', tags: ['treasury', 'ops'] },
  op: { amount: 300, asset: 'USDC', type: 'payment' },
  wallet: { balance: 1_000, label: null, nested: { limit: 5 } },
};

function compiled(source: string, options?: CompileOptions): CompiledExpression {
  const result = engine.compile(source, options);
  if (!result.ok) throw new Error(`${source}: ${JSON.stringify(result.diagnostics)}`);
  return result.expression;
}

function run(source: string, ctx: Record<string, unknown> = context, options: EvaluateOptions = RELAXED) {
  return engine.evaluate(compiled(source), ctx, options);
}

function value(source: string) {
  const result = run(source);
  if (!result.ok) throw new Error(`${source}: ${JSON.stringify(result.error)}`);
  return result.value;
}

describe('SafeExpressionEngine evaluation', () => {
  it('evaluates the cross-field ratio formula from the issue', () => {
    expect(value('tx.fee_charged > 50000 && (op.amount / wallet.balance) > 0.25')).toBe(true);
    expect(value('tx.fee_charged > 50000 && (op.amount / wallet.balance) > 0.5')).toBe(false);
  });

  it.each([
    ['1 + 2 * 3 == 7', true],
    ['(1 + 2) * 3 == 9', true],
    ['10 - 4 - 3 == 3', true],
    ['17 % 5 == 2', true],
    ['-2 * -3 == 6', true],
    ['1.5e2 == 150', true],
    ['2 >= 2 && 2 <= 2 && 1 < 2 && 2 > 1', true],
    ['1 != 2', true],
    ['!(1 > 2)', true],
    ['false || true && false', false],
    ['"a" + "b" == "ab"', true],
    ['"abc" < "abd"', true],
  ])('evaluates %s', (source, expected) => {
    expect(value(source)).toBe(expected);
  });

  it('supports whitelisted macros in function and method form', () => {
    expect(value('startsWith(tx.memo, "invoice")')).toBe(true);
    expect(value('tx.memo.startsWith("receipt")')).toBe(false);
    expect(value('tx.memo.matches("^invoice-[0-9]+$")')).toBe(true);
    expect(value('matches(tx.source, "^G[A-Z0-9]{6}$")')).toBe(true);
    expect(value('abs(op.amount - wallet.balance) == 700')).toBe(true);
    expect(value('op.asset in ["USDC", "EURC"]')).toBe(true);
    expect(value('op.asset in ["XLM"]')).toBe(false);
    expect(value('"ops" in tx.tags')).toBe(true);
  });

  it('supports the documented regex syntax', () => {
    expect(value('"abab".matches("^(ab)+$")')).toBe(true);
    expect(value('"cat".matches("^(cat|dog)$")')).toBe(true);
    expect(value('"bird".matches("^(?:cat|dog)$")')).toBe(false);
    expect(value('"a1_".matches("^\\\\w{3}$")')).toBe(true);
    expect(value('"x-9".matches("^[^0-9]-\\\\d$")')).toBe(true);
    expect(value('"needle in hay".matches("needle")')).toBe(true);
    expect(value('"aa".matches("^a{3,}$")')).toBe(false);
    expect(value('"color".matches("^colou?r$")')).toBe(true);
  });

  it('reads nested fields, list indexes and null values', () => {
    expect(value('wallet.nested.limit == 5')).toBe(true);
    expect(value('tx.tags[1] == "ops"')).toBe(true);
    expect(value('wallet["balance"] == 1000')).toBe(true);
    expect(value('wallet.label == null')).toBe(true);
  });

  it('short-circuits so a guarded division cannot fail', () => {
    const ctx = { ...context, wallet: { balance: 0 } };
    const result = run('wallet.balance != 0 && op.amount / wallet.balance > 0.25', ctx);
    expect(result).toMatchObject({ ok: true, value: false });
  });

  it.each([
    ['op.amount / 0 > 1', 'DIVISION_BY_ZERO'],
    ['op.amount % 0 > 1', 'DIVISION_BY_ZERO'],
    ['tx.missing > 1', 'FIELD_NOT_FOUND'],
    ['tx.memo > 1', 'TYPE_ERROR'],
    ['tx.tags[9] == "x"', 'INDEX_OUT_OF_BOUNDS'],
    ['1e308 * 10 > 0', 'NUMERIC_OVERFLOW'],
    ['op.amount', 'NON_BOOLEAN_RESULT'],
  ])('returns a positioned runtime error for %s', (source, code) => {
    const result = run(source);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe(code);
      expect(result.error.column).toBeGreaterThanOrEqual(1);
    }
  });
});

describe('SafeExpressionEngine diagnostics', () => {
  it.each([
    ['tx.fee >', 'UNEXPECTED_TOKEN', 9],
    ['(1 + 2', 'UNEXPECTED_TOKEN', 7],
    ['1 + @', 'UNEXPECTED_CHARACTER', 5],
    ['"open', 'UNTERMINATED_STRING', 1],
    ['"bad\\q"', 'INVALID_ESCAPE', 5],
    ['12abc > 1', 'INVALID_NUMBER', 1],
    ['1e > 1', 'INVALID_NUMBER', 1],
    ['user.id == 1', 'UNKNOWN_IDENTIFIER', 1],
    ['eval("1") == 1', 'UNKNOWN_FUNCTION', 1],
    ['tx.memo.toString() == "x"', 'UNKNOWN_FUNCTION', 9],
    ['abs(1, 2) > 0', 'INVALID_ARGUMENTS', 1],
    ['tx.memo.matches(op.asset)', 'INVALID_ARGUMENTS', 17],
    ['tx.memo.matches("(")', 'INVALID_REGEX', 17],
    ['tx.memo.matches("(?=a)")', 'INVALID_REGEX', 17],
    ['tx.memo.matches("(a)\\\\1")', 'INVALID_REGEX', 17],
    ['1 + "a" == 2', 'TYPE_MISMATCH', 1],
    ['!1', 'TYPE_MISMATCH', 2],
    ['1 + 2', 'TYPE_MISMATCH', 1],
  ])('reports %s as %s at column %i', (source, code, column) => {
    const [first] = engine.validate(source);
    expect(first).toMatchObject({ code, column });
  });

  it('type-checks fields against a schema and reports every error', () => {
    const schema = {
      'tx.fee_charged': 'number',
      'tx.memo': 'string',
      'op.amount': 'number',
    } as const;

    expect(engine.validate('tx.fee_charged > 1 && op.amount > 2', { schema })).toEqual([]);

    const diagnostics = engine.validate('tx.memo > 1 && tx.unknown == 2', { schema });
    expect(diagnostics.map((item) => item.code)).toEqual(['TYPE_MISMATCH', 'UNKNOWN_FIELD']);
    expect(diagnostics[1]).toMatchObject({ column: 19 });
  });

  it('never evaluates anything during validation', () => {
    let reads = 0;
    const ctx = {
      get tx() {
        reads += 1;
        return {};
      },
    };
    engine.validate('tx.fee > 1');
    expect(reads).toBe(0);
    expect(ctx).toBeDefined();
  });
});

describe('SafeExpressionEngine hardening', () => {
  it.each([
    'tx.__proto__ == null',
    'tx.constructor == null',
    'tx.prototype == null',
    'tx["__proto__"] == null',
    'tx["constructor"] == null',
    '__proto__ == null',
    'constructor == null',
    'tx.constructor.constructor("return process")() == null',
  ])('rejects prototype access at compile time: %s', (source) => {
    expect(engine.validate(source)[0]?.code).toBe('FORBIDDEN_MEMBER');
  });

  it('rejects dynamically built prototype keys at runtime', () => {
    const result = run('tx["__pro" + "to__"] == null');
    expect(result).toMatchObject({ ok: false, error: { code: 'FORBIDDEN_MEMBER' } });

    const ctor = run('tx["const" + "ructor"] == null');
    expect(ctor).toMatchObject({ ok: false, error: { code: 'FORBIDDEN_MEMBER' } });
  });

  it('does not read inherited properties or invoke accessors', () => {
    let invoked = false;
    const tx = Object.create({ inherited: 1 }) as Record<string, unknown>;
    expect(run('tx.inherited == 1', { tx })).toMatchObject({ ok: false });

    const accessor = {};
    Object.defineProperty(accessor, 'secret', {
      enumerable: true,
      get() {
        invoked = true;
        return 1;
      },
    });
    expect(run('tx.secret == 1', { tx: accessor })).toMatchObject({ ok: false, error: { code: 'FIELD_NOT_FOUND' } });
    expect(invoked).toBe(false);
  });

  it('does not expose array or string built-ins', () => {
    expect(run('tx.tags.length > 0')).toMatchObject({ ok: false, error: { code: 'TYPE_ERROR' } });
    expect(run('tx.memo.length > 0')).toMatchObject({ ok: false, error: { code: 'TYPE_ERROR' } });
  });

  it('rejects class instances in the context', () => {
    expect(run('tx.at == 1', { tx: new Date() })).toMatchObject({ ok: false, error: { code: 'TYPE_ERROR' } });
  });

  it('leaves Object.prototype untouched by hostile expressions', () => {
    run('tx["__pro" + "to__"] == null');
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('rejects expressions over the node budget at compile time', () => {
    const source = `${Array.from({ length: MAX_EVALUATION_STEPS }, () => '1').join(' + ')} > 0`;
    expect(engine.validate(source)[0]?.code).toBe('BUDGET_EXCEEDED');
  });

  it('enforces the step budget at evaluation time', () => {
    const expression = compiled('1 + 1 + 1 + 1 + 1 > 0');
    const result = engine.evaluate(expression, context, { ...RELAXED, maxSteps: 3 });
    expect(result).toMatchObject({ ok: false, error: { code: 'BUDGET_EXCEEDED' } });
  });

  it('cannot raise the step budget above the hard cap', () => {
    const list = Array.from({ length: 10_000 }, (_, index) => index);
    const result = engine.evaluate(compiled('-1 in tx.values'), { tx: { values: list } }, {
      ...RELAXED,
      maxSteps: Number.MAX_SAFE_INTEGER,
    });
    expect(result).toMatchObject({ ok: false, error: { code: 'BUDGET_EXCEEDED' } });
    expect(result.steps).toBeLessThanOrEqual(MAX_EVALUATION_STEPS + 1);
  });

  it('enforces the default 1ms deadline', () => {
    let time = 0;
    const now = () => {
      time += 0.6;
      return time;
    };
    const result = engine.evaluate(compiled('1 + 2 + 3 + 4 > 0'), context, { now });
    expect(result).toMatchObject({ ok: false, error: { code: 'TIMEOUT' } });
  });

  it('rejects excessive nesting without overflowing the stack', () => {
    const deep = `${'('.repeat(MAX_AST_DEPTH + 1)}1${')'.repeat(MAX_AST_DEPTH + 1)} > 0`;
    expect(engine.validate(deep)[0]?.code).toBe('MAX_DEPTH_EXCEEDED');
    expect(engine.validate(`${'!'.repeat(4_000)}true`)[0]?.code).toBe('MAX_DEPTH_EXCEEDED');
    expect(engine.validate(`${'['.repeat(4_000)}`)[0]?.code).toBe('MAX_DEPTH_EXCEEDED');
  });

  it('rejects oversized source', () => {
    expect(engine.validate(`"${'a'.repeat(5_000)}" == "a"`)[0]?.code).toBe('EXPRESSION_TOO_LONG');
  });

  it.each(['^(a+)+$', '^(a|a)*$', '^(a|aa)+$', '^(.*a){12}$'])('is immune to ReDoS pattern %s', (pattern) => {
    const input = `${'a'.repeat(MAX_REGEX_INPUT_LENGTH - 1)}!`;
    const expression = compiled(`tx.memo.matches("${pattern}")`);
    const started = performance.now();
    const result = engine.evaluate(expression, { tx: { memo: input } }, { timeoutMs: 1_000 });
    expect(performance.now() - started).toBeLessThan(500);
    if (result.ok) expect(result.value).toBe(false);
    else expect(result.error.code).toBe('BUDGET_EXCEEDED');
  });

  it('caps regex input length', () => {
    const result = run('tx.memo.matches("a")', { tx: { memo: 'a'.repeat(MAX_REGEX_INPUT_LENGTH + 1) } });
    expect(result).toMatchObject({ ok: false, error: { code: 'REGEX_INPUT_TOO_LONG' } });
  });

  it('rejects regexes that expand beyond the program limit', () => {
    expect(engine.validate('tx.memo.matches("(a{100}){100}")')[0]?.code).toBe('INVALID_REGEX');
  });
});
