/**
 * SafeExpressionEngine: a small, deterministic, non-Turing-complete evaluator
 * for CEL-style policy expressions such as
 *
 *   tx.fee_charged > 50000 && (op.amount / wallet.balance) > 0.25
 *
 * Safety properties:
 *  - No eval, Function constructor or native RegExp on user input. `matches`
 *    runs on a linear-time Pike VM, so catastrophic backtracking cannot occur.
 *  - The grammar has no loops, recursion, assignment or user-defined functions.
 *  - Evaluation is bounded by an AST step budget and a wall-clock deadline.
 *  - Member access only reads own data properties of plain objects and arrays.
 *    Accessors are never invoked and prototype keys are rejected.
 */

export const MAX_EVALUATION_STEPS = 256;
export const DEFAULT_TIMEOUT_MS = 1;
export const MAX_EXPRESSION_LENGTH = 4096;
export const MAX_AST_DEPTH = 32;
export const MAX_REGEX_PATTERN_LENGTH = 256;
export const MAX_REGEX_INPUT_LENGTH = 1024;
const MAX_REGEX_PROGRAM_SIZE = 512;
const MAX_REGEX_VM_STEPS = 20_000;
const REGEX_DEADLINE_CHECK_INTERVAL = 64;

const FORBIDDEN_MEMBERS = new Set(['__proto__', 'prototype', 'constructor']);
const DEFAULT_ROOTS = ['tx', 'op', 'wallet'] as const;

export type ExpressionType = 'number' | 'string' | 'boolean' | 'null' | 'list' | 'object' | 'dyn';
export type ExpressionValue = number | string | boolean | null | ExpressionValue[] | { [key: string]: ExpressionValue };

export type DiagnosticCode =
  | 'EXPRESSION_TOO_LONG'
  | 'UNEXPECTED_CHARACTER'
  | 'UNTERMINATED_STRING'
  | 'INVALID_ESCAPE'
  | 'INVALID_NUMBER'
  | 'UNEXPECTED_TOKEN'
  | 'MAX_DEPTH_EXCEEDED'
  | 'BUDGET_EXCEEDED'
  | 'FORBIDDEN_MEMBER'
  | 'UNKNOWN_IDENTIFIER'
  | 'UNKNOWN_FIELD'
  | 'UNKNOWN_FUNCTION'
  | 'INVALID_ARGUMENTS'
  | 'INVALID_REGEX'
  | 'TYPE_MISMATCH';

export interface ExpressionDiagnostic {
  code: DiagnosticCode;
  message: string;
  /** 1-based character column in the source expression. */
  column: number;
  /** 0-based source offset. */
  offset: number;
  length: number;
}

export type EvaluationErrorCode =
  | 'BUDGET_EXCEEDED'
  | 'TIMEOUT'
  | 'DIVISION_BY_ZERO'
  | 'NUMERIC_OVERFLOW'
  | 'TYPE_ERROR'
  | 'FIELD_NOT_FOUND'
  | 'FORBIDDEN_MEMBER'
  | 'INDEX_OUT_OF_BOUNDS'
  | 'REGEX_INPUT_TOO_LONG'
  | 'NON_BOOLEAN_RESULT';

export interface ExpressionEvaluationError {
  code: EvaluationErrorCode;
  message: string;
  column: number;
  offset: number;
}

export type EvaluationResult =
  | { ok: true; value: ExpressionValue; steps: number }
  | { ok: false; error: ExpressionEvaluationError; steps: number };

export type CompileResult =
  | { ok: true; expression: CompiledExpression; diagnostics: [] }
  | { ok: false; diagnostics: ExpressionDiagnostic[] };

export interface CompileOptions {
  /** Field types by dotted path, e.g. `{ 'tx.fee_charged': 'number' }`. */
  schema?: Record<string, ExpressionType>;
  /** Allowed root identifiers. Defaults to tx, op and wallet. */
  roots?: readonly string[];
}

export interface EvaluateOptions {
  maxSteps?: number;
  timeoutMs?: number;
  /** Monotonic millisecond clock; injectable for deterministic tests. */
  now?: () => number;
}

export interface CompiledExpression {
  readonly source: string;
  readonly ast: ExprNode;
  readonly resultType: ExpressionType;
}

// ── AST ─────────────────────────────────────────────────────────────────────

interface Span {
  offset: number;
  length: number;
}

type BinaryOperator = '+' | '-' | '*' | '/' | '%' | '==' | '!=' | '<' | '<=' | '>' | '>=' | '&&' | '||' | 'in';
type FunctionName = 'startsWith' | 'matches' | 'abs';

export type ExprNode = Span &
  (
    | { kind: 'literal'; value: number | string | boolean | null }
    | { kind: 'identifier'; name: string }
    | { kind: 'member'; object: ExprNode; property: string; propertySpan: Span }
    | { kind: 'index'; object: ExprNode; index: ExprNode }
    | { kind: 'list'; items: ExprNode[] }
    | { kind: 'unary'; operator: '!' | '-'; operand: ExprNode }
    | { kind: 'binary'; operator: BinaryOperator; left: ExprNode; right: ExprNode }
    | { kind: 'call'; name: FunctionName; args: ExprNode[]; regex?: RegexProgram }
  );

class CompileFailure extends Error {
  constructor(readonly diagnostic: ExpressionDiagnostic) {
    super(diagnostic.message);
  }
}

function diagnostic(code: DiagnosticCode, message: string, span: Span): ExpressionDiagnostic {
  return { code, message, column: span.offset + 1, offset: span.offset, length: Math.max(span.length, 1) };
}

function fail(code: DiagnosticCode, message: string, span: Span): never {
  throw new CompileFailure(diagnostic(code, message, span));
}

// ── Lexer ───────────────────────────────────────────────────────────────────

type TokenKind = 'number' | 'string' | 'identifier' | 'operator' | 'eof';

interface Token extends Span {
  kind: TokenKind;
  text: string;
  value?: number | string;
}

const OPERATORS = ['&&', '||', '==', '!=', '<=', '>=', '+', '-', '*', '/', '%', '<', '>', '!', '(', ')', '[', ']', ',', '.'];
const ESCAPES: Record<string, string> = { n: '\n', r: '\r', t: '\t', '\\': '\\', '"': '"', "'": "'" };

const isDigit = (char: string | undefined) => char !== undefined && char >= '0' && char <= '9';
const isIdentStart = (char: string | undefined) =>
  char !== undefined && ((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char === '_');
const isIdentPart = (char: string | undefined) => isIdentStart(char) || isDigit(char);

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let pos = 0;

  while (pos < source.length) {
    const char = source[pos];
    if (char === ' ' || char === '\t' || char === '\n' || char === '\r') {
      pos += 1;
      continue;
    }

    const start = pos;
    if (isDigit(char) || (char === '.' && isDigit(source[pos + 1]))) {
      while (isDigit(source[pos])) pos += 1;
      if (source[pos] === '.' && isDigit(source[pos + 1])) {
        pos += 1;
        while (isDigit(source[pos])) pos += 1;
      }
      if (source[pos] === 'e' || source[pos] === 'E') {
        let next = pos + 1;
        if (source[next] === '+' || source[next] === '-') next += 1;
        if (!isDigit(source[next])) {
          fail('INVALID_NUMBER', 'Exponent requires at least one digit', { offset: start, length: next - start });
        }
        pos = next;
        while (isDigit(source[pos])) pos += 1;
      }
      if (isIdentStart(source[pos])) {
        fail('INVALID_NUMBER', 'Invalid numeric literal', { offset: start, length: pos - start + 1 });
      }
      const text = source.slice(start, pos);
      const value = Number(text);
      if (!Number.isFinite(value)) {
        fail('INVALID_NUMBER', 'Numeric literal is out of range', { offset: start, length: pos - start });
      }
      tokens.push({ kind: 'number', text, value, offset: start, length: pos - start });
      continue;
    }

    if (isIdentStart(char)) {
      while (isIdentPart(source[pos])) pos += 1;
      const text = source.slice(start, pos);
      tokens.push({ kind: 'identifier', text, offset: start, length: pos - start });
      continue;
    }

    if (char === '"' || char === "'") {
      pos += 1;
      let value = '';
      for (;;) {
        const current = source[pos];
        if (current === undefined || current === '\n') {
          fail('UNTERMINATED_STRING', 'Unterminated string literal', { offset: start, length: pos - start });
        }
        if (current === char) {
          pos += 1;
          break;
        }
        if (current === '\\') {
          const escaped = source[pos + 1];
          const replacement = escaped === undefined ? undefined : ESCAPES[escaped];
          if (replacement === undefined) {
            // Regex escapes such as \d pass through so patterns stay readable.
            if (escaped !== undefined && /^[dDwWsSbB.^$*+?()[\]{}|/-]$/.test(escaped)) {
              value += `\\${escaped}`;
              pos += 2;
              continue;
            }
            fail('INVALID_ESCAPE', `Invalid escape sequence \\${escaped ?? ''}`, { offset: pos, length: 2 });
          }
          value += replacement;
          pos += 2;
          continue;
        }
        value += current;
        pos += 1;
      }
      tokens.push({ kind: 'string', text: source.slice(start, pos), value, offset: start, length: pos - start });
      continue;
    }

    const operator = OPERATORS.find((candidate) => source.startsWith(candidate, pos));
    if (!operator) {
      fail('UNEXPECTED_CHARACTER', `Unexpected character '${char}'`, { offset: pos, length: 1 });
    }
    pos += operator.length;
    tokens.push({ kind: 'operator', text: operator, offset: start, length: operator.length });
  }

  tokens.push({ kind: 'eof', text: 'end of expression', offset: source.length, length: 1 });
  return tokens;
}

// ── Recursive-descent parser ────────────────────────────────────────────────

const FUNCTIONS: Record<FunctionName, number> = { startsWith: 2, matches: 2, abs: 1 };
const isFunctionName = (name: string): name is FunctionName => Object.hasOwn(FUNCTIONS, name);

function spanBetween(left: Span, right: Span): Span {
  return { offset: left.offset, length: right.offset + right.length - left.offset };
}

class Parser {
  private index = 0;
  private depth = 0;
  private nodes = 0;

  constructor(private readonly tokens: Token[]) {}

  parse(): ExprNode {
    const expression = this.parseOr();
    const token = this.peek();
    if (token.kind !== 'eof') this.unexpected(token, 'end of expression');
    return expression;
  }

  private peek(): Token {
    return this.tokens[this.index] as Token;
  }

  private advance(): Token {
    const token = this.peek();
    if (token.kind !== 'eof') this.index += 1;
    return token;
  }

  private isOperator(text: string): boolean {
    const token = this.peek();
    return token.kind === 'operator' && token.text === text;
  }

  private matchOperator(...operators: string[]): Token | null {
    const token = this.peek();
    if (token.kind === 'operator' && operators.includes(token.text)) return this.advance();
    return null;
  }

  private expectOperator(text: string): Token {
    const token = this.peek();
    if (token.kind !== 'operator' || token.text !== text) this.unexpected(token, `'${text}'`);
    return this.advance();
  }

  private unexpected(token: Token, expected: string): never {
    const found = token.kind === 'eof' ? 'end of expression' : `'${token.text}'`;
    fail('UNEXPECTED_TOKEN', `Expected ${expected} but found ${found}`, token);
  }

  private node<T extends ExprNode>(node: T): T {
    this.nodes += 1;
    if (this.nodes > MAX_EVALUATION_STEPS) {
      fail('BUDGET_EXCEEDED', `Expression exceeds the ${MAX_EVALUATION_STEPS} node budget`, node);
    }
    return node;
  }

  private nested<T>(token: Token, parse: () => T): T {
    this.depth += 1;
    if (this.depth > MAX_AST_DEPTH) {
      fail('MAX_DEPTH_EXCEEDED', `Expression nesting exceeds the maximum depth of ${MAX_AST_DEPTH}`, token);
    }
    try {
      return parse();
    } finally {
      this.depth -= 1;
    }
  }

  private binary(operator: BinaryOperator, left: ExprNode, right: ExprNode): ExprNode {
    return this.node({ kind: 'binary', operator, left, right, ...spanBetween(left, right) });
  }

  private parseOr(): ExprNode {
    let left = this.parseAnd();
    while (this.matchOperator('||')) left = this.binary('||', left, this.parseAnd());
    return left;
  }

  private parseAnd(): ExprNode {
    let left = this.parseEquality();
    while (this.matchOperator('&&')) left = this.binary('&&', left, this.parseEquality());
    return left;
  }

  private parseEquality(): ExprNode {
    let left = this.parseRelational();
    for (;;) {
      const token = this.matchOperator('==', '!=');
      if (!token) return left;
      left = this.binary(token.text as BinaryOperator, left, this.parseRelational());
    }
  }

  private parseRelational(): ExprNode {
    let left = this.parseAdditive();
    for (;;) {
      const next = this.peek();
      if (next.kind === 'identifier' && next.text === 'in') {
        this.advance();
        left = this.binary('in', left, this.parseAdditive());
        continue;
      }
      const token = this.matchOperator('<=', '>=', '<', '>');
      if (!token) return left;
      left = this.binary(token.text as BinaryOperator, left, this.parseAdditive());
    }
  }

  private parseAdditive(): ExprNode {
    let left = this.parseMultiplicative();
    for (;;) {
      const token = this.matchOperator('+', '-');
      if (!token) return left;
      left = this.binary(token.text as BinaryOperator, left, this.parseMultiplicative());
    }
  }

  private parseMultiplicative(): ExprNode {
    let left = this.parseUnary();
    for (;;) {
      const token = this.matchOperator('*', '/', '%');
      if (!token) return left;
      left = this.binary(token.text as BinaryOperator, left, this.parseUnary());
    }
  }

  private parseUnary(): ExprNode {
    const token = this.matchOperator('!', '-');
    if (!token) return this.parsePostfix();
    const operand = this.nested(token, () => this.parseUnary());
    return this.node({
      kind: 'unary',
      operator: token.text as '!' | '-',
      operand,
      ...spanBetween(token, operand),
    });
  }

  private parsePostfix(): ExprNode {
    let expression = this.parsePrimary();
    for (;;) {
      if (this.matchOperator('.')) {
        const property = this.peek();
        if (property.kind !== 'identifier') this.unexpected(property, 'a field name');
        this.advance();
        if (FORBIDDEN_MEMBERS.has(property.text)) {
          fail('FORBIDDEN_MEMBER', `Access to '${property.text}' is not allowed`, property);
        }
        if (this.isOperator('(')) {
          expression = this.parseMethod(expression, property);
          continue;
        }
        expression = this.node({
          kind: 'member',
          object: expression,
          property: property.text,
          propertySpan: { offset: property.offset, length: property.length },
          ...spanBetween(expression, property),
        });
        continue;
      }

      const open = this.matchOperator('[');
      if (open) {
        const index = this.nested(open, () => this.parseOr());
        if (index.kind === 'literal' && typeof index.value === 'string' && FORBIDDEN_MEMBERS.has(index.value)) {
          fail('FORBIDDEN_MEMBER', `Access to '${index.value}' is not allowed`, index);
        }
        const close = this.expectOperator(']');
        expression = this.node({ kind: 'index', object: expression, index, ...spanBetween(expression, close) });
        continue;
      }

      return expression;
    }
  }

  private parseMethod(receiver: ExprNode, name: Token): ExprNode {
    if (!isFunctionName(name.text) || name.text === 'abs') {
      fail('UNKNOWN_FUNCTION', `Unknown method '${name.text}'`, name);
    }
    const { args, close } = this.parseArguments();
    return this.buildCall(name, [receiver, ...args], spanBetween(receiver, close));
  }

  private parseArguments(): { args: ExprNode[]; close: Token } {
    const open = this.expectOperator('(');
    const args: ExprNode[] = [];
    if (!this.isOperator(')')) {
      do {
        args.push(this.nested(open, () => this.parseOr()));
      } while (this.matchOperator(','));
    }
    return { args, close: this.expectOperator(')') };
  }

  private buildCall(name: Token, args: ExprNode[], span: Span): ExprNode {
    const functionName = name.text as FunctionName;
    const arity = FUNCTIONS[functionName];
    if (args.length !== arity) {
      fail('INVALID_ARGUMENTS', `${functionName} expects ${arity} argument(s) but received ${args.length}`, span);
    }

    let regex: RegexProgram | undefined;
    if (functionName === 'matches') {
      const pattern = args[1] as ExprNode;
      if (pattern.kind !== 'literal' || typeof pattern.value !== 'string') {
        fail('INVALID_ARGUMENTS', 'matches requires a string literal pattern', pattern);
      }
      try {
        regex = compileRegex(pattern.value);
      } catch (err: unknown) {
        fail('INVALID_REGEX', `Invalid regular expression: ${err instanceof Error ? err.message : String(err)}`, pattern);
      }
    }
    return this.node({ kind: 'call', name: functionName, args, regex, ...span });
  }

  private parsePrimary(): ExprNode {
    const token = this.peek();

    if (token.kind === 'number' || token.kind === 'string') {
      this.advance();
      return this.node({ kind: 'literal', value: token.value as number | string, offset: token.offset, length: token.length });
    }

    if (token.kind === 'identifier') {
      this.advance();
      if (token.text === 'true' || token.text === 'false') {
        return this.node({ kind: 'literal', value: token.text === 'true', offset: token.offset, length: token.length });
      }
      if (token.text === 'null') {
        return this.node({ kind: 'literal', value: null, offset: token.offset, length: token.length });
      }
      if (token.text === 'in') this.unexpected(token, 'an expression');
      if (FORBIDDEN_MEMBERS.has(token.text)) {
        fail('FORBIDDEN_MEMBER', `Access to '${token.text}' is not allowed`, token);
      }
      if (this.isOperator('(')) {
        if (!isFunctionName(token.text)) fail('UNKNOWN_FUNCTION', `Unknown function '${token.text}'`, token);
        const { args, close } = this.parseArguments();
        return this.buildCall(token, args, spanBetween(token, close));
      }
      return this.node({ kind: 'identifier', name: token.text, offset: token.offset, length: token.length });
    }

    if (this.isOperator('(')) {
      const open = this.advance();
      const inner = this.nested(open, () => this.parseOr());
      this.expectOperator(')');
      return inner;
    }

    if (this.isOperator('[')) {
      const open = this.advance();
      const items: ExprNode[] = [];
      if (!this.isOperator(']')) {
        do {
          items.push(this.nested(open, () => this.parseOr()));
        } while (this.matchOperator(','));
      }
      const close = this.expectOperator(']');
      return this.node({ kind: 'list', items, ...spanBetween(open, close) });
    }

    this.unexpected(token, 'an expression');
  }
}

// ── Type checker ────────────────────────────────────────────────────────────

class TypeChecker {
  readonly diagnostics: ExpressionDiagnostic[] = [];
  private readonly roots: Set<string>;
  private readonly schema: Map<string, ExpressionType> | null;

  constructor(options: CompileOptions) {
    this.roots = new Set(options.roots ?? DEFAULT_ROOTS);
    this.schema = options.schema ? new Map(Object.entries(options.schema)) : null;
  }

  private report(code: DiagnosticCode, message: string, span: Span): void {
    this.diagnostics.push(diagnostic(code, message, span));
  }

  private requireType(node: ExprNode, actual: ExpressionType, expected: ExpressionType, context: string): void {
    if (actual !== 'dyn' && actual !== expected) {
      this.report('TYPE_MISMATCH', `${context} requires ${expected} but received ${actual}`, node);
    }
  }

  private path(node: ExprNode): string | null {
    if (node.kind === 'identifier') return node.name;
    if (node.kind === 'member') {
      const parent = this.path(node.object);
      return parent ? `${parent}.${node.property}` : null;
    }
    return null;
  }

  private hasSchemaChildren(path: string): boolean {
    if (!this.schema) return false;
    for (const key of this.schema.keys()) {
      if (key.startsWith(`${path}.`)) return true;
    }
    return false;
  }

  check(node: ExprNode): ExpressionType {
    switch (node.kind) {
      case 'literal':
        if (node.value === null) return 'null';
        return typeof node.value as 'number' | 'string' | 'boolean';
      case 'identifier':
        if (!this.roots.has(node.name)) {
          this.report('UNKNOWN_IDENTIFIER', `Unknown identifier '${node.name}'`, node);
          return 'dyn';
        }
        return this.schema?.get(node.name) ?? (this.schema ? 'object' : 'dyn');
      case 'member':
        return this.checkMember(node);
      case 'index': {
        const objectType = this.check(node.object);
        const indexType = this.check(node.index);
        if (objectType === 'list') this.requireType(node.index, indexType, 'number', 'List index');
        else if (objectType === 'object') this.requireType(node.index, indexType, 'string', 'Object key');
        else if (objectType !== 'dyn') {
          this.report('TYPE_MISMATCH', `Cannot index a value of type ${objectType}`, node.object);
        }
        return 'dyn';
      }
      case 'list':
        for (const item of node.items) this.check(item);
        return 'list';
      case 'unary': {
        const operandType = this.check(node.operand);
        const expected = node.operator === '!' ? 'boolean' : 'number';
        this.requireType(node.operand, operandType, expected, `Operator '${node.operator}'`);
        return expected;
      }
      case 'binary':
        return this.checkBinary(node);
      case 'call':
        return this.checkCall(node);
    }
  }

  private checkMember(node: Extract<ExprNode, { kind: 'member' }>): ExpressionType {
    const objectType = this.check(node.object);
    if (objectType !== 'dyn' && objectType !== 'object') {
      this.report('TYPE_MISMATCH', `Cannot read field '${node.property}' of ${objectType}`, node.propertySpan);
      return 'dyn';
    }
    const path = this.path(node);
    if (!this.schema || !path) return 'dyn';
    const declared = this.schema.get(path);
    if (declared) return declared;
    if (this.hasSchemaChildren(path)) return 'object';
    if (objectType === 'dyn') return 'dyn';
    this.report('UNKNOWN_FIELD', `Unknown field '${path}'`, node.propertySpan);
    return 'dyn';
  }

  private checkBinary(node: Extract<ExprNode, { kind: 'binary' }>): ExpressionType {
    const left = this.check(node.left);
    const right = this.check(node.right);
    const context = `Operator '${node.operator}'`;

    switch (node.operator) {
      case '&&':
      case '||':
        this.requireType(node.left, left, 'boolean', context);
        this.requireType(node.right, right, 'boolean', context);
        return 'boolean';
      case '+':
        if (left === 'string' || right === 'string') {
          this.requireType(node.left, left, 'string', context);
          this.requireType(node.right, right, 'string', context);
          return 'string';
        }
        this.requireType(node.left, left, 'number', context);
        this.requireType(node.right, right, 'number', context);
        return left === 'dyn' || right === 'dyn' ? 'dyn' : 'number';
      case '-':
      case '*':
      case '/':
      case '%':
        this.requireType(node.left, left, 'number', context);
        this.requireType(node.right, right, 'number', context);
        return 'number';
      case '<':
      case '<=':
      case '>':
      case '>=':
        if (left === 'string' || right === 'string') {
          this.requireType(node.left, left, 'string', context);
          this.requireType(node.right, right, 'string', context);
        } else {
          this.requireType(node.left, left, 'number', context);
          this.requireType(node.right, right, 'number', context);
        }
        return 'boolean';
      case '==':
      case '!=':
        if (left !== 'dyn' && right !== 'dyn' && left !== right && left !== 'null' && right !== 'null') {
          this.report('TYPE_MISMATCH', `Cannot compare ${left} with ${right}`, node);
        }
        return 'boolean';
      case 'in':
        this.requireType(node.right, right, 'list', context);
        return 'boolean';
    }
  }

  private checkCall(node: Extract<ExprNode, { kind: 'call' }>): ExpressionType {
    const types = node.args.map((arg) => this.check(arg));
    if (node.name === 'abs') {
      this.requireType(node.args[0] as ExprNode, types[0] as ExpressionType, 'number', 'abs');
      return 'number';
    }
    node.args.forEach((arg, index) => {
      this.requireType(arg, types[index] as ExpressionType, 'string', node.name);
    });
    return 'boolean';
  }
}

// ── Linear-time regular expressions (Pike VM) ───────────────────────────────

interface CharRange {
  low: number;
  high: number;
}

type RegexNode =
  | { type: 'empty' }
  | { type: 'char'; ranges: CharRange[]; negated: boolean }
  | { type: 'start' }
  | { type: 'end' }
  | { type: 'concat'; parts: RegexNode[] }
  | { type: 'alternate'; options: RegexNode[] }
  | { type: 'repeat'; node: RegexNode; min: number; max: number | null };

type RegexInstruction =
  | { op: 'char'; ranges: CharRange[]; negated: boolean }
  | { op: 'split'; first: number; second: number }
  | { op: 'jump'; target: number }
  | { op: 'start' }
  | { op: 'end' }
  | { op: 'match' };

export type RegexProgram = RegexInstruction[];

const code = (char: string) => char.charCodeAt(0);
const DIGIT_RANGES: CharRange[] = [{ low: code('0'), high: code('9') }];
const WORD_RANGES: CharRange[] = [
  { low: code('0'), high: code('9') },
  { low: code('A'), high: code('Z') },
  { low: code('_'), high: code('_') },
  { low: code('a'), high: code('z') },
];
const SPACE_RANGES: CharRange[] = [
  { low: 9, high: 13 },
  { low: 32, high: 32 },
];

function invertRanges(ranges: CharRange[]): CharRange[] {
  const sorted = [...ranges].sort((a, b) => a.low - b.low);
  const inverted: CharRange[] = [];
  let next = 0;
  for (const range of sorted) {
    if (range.low > next) inverted.push({ low: next, high: range.low - 1 });
    next = Math.max(next, range.high + 1);
  }
  if (next <= 0xffff) inverted.push({ low: next, high: 0xffff });
  return inverted;
}

function classEscape(char: string): CharRange[] | null {
  switch (char) {
    case 'd':
      return DIGIT_RANGES;
    case 'D':
      return invertRanges(DIGIT_RANGES);
    case 'w':
      return WORD_RANGES;
    case 'W':
      return invertRanges(WORD_RANGES);
    case 's':
      return SPACE_RANGES;
    case 'S':
      return invertRanges(SPACE_RANGES);
    default:
      return null;
  }
}

const LITERAL_ESCAPES: Record<string, number> = { n: 10, r: 13, t: 9 };
const REGEX_METACHARACTERS = new Set('.^$*+?()[]{}|\\/-'.split(''));

class RegexParser {
  private pos = 0;
  private depth = 0;

  constructor(private readonly pattern: string) {}

  parse(): RegexNode {
    const node = this.alternate();
    if (this.pos < this.pattern.length) throw new Error(`unexpected '${this.pattern[this.pos]}'`);
    return node;
  }

  private alternate(): RegexNode {
    this.depth += 1;
    if (this.depth > MAX_AST_DEPTH) throw new Error('pattern is nested too deeply');
    const options = [this.concat()];
    while (this.pattern[this.pos] === '|') {
      this.pos += 1;
      options.push(this.concat());
    }
    this.depth -= 1;
    return options.length === 1 ? (options[0] as RegexNode) : { type: 'alternate', options };
  }

  private concat(): RegexNode {
    const parts: RegexNode[] = [];
    while (this.pos < this.pattern.length && this.pattern[this.pos] !== '|' && this.pattern[this.pos] !== ')') {
      parts.push(this.repeat());
    }
    if (parts.length === 0) return { type: 'empty' };
    return parts.length === 1 ? (parts[0] as RegexNode) : { type: 'concat', parts };
  }

  private repeat(): RegexNode {
    let node = this.atom();
    let quantified = false;
    for (;;) {
      const char = this.pattern[this.pos];
      let min: number;
      let max: number | null;
      if (char === '*') {
        [min, max] = [0, null];
        this.pos += 1;
      } else if (char === '+') {
        [min, max] = [1, null];
        this.pos += 1;
      } else if (char === '?') {
        if (quantified) throw new Error('lazy quantifiers are not supported');
        [min, max] = [0, 1];
        this.pos += 1;
      } else if (char === '{') {
        [min, max] = this.bounds();
      } else {
        return node;
      }
      if (quantified) throw new Error('nested quantifier');
      if (node.type === 'start' || node.type === 'end') throw new Error('cannot quantify an anchor');
      node = { type: 'repeat', node, min, max };
      quantified = true;
    }
  }

  private bounds(): [number, number | null] {
    const match = /^\{(\d{1,3})(?:(,)(\d{1,3})?)?\}/.exec(this.pattern.slice(this.pos, this.pos + 10));
    if (!match) throw new Error('invalid repetition bounds');
    this.pos += match[0].length;
    const min = Number(match[1]);
    const max = match[2] ? (match[3] === undefined ? null : Number(match[3])) : min;
    if (max !== null && max < min) throw new Error('repetition maximum is below minimum');
    return [min, max];
  }

  private atom(): RegexNode {
    const char = this.pattern[this.pos] as string;
    switch (char) {
      case '(': {
        this.pos += 1;
        if (this.pattern[this.pos] === '?') {
          if (this.pattern[this.pos + 1] !== ':') throw new Error('lookaround and named groups are not supported');
          this.pos += 2;
        }
        const inner = this.alternate();
        if (this.pattern[this.pos] !== ')') throw new Error('unterminated group');
        this.pos += 1;
        return inner;
      }
      case '[':
        return this.characterClass();
      case '.':
        this.pos += 1;
        return { type: 'char', ranges: [{ low: 10, high: 10 }], negated: true };
      case '^':
        this.pos += 1;
        return { type: 'start' };
      case '$':
        this.pos += 1;
        return { type: 'end' };
      case '\\':
        return this.escape();
      case '*':
      case '+':
      case '?':
      case '{':
        throw new Error(`nothing to repeat at '${char}'`);
      default:
        this.pos += 1;
        return { type: 'char', ranges: [{ low: code(char), high: code(char) }], negated: false };
    }
  }

  private escapeRanges(): CharRange[] {
    const char = this.pattern[this.pos + 1];
    if (char === undefined) throw new Error('trailing backslash');
    this.pos += 2;
    const predefined = classEscape(char);
    if (predefined) return predefined;
    const literal = LITERAL_ESCAPES[char];
    if (literal !== undefined) return [{ low: literal, high: literal }];
    if (REGEX_METACHARACTERS.has(char)) return [{ low: code(char), high: code(char) }];
    throw new Error(`unsupported escape \\${char}`);
  }

  private escape(): RegexNode {
    return { type: 'char', ranges: this.escapeRanges(), negated: false };
  }

  private characterClass(): RegexNode {
    this.pos += 1;
    const negated = this.pattern[this.pos] === '^';
    if (negated) this.pos += 1;

    const ranges: CharRange[] = [];
    let first = true;
    while (this.pattern[this.pos] !== ']' || first) {
      if (this.pos >= this.pattern.length) throw new Error('unterminated character class');
      first = false;

      const low = this.classAtom();
      if (low.length !== 1 || low[0]?.low !== low[0]?.high) {
        ranges.push(...low);
        continue;
      }
      if (this.pattern[this.pos] === '-' && this.pattern[this.pos + 1] !== ']' && this.pos + 1 < this.pattern.length) {
        this.pos += 1;
        const high = this.classAtom();
        if (high.length !== 1 || high[0]?.low !== high[0]?.high) throw new Error('invalid character range');
        const lowCode = low[0]?.low as number;
        const highCode = high[0]?.low as number;
        if (highCode < lowCode) throw new Error('character range is out of order');
        ranges.push({ low: lowCode, high: highCode });
      } else {
        ranges.push(...low);
      }
    }
    this.pos += 1;
    return { type: 'char', ranges, negated };
  }

  private classAtom(): CharRange[] {
    if (this.pattern[this.pos] === '\\') return this.escapeRanges();
    const char = this.pattern[this.pos];
    if (char === undefined) throw new Error('unterminated character class');
    this.pos += 1;
    return [{ low: code(char), high: code(char) }];
  }
}

function emitRegex(node: RegexNode, program: RegexProgram): void {
  const push = (instruction: RegexInstruction): number => {
    if (program.length >= MAX_REGEX_PROGRAM_SIZE) throw new Error('pattern is too complex');
    program.push(instruction);
    return program.length - 1;
  };

  switch (node.type) {
    case 'empty':
      return;
    case 'char':
      push({ op: 'char', ranges: node.ranges, negated: node.negated });
      return;
    case 'start':
      push({ op: 'start' });
      return;
    case 'end':
      push({ op: 'end' });
      return;
    case 'concat':
      for (const part of node.parts) emitRegex(part, program);
      return;
    case 'alternate': {
      const jumps: number[] = [];
      node.options.forEach((option, index) => {
        if (index === node.options.length - 1) {
          emitRegex(option, program);
          return;
        }
        const split = push({ op: 'split', first: 0, second: 0 });
        emitRegex(option, program);
        jumps.push(push({ op: 'jump', target: 0 }));
        program[split] = { op: 'split', first: split + 1, second: program.length };
      });
      for (const jump of jumps) program[jump] = { op: 'jump', target: program.length };
      return;
    }
    case 'repeat': {
      for (let count = 0; count < node.min; count += 1) emitRegex(node.node, program);
      if (node.max === null) {
        const split = push({ op: 'split', first: 0, second: 0 });
        emitRegex(node.node, program);
        push({ op: 'jump', target: split });
        program[split] = { op: 'split', first: split + 1, second: program.length };
        return;
      }
      const splits: number[] = [];
      for (let count = node.min; count < node.max; count += 1) {
        splits.push(push({ op: 'split', first: 0, second: 0 }));
        emitRegex(node.node, program);
      }
      for (const split of splits) program[split] = { op: 'split', first: split + 1, second: program.length };
    }
  }
}

function compileRegex(pattern: string): RegexProgram {
  if (pattern.length > MAX_REGEX_PATTERN_LENGTH) {
    throw new Error(`pattern exceeds ${MAX_REGEX_PATTERN_LENGTH} characters`);
  }
  const program: RegexProgram = [];
  emitRegex(new RegexParser(pattern).parse(), program);
  if (program.length >= MAX_REGEX_PROGRAM_SIZE) throw new Error('pattern is too complex');
  program.push({ op: 'match' });
  return program;
}

function charMatches(instruction: Extract<RegexInstruction, { op: 'char' }>, charCode: number): boolean {
  const inRange = instruction.ranges.some((range) => charCode >= range.low && charCode <= range.high);
  return inRange !== instruction.negated;
}

/** Unanchored search over UTF-16 code units; time is O(input × program). */
function runRegex(program: RegexProgram, input: string, checkLimit: () => void): boolean {
  let current: number[] = [];
  let next: number[] = [];
  const marks = new Int32Array(program.length).fill(-1);
  let vmSteps = 0;
  let generation = 0;

  const charge = () => {
    vmSteps += 1;
    if (vmSteps > MAX_REGEX_VM_STEPS) {
      throw new EvaluationFailure('BUDGET_EXCEEDED', 'Regular expression exceeded its step budget');
    }
    if (vmSteps % REGEX_DEADLINE_CHECK_INTERVAL === 0) checkLimit();
  };

  const addThread = (list: number[], start: number, position: number): boolean => {
    const stack = [start];
    while (stack.length > 0) {
      const pc = stack.pop() as number;
      if (marks[pc] === generation) continue;
      marks[pc] = generation;
      charge();
      const instruction = program[pc] as RegexInstruction;
      switch (instruction.op) {
        case 'jump':
          stack.push(instruction.target);
          break;
        case 'split':
          stack.push(instruction.second, instruction.first);
          break;
        case 'start':
          if (position === 0) stack.push(pc + 1);
          break;
        case 'end':
          if (position === input.length) stack.push(pc + 1);
          break;
        case 'match':
          return true;
        case 'char':
          list.push(pc);
          break;
      }
    }
    return false;
  };

  for (let position = 0; position <= input.length; position += 1) {
    // `current` already holds threads advanced from the previous position, so
    // their marks stay valid while the fresh start thread is seeded.
    if (addThread(current, 0, position)) return true;
    if (position === input.length) return false;

    generation += 1;
    next = [];
    const charCode = input.charCodeAt(position);
    for (const pc of current) {
      charge();
      const instruction = program[pc] as Extract<RegexInstruction, { op: 'char' }>;
      if (charMatches(instruction, charCode) && addThread(next, pc + 1, position + 1)) return true;
    }
    [current, next] = [next, current];
  }
  return false;
}

// ── Evaluator ───────────────────────────────────────────────────────────────

class EvaluationFailure extends Error {
  span?: Span;

  constructor(
    readonly code: EvaluationErrorCode,
    message: string,
    span?: Span,
  ) {
    super(message);
    this.span = span;
  }
}

function typeName(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'list';
  return typeof value;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function readOwnData(target: object, key: string): { found: boolean; value?: unknown } {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  if (!descriptor || !('value' in descriptor)) return { found: false };
  return { found: true, value: descriptor.value };
}

function toExpressionValue(value: unknown, span: Span): ExpressionValue {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new EvaluationFailure('NUMERIC_OVERFLOW', 'Field is not a finite number', span);
    return value;
  }
  if (Array.isArray(value) || isPlainObject(value)) return value as ExpressionValue;
  throw new EvaluationFailure('TYPE_ERROR', `Unsupported value of type ${typeof value}`, span);
}

function finite(value: number, span: Span): number {
  if (!Number.isFinite(value)) throw new EvaluationFailure('NUMERIC_OVERFLOW', 'Arithmetic result is not finite', span);
  return value;
}

function expectNumber(value: ExpressionValue, node: ExprNode, context: string): number {
  if (typeof value !== 'number') {
    throw new EvaluationFailure('TYPE_ERROR', `${context} requires number but received ${typeName(value)}`, node);
  }
  return value;
}

function expectString(value: ExpressionValue, node: ExprNode, context: string): string {
  if (typeof value !== 'string') {
    throw new EvaluationFailure('TYPE_ERROR', `${context} requires string but received ${typeName(value)}`, node);
  }
  return value;
}

function expectBoolean(value: ExpressionValue, node: ExprNode, context: string): boolean {
  if (typeof value !== 'boolean') {
    throw new EvaluationFailure('TYPE_ERROR', `${context} requires boolean but received ${typeName(value)}`, node);
  }
  return value;
}

function scalarEquals(left: ExpressionValue, right: ExpressionValue, node: ExprNode): boolean {
  if (left === null || right === null) return left === right;
  const leftType = typeName(left);
  const rightType = typeName(right);
  if (leftType !== rightType) {
    throw new EvaluationFailure('TYPE_ERROR', `Cannot compare ${leftType} with ${rightType}`, node);
  }
  if (leftType === 'list' || leftType === 'object') {
    throw new EvaluationFailure('TYPE_ERROR', `Cannot compare values of type ${leftType}`, node);
  }
  return left === right;
}

class Evaluator {
  steps = 0;
  private readonly maxSteps: number;
  private readonly deadline: number;
  private readonly now: () => number;

  constructor(
    private readonly context: Record<string, unknown>,
    options: EvaluateOptions,
  ) {
    this.maxSteps = Math.min(options.maxSteps ?? MAX_EVALUATION_STEPS, MAX_EVALUATION_STEPS);
    this.now = options.now ?? (() => performance.now());
    this.deadline = this.now() + (options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  }

  private readonly checkDeadline = (): void => {
    if (this.now() > this.deadline) {
      throw new EvaluationFailure('TIMEOUT', 'Expression exceeded its execution deadline');
    }
  };

  evaluate(node: ExprNode): ExpressionValue {
    this.steps += 1;
    if (this.steps > this.maxSteps) {
      throw new EvaluationFailure('BUDGET_EXCEEDED', `Expression exceeded ${this.maxSteps} evaluation steps`, node);
    }
    this.checkDeadline();

    try {
      return this.evaluateNode(node);
    } catch (err: unknown) {
      if (err instanceof EvaluationFailure && !err.span) err.span = node;
      throw err;
    }
  }

  private evaluateNode(node: ExprNode): ExpressionValue {
    switch (node.kind) {
      case 'literal':
        return node.value;
      case 'identifier': {
        const root = readOwnData(this.context, node.name);
        if (!root.found) throw new EvaluationFailure('FIELD_NOT_FOUND', `Field '${node.name}' is not set`, node);
        return toExpressionValue(root.value, node);
      }
      case 'member':
        return this.readKey(this.evaluate(node.object), node.property, node);
      case 'index':
        return this.readIndex(this.evaluate(node.object), this.evaluate(node.index), node);
      case 'list':
        return node.items.map((item) => this.evaluate(item));
      case 'unary': {
        const operand = this.evaluate(node.operand);
        return node.operator === '!'
          ? !expectBoolean(operand, node.operand, "Operator '!'")
          : -expectNumber(operand, node.operand, "Operator '-'");
      }
      case 'binary':
        return this.evaluateBinary(node);
      case 'call':
        return this.evaluateCall(node);
    }
  }

  private readKey(target: ExpressionValue, key: string, node: ExprNode): ExpressionValue {
    if (FORBIDDEN_MEMBERS.has(key)) {
      throw new EvaluationFailure('FORBIDDEN_MEMBER', `Access to '${key}' is not allowed`, node);
    }
    if (!isPlainObject(target)) {
      throw new EvaluationFailure('TYPE_ERROR', `Cannot read field '${key}' of ${typeName(target)}`, node);
    }
    const result = readOwnData(target, key);
    if (!result.found) throw new EvaluationFailure('FIELD_NOT_FOUND', `Field '${key}' is not set`, node);
    return toExpressionValue(result.value, node);
  }

  private readIndex(target: ExpressionValue, index: ExpressionValue, node: ExprNode): ExpressionValue {
    if (Array.isArray(target)) {
      if (typeof index !== 'number' || !Number.isInteger(index)) {
        throw new EvaluationFailure('TYPE_ERROR', 'List index must be an integer', node);
      }
      if (index < 0 || index >= target.length) {
        throw new EvaluationFailure('INDEX_OUT_OF_BOUNDS', `List index ${index} is out of bounds`, node);
      }
      return toExpressionValue(readOwnData(target, String(index)).value, node);
    }
    if (typeof index !== 'string') {
      throw new EvaluationFailure('TYPE_ERROR', 'Object key must be a string', node);
    }
    return this.readKey(target, index, node);
  }

  private evaluateBinary(node: Extract<ExprNode, { kind: 'binary' }>): ExpressionValue {
    const context = `Operator '${node.operator}'`;

    if (node.operator === '&&' || node.operator === '||') {
      const left = expectBoolean(this.evaluate(node.left), node.left, context);
      if (node.operator === '&&' ? !left : left) return left;
      return expectBoolean(this.evaluate(node.right), node.right, context);
    }

    const left = this.evaluate(node.left);
    const right = this.evaluate(node.right);

    switch (node.operator) {
      case '+':
        if (typeof left === 'string' || typeof right === 'string') {
          const joined = expectString(left, node.left, context) + expectString(right, node.right, context);
          if (joined.length > MAX_EXPRESSION_LENGTH) {
            throw new EvaluationFailure('BUDGET_EXCEEDED', 'String result is too long', node);
          }
          return joined;
        }
        return finite(expectNumber(left, node.left, context) + expectNumber(right, node.right, context), node);
      case '-':
        return finite(expectNumber(left, node.left, context) - expectNumber(right, node.right, context), node);
      case '*':
        return finite(expectNumber(left, node.left, context) * expectNumber(right, node.right, context), node);
      case '/':
      case '%': {
        const dividend = expectNumber(left, node.left, context);
        const divisor = expectNumber(right, node.right, context);
        if (divisor === 0) throw new EvaluationFailure('DIVISION_BY_ZERO', 'Division by zero', node.right);
        return finite(node.operator === '/' ? dividend / divisor : dividend % divisor, node);
      }
      case '==':
        return scalarEquals(left, right, node);
      case '!=':
        return !scalarEquals(left, right, node);
      case '<':
      case '<=':
      case '>':
      case '>=':
        return this.compare(node.operator, left, right, node);
      case 'in':
        return this.contains(left, right, node);
    }
  }

  private compare(
    operator: '<' | '<=' | '>' | '>=',
    left: ExpressionValue,
    right: ExpressionValue,
    node: Extract<ExprNode, { kind: 'binary' }>,
  ): boolean {
    const context = `Operator '${operator}'`;
    let a: number | string;
    let b: number | string;
    if (typeof left === 'string' || typeof right === 'string') {
      a = expectString(left, node.left, context);
      b = expectString(right, node.right, context);
    } else {
      a = expectNumber(left, node.left, context);
      b = expectNumber(right, node.right, context);
    }
    if (operator === '<') return a < b;
    if (operator === '<=') return a <= b;
    if (operator === '>') return a > b;
    return a >= b;
  }

  private contains(needle: ExpressionValue, haystack: ExpressionValue, node: Extract<ExprNode, { kind: 'binary' }>): boolean {
    if (!Array.isArray(haystack)) {
      throw new EvaluationFailure('TYPE_ERROR', `Operator 'in' requires list but received ${typeName(haystack)}`, node.right);
    }
    for (let index = 0; index < haystack.length; index += 1) {
      // Each comparison is charged so a large context list cannot bypass the budget.
      this.steps += 1;
      if (this.steps > this.maxSteps) {
        throw new EvaluationFailure('BUDGET_EXCEEDED', `Expression exceeded ${this.maxSteps} evaluation steps`, node);
      }
      this.checkDeadline();
      const item = toExpressionValue(readOwnData(haystack, String(index)).value, node);
      if (typeName(item) === typeName(needle) && scalarEquals(needle, item, node)) return true;
    }
    return false;
  }

  private evaluateCall(node: Extract<ExprNode, { kind: 'call' }>): ExpressionValue {
    const first = node.args[0] as ExprNode;
    if (node.name === 'abs') return Math.abs(expectNumber(this.evaluate(first), first, 'abs'));

    const second = node.args[1] as ExprNode;
    const subject = expectString(this.evaluate(first), first, node.name);
    const argument = expectString(this.evaluate(second), second, node.name);
    if (node.name === 'startsWith') return subject.startsWith(argument);

    if (subject.length > MAX_REGEX_INPUT_LENGTH) {
      throw new EvaluationFailure('REGEX_INPUT_TOO_LONG', `matches input exceeds ${MAX_REGEX_INPUT_LENGTH} characters`, first);
    }
    return runRegex(node.regex as RegexProgram, subject, this.checkDeadline);
  }
}

// ── Public engine ───────────────────────────────────────────────────────────

export class SafeExpressionEngine {
  /** Parses and type-checks an expression, returning positioned diagnostics. */
  compile(source: string, options: CompileOptions = {}): CompileResult {
    if (source.length > MAX_EXPRESSION_LENGTH) {
      return {
        ok: false,
        diagnostics: [
          diagnostic('EXPRESSION_TOO_LONG', `Expression exceeds ${MAX_EXPRESSION_LENGTH} characters`, {
            offset: MAX_EXPRESSION_LENGTH,
            length: 1,
          }),
        ],
      };
    }

    let ast: ExprNode;
    try {
      ast = new Parser(tokenize(source)).parse();
    } catch (err: unknown) {
      if (err instanceof CompileFailure) return { ok: false, diagnostics: [err.diagnostic] };
      throw err;
    }

    const checker = new TypeChecker(options);
    const resultType = checker.check(ast);
    if (resultType !== 'boolean' && resultType !== 'dyn') {
      checker.diagnostics.push(
        diagnostic('TYPE_MISMATCH', `Policy expression must evaluate to boolean but has type ${resultType}`, ast),
      );
    }
    if (checker.diagnostics.length > 0) {
      const diagnostics = [...checker.diagnostics].sort((a, b) => a.offset - b.offset);
      return { ok: false, diagnostics };
    }

    return { ok: true, expression: Object.freeze({ source, ast, resultType }), diagnostics: [] };
  }

  /** Validation entry point for rule editors; never evaluates the expression. */
  validate(source: string, options: CompileOptions = {}): ExpressionDiagnostic[] {
    return this.compile(source, options).diagnostics;
  }

  /**
   * Evaluates a compiled expression. Never throws for expression failures;
   * callers should treat `ok: false` as "policy did not match" (fail closed).
   */
  evaluate(
    expression: CompiledExpression,
    context: Record<string, unknown>,
    options: EvaluateOptions = {},
  ): EvaluationResult {
    const evaluator = new Evaluator(context, options);
    try {
      const value = evaluator.evaluate(expression.ast);
      if (typeof value !== 'boolean') {
        throw new EvaluationFailure(
          'NON_BOOLEAN_RESULT',
          `Policy expression evaluated to ${typeName(value)}`,
          expression.ast,
        );
      }
      return { ok: true, value, steps: evaluator.steps };
    } catch (err: unknown) {
      if (err instanceof EvaluationFailure) {
        const offset = err.span?.offset ?? 0;
        return {
          ok: false,
          error: { code: err.code, message: err.message, column: offset + 1, offset },
          steps: evaluator.steps,
        };
      }
      throw err;
    }
  }
}

export const safeExpressionEngine = new SafeExpressionEngine();
