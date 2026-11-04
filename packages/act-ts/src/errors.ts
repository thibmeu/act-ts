/**
 * Errors of draft-schlesinger-mole-ec-act-00, Section 3.2.
 */
export type ACTErrorCode =
  /** A byte string is not a canonical encoding. */
  | 'Deserialize'
  /** A received value failed a verification check. */
  | 'Verify'
  /** A derivation produced an unusable scalar (negligible probability). */
  | 'Derive'
  /** An input has an invalid length or is outside its permitted range. */
  | 'Value'
  /** A credit amount is outside its permitted range. */
  | 'Amount';

export class ACTError extends Error {
  override name = 'ACTError';
  readonly code: ACTErrorCode;

  constructor(code: ACTErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}
