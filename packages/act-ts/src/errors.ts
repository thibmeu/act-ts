/**
 * ACT Protocol Errors
 */

/**
 * Error codes for ACT protocol operations
 */
export enum ACTErrorCode {
  InvalidIssuanceRequestProof = 1,
  InvalidIssuanceResponseProof = 2,
  InvalidSpendProof = 3,
  InvalidRefundProof = 4,
  DoubleSpend = 5,
  InvalidAmount = 6,
  AmountTooBig = 7,
  ScalarOutOfRange = 8,
  IdentityPoint = 9,
  InvalidParameter = 10,
  InvalidRefundAmount = 11,
}

/**
 * Error type for ACT protocol operations
 */
export class ACTError extends Error {
  constructor(
    message: string,
    readonly code: ACTErrorCode
  ) {
    super(message);
    this.name = 'ACTError';
  }
}
