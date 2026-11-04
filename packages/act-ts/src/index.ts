/**
 * EC-ACT: Anonymous Credit Tokens (draft-schlesinger-mole-ec-act-00) over
 * P-256, with compact Sigma proofs (draft-irtf-cfrg-sigma-protocols-03).
 *
 * @module
 */

export {
  IDENTIFIER,
  MAX_BIT_LENGTH,
  VerifiedSpend,
  contextScalar,
  createParams,
  createProtocolContext,
  deriveKeys,
  finalizeIssue,
  finalizeIssueAsync,
  finalizeRefund,
  finalizeRefundAsync,
  generateKeys,
  issueRefund,
  issueRefundAsync,
  issueRequest,
  issueRequestAsync,
  issueResponse,
  issueResponseAsync,
  proveSpend,
  proveSpendAsync,
  rangeWeights,
  verifySpend,
  verifySpendAsync,
  type ClientIssuanceState,
  type ClientSpendState,
  type Credential,
  type IssueRequestMessage,
  type IssueResponseMessage,
  type KeyPair,
  type Params,
  type Random,
  type RefundMessage,
  type SpendMessage,
} from './act.js';
export { ACTError, type ACTErrorCode } from './errors.js';
export type { Point } from './group.js';
export * from './wire.js';
