/**
 * EC-ACT: Anonymous Credit Tokens (draft-schlesinger-mole-ec-act-00) over
 * P-256, with compact Sigma proofs (draft-irtf-cfrg-sigma-protocols-03).
 * Protocol operations are asynchronous: their scalar multiplications run in
 * batches on WebCrypto where available, on noble otherwise.
 *
 * @module
 */

export {
  type ClientIssuanceState,
  type ClientSpendState,
  type Credential,
  contextScalar,
  createParams,
  createProtocolContext,
  deriveKeys,
  finalizeIssue,
  finalizeRefund,
  generateKeys,
  IDENTIFIER,
  type IssueRequestMessage,
  type IssueResponseMessage,
  issueRefund,
  issueRequest,
  issueResponse,
  type KeyPair,
  MAX_BIT_LENGTH,
  type Params,
  proveSpend,
  type Random,
  type RefundMessage,
  rangeWeights,
  type SpendMessage,
  VerifiedSpend,
  verifySpend,
} from './act.ts';
export { ACTError, type ACTErrorCode } from './errors.ts';
export type { Point } from './group.ts';
export * from './wire.ts';
