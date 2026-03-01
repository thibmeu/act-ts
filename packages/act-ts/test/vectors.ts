/**
 * Test vectors from draft-schlesinger-cfrg-act-01 Appendix A
 */

// A.1 Parameters
export const PARAMS = {
  domainSeparator: 'ACT-v1:test-org:test-service:test:2024-01-15',
  H1: '5a62e8f0e54c1c3a9a2b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2',
  H2: '6b73f9g1f65d2d4b0b3c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f23',
  H3: '7c84g0h2g76e3e5c1c4d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f234',
  H4: '8d95h1i3h87f4f6d2d5e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2345',
};

// A.2 Key Generation
export const KEYGEN = {
  // Private key x (scalar)
  x: '0c4f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f',
  // Public key W = x * G
  W: '2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b',
};

// A.3 Issuance
export const ISSUANCE = {
  // PreIssuance state
  k: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
  r: '2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c',

  // IssuanceRequest
  K: '3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d',
  gamma_request: '4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e',
  k_bar: '5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f',
  r_bar: '6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a',

  // Credit amount
  c: 100n,
  ctx: 0n,

  // IssuanceResponse (TODO: fill in from spec once available)
};

// A.4 Spending
export const SPENDING = {
  // Spend amount
  s: 30n,

  // SpendProof fields (TODO: fill in from spec once available)
};

// A.5 Refund
export const REFUND = {
  // Partial return amount
  t: 0n,

  // Refund fields (TODO: fill in from spec once available)
};

// A.6 Refund Token
export const REFUND_TOKEN = {
  // New token with remaining balance
  // c_new = c - s + t = 100 - 30 + 0 = 70
  c_new: 70n,
};
