# privacypass-act

Privacy Pass integration for Anonymous Credit Tokens.

**Specification:** [draft-schlesinger-privacypass-act-01](https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/)

**Status:** Not yet implemented

## Overview

This package integrates ACT with the Privacy Pass architecture (RFC 9576, RFC 9577, RFC 9578), enabling:

- Token challenges and responses per Privacy Pass HTTP authentication
- Credential issuance via Privacy Pass token request/response
- Token redemption with spend proofs and refunds

## Planned Features

- `TokenChallenge` parsing with ACT extensions (`credential_context`, `cost`)
- `TokenRequest` / `TokenResponse` message encoding
- `Token` creation from ACT spend proofs
- `Refund` handling for credential chain management

## Token Type

```
token_type = 0xE5AD  // ACT(Ristretto255)
```

## Protocol Flow

```
Client                    Attester              Issuer/Origin
  |                          |                       |
  +---- Request ----------------------------------->|
  |<--- TokenChallenge (with cost) -----------------|
  |                          |                       |
  |<=== Attestation ========>|                       |
  +---- CredentialRequest -->|                       |
  |     (TokenRequest)       +-- TokenRequest ------>|
  |                          |<-- TokenResponse -----|
  |<--- CredentialResponse --|                       |
  |     (TokenResponse)      |                       |
  |                          |                       |
  +---- Request + Token ---------------------------->|
  |<--- Response + Refund ---------------------------|
  |                          |                       |
```

## Request Context

The `ctx` parameter binds credentials to application context:

```typescript
request_context = concat(
  tokenChallenge.issuer_name,
  tokenChallenge.origin_info,
  tokenChallenge.credential_context,
  issuer_key_id
);
```

## Installation

```bash
npm install privacypass-act
```

## Development

```bash
npm test        # Run tests
npm run build   # Build package
```

## Related

- [act](../act) - Core ACT protocol
- [privacypass-ts](https://github.com/cloudflare/privacypass-ts) - Privacy Pass TypeScript library

## License

Apache-2.0
