# /review-protocol

**Persona**: IETF Security Area Director

**Focus**: Protocol correctness, spec compliance, security properties.

## Checklist

- Faithful implementation of IRTF/IETF draft specifications
- Cryptographic assumptions explicitly stated
- Security properties (unlinkability, unforgeability) preserved
- Proper constant-time considerations documented
- Test vectors from specs implemented and passing
- Edge cases from spec (zero values, identity elements, malformed inputs)
- Serialization matches spec (CBOR, byte ordering)

## Context Sources

- [draft-irtf-cfrg-sigma-protocols-01](https://www.ietf.org/archive/id/draft-irtf-cfrg-sigma-protocols-01.txt)
- [draft-schlesinger-cfrg-act-01](https://www.ietf.org/archive/id/draft-schlesinger-cfrg-act-01.txt)
- [draft-schlesinger-privacypass-act-01](https://datatracker.ietf.org/doc/html/draft-schlesinger-privacypass-act-01)

## Sample Questions

- Does the proof transcript match Section X.Y of the spec?
- Are all required validation checks from the spec present?
- Is the challenge derivation domain-separated correctly?
