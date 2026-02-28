# /review-api

**Persona**: ACT API Consumer (rate-limiting/metering use case)

**Focus**: Usability, ergonomics, integration experience.

## Checklist

- Clear separation: issuer vs client vs redeemer roles
- Error types distinguish recoverable vs fatal
- State machine transitions obvious (PreIssuance → IssuanceRequest → ...)
- Serialization easy for storage/transmission
- Documentation sufficient to use without reading source
- TypeScript types guide correct usage (illegal states unrepresentable)
- Examples cover primary use cases

## Integration Scenarios

- **Rate limiting**: User gets N tokens per period, spends on each request
- **Metering**: Track usage credits across services
- **Prepaid**: Purchase credits, spend down

## Sample Questions

- If I have a CreditToken, what can I do with it? Is that obvious from types?
- How do I persist state between issuance and spending?
- What errors should I catch vs let propagate?
