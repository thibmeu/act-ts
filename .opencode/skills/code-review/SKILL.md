---
name: code-review
description: Multi-persona code review. Supports security, correctness, and maintainability lenses. Adapts to codebase via AGENTS.md.
---

# Code Review Skill

Review code through specialized personas. Each catches different bug classes.

## Usage

```
/review security
/review correctness
/review maintainability
/review              # auto-selects from diff
/review all          # all personas
```

---

## Personas

### security

**Focus**: Vulnerabilities, input validation, secret handling, injection.

**Universal checks**:

- Input validation at trust boundaries
- No secrets in logs/errors
- Proper authentication/authorization
- Injection prevention (SQL, command, path traversal)
- Safe deserialization
- CSRF/XSS where applicable

**Language-specific** (infer from codebase):

- Memory safety, buffer handling
- Cryptographic misuse (weak RNG, timing attacks, hardcoded keys)
- Dependency vulnerabilities

---

### correctness

**Focus**: Logic errors, edge cases, spec compliance, type safety.

**Universal checks**:

- Off-by-one errors
- Null/undefined handling
- Integer overflow/underflow
- Race conditions
- Error handling completeness
- Boundary conditions

**Spec compliance** (when AGENTS.md references specs):

- Cite specific sections
- Flag deviations without justification

---

### maintainability

**Focus**: Readability, testability, future maintenance burden.

**Universal checks**:

- Dead code
- Excessive complexity (deep nesting, long functions)
- Poor naming
- Missing/misleading comments
- Code duplication
- Test coverage gaps

**Style** (defer to AGENTS.md):

- Follow codebase conventions
- Type safety patterns per project rules

---

## Auto-Selection Heuristics

When no persona specified, select based on changed paths:

| Pattern                                                     | Personas              |
| ----------------------------------------------------------- | --------------------- |
| `auth`, `crypto`, `security`, `password`, `token`, `secret` | security              |
| `test`, `spec`, `.test.`, `.spec.`                          | maintainability       |
| `api`, `handler`, `controller`, `route`                     | security, correctness |
| `encoding`, `parsing`, `serialize`                          | correctness           |
| Default                                                     | all three             |

---

## Review Output Format

```
[PERSONA] severity: description
  location: file:line
  why: impact explanation
  fix: concrete suggestion
```

Severities: `critical` > `high` > `medium` > `low` > `nit`

---

## Codebase Adaptation

**Read AGENTS.md** for:

- Language/framework conventions
- Type safety rules
- Test requirements
- Spec references to verify against
- Boundaries (what's allowed, what requires approval)

Apply codebase rules as additional constraints on each persona.
