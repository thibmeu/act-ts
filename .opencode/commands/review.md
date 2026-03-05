---
description: Code review with security/correctness/maintainability personas
subtask: true
---

Load the code-review skill, then review the current changes.

**Persona requested**: $ARGUMENTS

**Instructions**:

1. If `$ARGUMENTS` is empty, auto-select personas based on changed files (see skill heuristics)
2. If `$ARGUMENTS` specifies a persona (`security`, `correctness`, `maintainability`), use only that lens
3. If `$ARGUMENTS` is `all`, use all three personas

**Get the diff**:
!`git diff HEAD`

If staged changes exist, also review:
!`git diff --cached`

**Apply the review**:

- Use the persona-specific checklists from the skill
- Output findings in the specified format
- Prioritize critical/high severity issues
- For crypto code, bias toward false positives over missed vulnerabilities
