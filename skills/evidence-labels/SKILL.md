---
name: evidence-labels
description: "Labels decision-relevant claims as measured, inferred, or assumed and names what was not checked. Use for test results, status, diagnoses, incident reports, and reviews."
license: MIT
metadata:
  version: "0.1"
---

# Evidence Labels

A confident claim nobody checked is the most expensive kind. Put the level of proof on the claims a reader will act on.

## The three labels

- **measured** - I performed the stated check in the named runtime or artifact and observed the stated output. Include scope and time (the number, exit code, row count or file size, and when). A log is a measured artifact, not automatically a measurement of the state it describes.
- **inferred** - I read the config, code or logs and concluded it. I did not run it.
- **assumed** - I have not checked it.

"I have not tested this" is a complete and acceptable answer.

## Rules

1. Label each decision-relevant claim or tightly related claim group. Do not hide mixed evidence classes inside one label, and do not add labels to purely normative or procedural text.
2. Name who did it: "I ran", "you ran", "the other agent says". Another agent's statement is never *measured* by you.
3. A test result is not a live result. Say which one you have. A test result proves only the exercised fixture, path, and assertion; name what the test did not exercise.
4. Do not say "should work", "appears to", "probably fine". Say what you saw, or say you did not check.
5. Before "X does not exist", list the places you looked and the places you did not.
6. If you were wrong earlier, say so first.

## Example

Bad: "The backup works."

Good: "**Measured:** the copy step finished with exit code 0, and the destination count matches the source count (412 files). **Assumed:** file identity and content completeness; no manifest or content hashes were compared. **Assumed:** a restore would succeed; I have not tried one. Next step: compare hashes, then restore one file to a scratch folder."
