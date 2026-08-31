## Change

Describe the artifact behavior and why this is the smallest safe change.

## Evidence

- [ ] Positive, negative, and boundary tests added or updated
- [ ] Deterministic ordering and severity overrides considered
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `pytest` passes with branch coverage
- [ ] `python -m build` succeeds

## Security boundary

State whether this changes parsing, filesystem access, resource limits, policy,
or process execution. Confirm that no test executes submitted artifact content.
