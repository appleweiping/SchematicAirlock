# Contributing

Thank you for helping make untrusted circuit artifacts easier to inspect.

## Development setup

Use Python 3.11 or newer in an isolated environment:

```console
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
pytest
python -m build
```

Keep runtime code free of third-party dependencies unless a proposal explains
why the security and maintenance cost is necessary. Tests may use development
dependencies declared in `pyproject.toml`.

## Changes

Open an issue for a new parsing capability, policy surface, or finding family.
Describe the concrete artifact, expected decision, simulator dialect if
relevant, false-positive risk, and proposed resource bound.

Each behavior change needs focused tests. A new rule needs safe, unsafe,
boundary, deterministic-order, and policy-override cases. Never execute an
artifact during a test. Fixtures must be original, minimal, and free of
proprietary model data.

Run the full quality suite before opening a pull request. Update the changelog
and public documentation when user-visible behavior changes. Keep commits
focused and make review possible without generated noise.

Every commit must carry an author-matching `Signed-off-by` DCO trailer. Use
`git commit -s` and retain each trailer when rebasing. The trusted-base DCO
workflow reads PR metadata, never PR executable code, and checks base/head/count
before/after download and before publishing its status. Retarget edits rerun
the gate and reset `DCO / commits` to pending. Protected main requires this
trusted status; the former PR-checkout CI DCO job has been retired.

By contributing, you agree that your contribution is licensed under the MIT
License included in this repository.
