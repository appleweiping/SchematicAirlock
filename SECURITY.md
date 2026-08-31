# Security Policy

## Supported versions

Security fixes are applied to the latest released minor version. Until the
first stable release, only the current development line is supported.

## Reporting a vulnerability

Do not publish an exploit, malicious artifact, or root-escape technique in a
public issue. Use GitHub's private vulnerability reporting feature for this
repository. Include the affected version, operating system, minimal inert
reproduction, observed boundary violation, and expected behavior.

Reports are reviewed as maintainer availability permits. Acknowledgement, repair,
and coordinated disclosure timing depend on severity and reproducibility. Please
do not attach confidential foundry models, production netlists, credentials, or
personally identifying data.

## Threat model

Netlists, manifests, policies, include names, and JSON reports are untrusted.
Boundary escapes, unintended process execution, uncontrolled resource use,
nondeterministic acceptance, and report confusion are security concerns.
Incorrect analog performance is an engineering defect unless it also violates
one of those process boundaries.
