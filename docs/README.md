# Security documentation

This folder is the entry point to the security documentation of the Secure Digital Document Vault (the *Secure File Exchange Platform*). Each document is a short summary of one topic and points to the deliverable that holds the full design and the tests.

| Document | Answers | Full detail |
|---|---|---|
| [`threat-model.md`](threat-model.md) | What do we protect, from whom, and under which assumptions? | [`D1`](../D1-Architecture-Threat-Model/secure-digital-document-vault-design.md) |
| [`cryptographic-design.md`](cryptographic-design.md) | Which primitives are used, how are they combined, and why? | [`D2`](../D2-Symmetric-Encryption/docs/design_d2.md), [`D3`](../D3-Hybrid-Encryption/docs/hybrid_design_d3.md), [`D5`](../D5-Digital-Signatures/docs/signature_design_d5.md), [`D6`](../D6-Key-Management/docs/key_management_d6.md) |
| [`canonicalization.md`](canonicalization.md) | Which bytes are authenticated and signed, and how is parsing kept strict? | D2, D3 and D5 designs |
| [`key-management.md`](key-management.md) | How are keys created, stored, shared, rotated, revoked and backed up? | [`D6`](../D6-Key-Management/docs/key_management_d6.md) |
| [`security-requirements.md`](security-requirements.md) | Where is each security requirement implemented and tested? | Source code and `tests/` |
| [`security-audit-findings.md`](security-audit-findings.md) | What did our own reviews find, and what was done about it? | Pull requests of the repository |

The final application is in [`D6-Key-Management/`](../D6-Key-Management/): it contains the code of D2, D3 and D5 as well, and a command line (`python -m vault`). The root [`README.md`](../README.md) explains how to install and run it.
