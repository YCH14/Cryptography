# Canonicalization and strict parsing

A signature or an authentication tag is only meaningful if the signer and the verifier compute it over exactly the same bytes. The project therefore has one serialization rule and one parsing rule, used everywhere.

Full detail: [D2](../D2-Symmetric-Encryption/docs/design_d2.md) (header), [D3](../D3-Hybrid-Encryption/docs/hybrid_design_d3.md) (container and AAD), [D5](../D5-Digital-Signatures/docs/signature_design_d5.md) (signature) and [D6](../D6-Key-Management/docs/key_management_d6.md) (keystore files).

## The rule

Everything that is authenticated is serialized as canonical JSON:

```python
json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
```

Sorted keys, no whitespace, ASCII only, no `NaN` or `Infinity`. The rule is inspired by RFC 8785 (JCS) but does not implement it completely (key order by code point, float formatting). That does not weaken the scheme, because the exact bytes that travel in the container are the ones authenticated; the project never signs a value and then sends a different serialization of it.

## What is authenticated with it

| Where | Bytes covered |
|---|---|
| D3 container (AES-GCM AAD) | `magic`, `version`, `algorithm`, `key_wrap_algorithm`, `timestamp`, `filename`, `metadata` and the full `recipients` list. `filename` and `metadata` are always present (`null` or `{}` when unused), so removing them changes the AAD |
| D3 key wrap (AAD of the wrap) | A domain label, the ephemeral public key and the recipient public key |
| D5 signature | SHA-256 of the canonical JSON of the whole container except the `signature` field, including `signer_id`, `container_id`, `document_id` and `document_version` |
| D6 keystore | The format name, `metadata`, `kdf_parameters` and the salt are the AAD of the key encryption, so editing any file of the keystore breaks the unlock |

## Strict parsing

Container bytes are treated as hostile until they are authenticated. The parser accepts a container only if:

- the JSON has no duplicate keys and no non-finite constants, and base64 fields are in canonical form;
- the field set is exactly the expected one (no unknown and no missing fields), with the exact types (`True` is not accepted as `1`);
- parameters have only the permitted values (AES-256-GCM, 256-bit key, 12-byte nonce, 16-byte tag);
- sizes are within limits (header and metadata 64 KiB, plaintext just under 2 GiB, key files 16 KiB, keystore JSON files 1 MiB);
- recipient ids do not look like a fingerprint, and fingerprints are unique.

Every failure while opening a container produces the same `DecryptionFailedError` without a chained cause, so an error message is never an oracle. This removes parser differential attacks (two parsers reading the same bytes differently) and algorithm downgrade attacks.

## Tests

`tests/test_symmetric.py` (`TestMetadataTampering`, `TestInputValidation`), `tests/hybrid/test_metadata.py` (`TestAadBinding`, `TestTamperingBreaksEveryRecipient`), `tests/hybrid/test_hybrid.py` (`test_container_schema_and_aad_structure_match_spec`) and `tests/signatures/test_signatures.py`.
