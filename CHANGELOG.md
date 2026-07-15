# Changelog — Entangled--substrate

## [Unreleased] — 2026-07-14

### Fixed
- **`state_commitment` was a hardcoded constant, not a real commitment.** Every proof carried
  the identical value `[0x7c; 32]` regardless of the actual data being attested to. Replaced
  with a SHA3-256 hash over `lineage_id`, `block_height`, and a domain-separation tag, so the
  commitment is now cryptographically bound to the actual proof data.
- **No expiration mechanism.** Added a `valid_until` field (Unix timestamp), signed as part of
  the attestation message and checked in `verify()`. Proofs past `valid_until` are rejected
  with a new `SubstrateError::ProofExpired`. Breaking wire-format change (5309 → 5317 bytes).
- Removed stale `src/main.rs.bak`.
- Hardened `unix_now()` to fall back to zero instead of panicking on a clock-before-epoch edge case.

### Added
- `correctness_tests` module with four tests (valid roundtrip, tampered-signature rejection,
  tampered-message rejection, expired-proof rejection), complementing the existing 1000-case
  parser fuzz test.
- `sha3 = "0.10"` dependency.

### For reviewers
Prior to this change, `state_commitment` provided no actual security property — it was a fixed
value that never varied. This has been corrected and is covered by new correctness tests
exercising both the happy path and adversarial tampering cases. No revocation mechanism exists
yet; a proof remains valid for its full validity window regardless of later state changes.
