# Fixtures

| File | Source |
|------|--------|
| `c2pa-sample.png` | Synthetic 8×8 PNG with an embedded C2PA manifest store, signed with `c2pa` crate `EphemeralSigner` (`metadissect-fixture.local`). Generated for MetaDissect Phase 3 tests — not a real camera/vendor claim. Expect `ValidationState=valid` with `signingCredential.untrusted` (no trust anchors bundled). |
| Other samples | Optional local samples used by integration tests when present. |
