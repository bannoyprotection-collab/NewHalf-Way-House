# Security Specification (Phase 0 TDD) — ระบบสารสนเทศโครงการบ้านน้อยในนิคม

## 1. Data Invariants
1. **Default Deny Safety Net**: All paths not explicitly matched are denied for both `read` and `write`.
2. **Identity & Verification Gate**: Every read or write operation requires an authenticated user (`request.auth != null`) with a verified email (`request.auth.token.email_verified == true`), and ownership is bound strictly to `ownerId == request.auth.uid` (or verified system admin `masakinaada@gmail.com` / `/admins/$(request.auth.uid)`).
3. **Strict Key & Schema Validation**: Every document creation and update on `/nikhoms/{nikhomId}`, `/beneficiaries/{beneficiaryId}`, `/reports/{reportId}`, and `/drive_sync_configs/{configId}` is validated via dedicated `isValid[Entity](incoming())` helpers enforcing `keys().hasAll(...)`, `keys().hasOnly(...)`, string length bounds, numeric ranges, bounded array sizes, and server timestamp (`request.time`).
4. **Query Enforcer & PII Isolation**: `allow list` never uses blanket `isSignedIn()`. It strictly enforces `resource.data.ownerId == request.auth.uid || isAdmin()`, preventing cross-tenant scraping and isolating beneficiary PII to the authorized owner/admin.
5. **Immutable Identity**: During `update`, `incoming().ownerId == existing().ownerId` and `incoming().id == existing().id` are strictly enforced.

## 2. The "Dirty Dozen" Payloads (Designed to Fail with PERMISSION_DENIED)
1. **Unauthenticated Write**: `auth = null`, creating a document in `/beneficiaries/b-1`.
2. **Unverified Email Spoof**: `auth = { uid: 'u1', token: { email: 'masakinaada@gmail.com', email_verified: false } }`, attempting admin read/write.
3. **Identity Spoofing on Create**: Authenticated as `u1`, setting `ownerId: 'u2'` in `/nikhoms/nk-01`.
4. **Shadow Field Injection on Create**: Adding undeclared field `"isAdmin": true` to `/nikhoms/nk-01`.
5. **Shadow Field Injection on Update**: Updating `/nikhoms/nk-01` with an undeclared key `"hacked": 1`.
6. **Owner Hijack on Update**: Authenticated as `u1`, mutating `ownerId` from `'u1'` to `'u2'` on `/beneficiaries/b-1`.
7. **ID Poisoning Attack**: Document ID exceeding 128 characters or containing invalid characters (`../etc/passwd`).
8. **String Exhaustion (Denial of Wallet)**: Setting `fullName` to a 10,000-character string on `/beneficiaries/b-1`.
9. **Client Timestamp Forgery**: Providing a past or future timestamp instead of `request.time` for `updatedAt`.
10. **Cross-Tenant PII Read (`get`)**: Authenticated as `u2`, attempting `get` on `/beneficiaries/b-1` owned by `u1`.
11. **Unfiltered Collection Scraping (`list`)**: Authenticated as `u2`, running an unfiltered `list` query on `/beneficiaries` owned by `u1`.
12. **Out-of-Bounds Numeric Value**: Setting `capacity: -50` or `age: 999` on `/nikhoms/nk-01` or `/beneficiaries/b-1`.
