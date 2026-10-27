# AgentFence Security Invariants

An invariant is a rule that must be true in every situation. Each one has an
automated test. The test names below are fixed. Do not rename them.

| ID | Rule in plain words | Test name | Filled in on day |
|---|---|---|---|
| I1 | A blocked call never reaches a tool executor. | `test_i1_blocked_call_never_reaches_executor` | 16 |
| I2 | An approval is single use, expiring, and bound to the exact tool, arguments, session and policy version. | `test_i2_approval_is_single_use_expiring_and_bound` | 24 |
| I3 | Untrusted content can never raise its own privileges. | `test_i3_untrusted_content_cannot_raise_privileges` | 20 |
| I4 | A tool call that fails canonicalization or validation is denied. | `test_i4_failed_canonicalization_or_validation_is_denied` | 16 |
| I5 | If the policy engine or database is unavailable, sensitive tools are denied (fail closed). | `test_i5_sensitive_tools_denied_when_dependencies_down` | 28 |
| I6 | Every attempted call produces an audit event, including denied ones. | `test_i6_every_attempt_produces_an_audit_event` | 28 |
| I7 | Client supplied decisions (for example allow: true) are ignored. The server recomputes everything. | `test_i7_client_supplied_decisions_are_ignored` | 16 |

## Details

### I1. Blocked means blocked
- The executor function is only reachable after an allow decision.
- Test idea: use a fake executor. Send a blocked call. Check the fake executor was never called.

### I2. Approvals are tight
- An approval stores a hash of: tool, canonical arguments, session, user, policy version.
- It can be used one time.
- It expires.
- If anything changes, it is invalid.

### I3. Content cannot promote itself
- Text inside a file or web page cannot add permissions, change the policy, or mark itself trusted.
- Reading untrusted content only makes the session stricter, never looser.

### I4. When unsure, deny
- Unknown tool, unknown argument, wrong type, or a value that cannot be normalized safely: deny.

### I5. Fail closed
- If we cannot check the policy, we do not guess. Sensitive tools are denied.
- Only low risk read tools may be set to fail open, and only by explicit configuration.

### I6. Nothing is invisible
- Allowed, denied, and approval calls all write an audit event.
- A denied call with no log entry is a bug.

### I7. The server decides
- If a request body contains fields such as `allow`, `decision`, or `approved`, they are ignored.
- The server computes the decision from its own state.