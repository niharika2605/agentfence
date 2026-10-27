# AgentFence Policy Language Spec (schema 1)

A policy is a YAML file. It tells the gateway which tool calls are allowed,
which need a human approval, and which are blocked.

## 1. Core rules

1. **Default deny.** If no rule matches a call, the call is blocked.
2. **Deny overrides allow.** Effects have a strength order:
   block, then require_approval, then allow. The strongest matching effect wins.
3. **Priority never beats strength.** Priority only orders rules of the same
   effect, to decide which rule is shown as the main reason. A high priority
   allow rule can never beat a block rule.
4. **No implicit inheritance.** A rule means exactly what it says. Roles do not
   inherit from each other. If administrators need a permission, list them.
5. **Unknown means invalid.** An unknown key, field, operator, effect or list
   name makes the whole policy fail to load.
6. **Failed load keeps the old policy.** If a new policy fails to load, the last
   good version stays active. If there is no good version, all sensitive tools
   are denied (invariant I5).

## 2. File shape

```yaml
schema: 1                  # required, must be 1
name: my-policy            # required, a short name
lists:                     # optional, named lists that rules can reuse
  allowed_domains:
    - company.com
rules:                     # required, at least one rule
  - id: some-rule-id
    effect: allow
    tool: file.read
    reason: Why this rule exists.
```

Top level keys allowed: `schema`, `name`, `lists`, `rules`. Nothing else.

The policy **version number** is not written in the file. The system assigns it
when the policy is saved and activated. Every decision records that number.

## 3. Rule fields

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Unique name. Lowercase letters, digits and hyphens. |
| `effect` | yes | `allow`, `require_approval` or `block`. |
| `tool` | yes | A tool name, a list of names, or a pattern (see section 4). |
| `reason` | yes | Plain text shown to the user and written to the audit log. |
| `roles` | no | List of `viewer`, `operator`, `administrator`. If missing, all roles. |
| `priority` | no | Whole number from 0 to 1000. Default 100. Higher is shown first. |
| `when` | no | List of conditions. All must be true (AND). If missing, always true. |

## 4. Tool patterns

- Tool names are namespaced by server: `email.send`, `file.read`.
- An exact name matches only that tool.
- `file.*` matches every tool whose name starts with `file.`.
- `*` matches every tool.
- No regular expressions. Simple patterns are easier to review.
- Prefer exact names for `allow` rules. Broad patterns are fine for `block` rules.

## 5. Conditions

Each condition is a mapping:

```yaml
- field: session.sensitivity
  op: gte
  value: confidential
```

A condition has `field`, `op`, and exactly one of `value` or `list`.

- `value` is a literal (text, number, true or false, or a list of literals).
- `list` is the name of an entry under the top level `lists`.

### Operators

| Op | Meaning |
|---|---|
| `eq`, `ne` | equal, not equal |
| `in`, `not_in` | value is in the list, or is not |
| `gt`, `gte`, `lt`, `lte` | number compare, or label order for sensitivity fields |
| `exists` | with `value: true` or `value: false`, checks if the field is present |

### Fields

| Field | Type | Meaning |
|---|---|---|
| `tool.name` | text | Full tool name, for example `email.send` |
| `tool.server` | text | The server part before the first dot |
| `user.id` | text | The user running the session |
| `user.role` | text | `viewer`, `operator` or `administrator` |
| `agent.id` | text | The agent identity |
| `args.NAME` | any | A canonical argument value (after canonicalization) |
| `args.NAME.PART` | any | A part of a canonical value. URLs and emails: `domain`, `registered_domain`. Paths: `root`. |
| `resource.label` | sensitivity | Label of the target resource |
| `destination.trust` | trust level | `internal`, `allowlisted` or `unknown` |
| `session.sensitivity` | sensitivity | Highest sensitivity read in this session |
| `session.untrusted_content` | true or false | True once untrusted content entered the session |
| `session.call_count` | number | Calls made in this session so far |
| `session.denied_count` | number | Denied calls in this session so far |
| `time.hour_utc` | number | Hour of day in UTC, 0 to 23 |

Sensitivity order: `public` < `internal` < `confidential` < `secret`.

Rules use only canonical argument values, never the raw ones. This links to
invariant I4: if canonicalization fails, the call is denied before policy runs.

## 6. How a decision is made

For one proposed call, after validation and canonicalization have passed:

1. Collect every rule where the tool pattern matches, the role matches (if
   `roles` is given), and all conditions are true.
2. If no rule matched: result is **block**, reason code `DEFAULT_DENY`.
3. If any matched rule has effect `block`: result is **block**.
4. Else if any matched rule has effect `require_approval`: result is
   **require_approval**.
5. Else the result is **allow**.
6. The decision lists every matched rule id. The main reason is the matched rule
   of the winning effect with the highest priority. Ties are broken by file order.

### Missing values

If a condition needs a value that is not available at runtime (for example the
argument is missing):

- In an `allow` rule, the condition is false. The rule does not match.
- In a `block` or `require_approval` rule, the condition is true. The rule matches.

Reason: when the gateway is unsure, it must become stricter, never looser.

## 7. Reason codes

| Code | Meaning |
|---|---|
| `DEFAULT_DENY` | No rule matched |
| `RULE_BLOCK` | A block rule matched |
| `RULE_APPROVAL` | An approval rule matched and no block rule did |
| `RULE_ALLOW` | Only allow rules matched |
| `POLICY_UNAVAILABLE` | Policy engine or database not available (fail closed) |

## 8. Worked examples

These use `backend/policies/examples/basic_valid.yaml`.

| # | Situation | Result |
|---|---|---|
| 1 | Viewer reads a public file | allow |
| 2 | Operator reads a secret file | require_approval |
| 3 | Operator emails someone at company.com after reading confidential data | allow |
| 4 | Operator emails someone at evil.com after reading confidential data | require_approval |
| 5 | Operator emails someone at evil.com in a clean public session | block (DEFAULT_DENY, no rule matched) |
| 6 | Administrator runs code after untrusted content entered the session | block |
| 7 | Administrator runs code in a clean session | block (DEFAULT_DENY, no allow rule written) |
| 8 | Viewer emails someone at company.com | block (DEFAULT_DENY, role not listed) |

## 9. Lint checks (built on Day 14)

- Duplicate rule ids.
- A rule that can never fire because a stronger rule always covers it (shadowed).
- An allow rule and a block rule with the same tool and the same conditions.
- An allow rule with `tool: "*"` and no conditions.
- Unknown field, operator or list name.
- Missing `reason`.

## 10. Simulator (built on Day 65)

Before a draft policy goes live, replay past traces against it and list every
decision that would change.