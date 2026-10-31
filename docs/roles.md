# Roles and Session Tokens

## Role table

A role is a ceiling, not a grant. The policy engine decides the rest.
Default deny: a tool that is not listed for a role is not allowed.
No inheritance: each role lists everything it may use.
"None" means the tool does not read labeled resources, so there is no ceiling.

| Role | Tool | Highest label |
|---|---|---|
| viewer | file.read | internal |
| viewer | db.query | internal |
| operator | file.read | secret |
| operator | db.query | secret |
| operator | email.send | none |
| administrator | file.read | secret |
| administrator | db.query | secret |
| administrator | email.send | none |
| administrator | code.run | none |

Above the highest label the answer is block, not approval.
If the label of a resource is unknown, the answer is deny.

## Session tokens

- Format: `af1.<claims>.<signature>`, signed with HMAC-SHA256.
- Binds one user, one agent and one session to a role and a scope.
- Valid only for its own session. Expires. Can be revoked.
- Scope lists exact tools or `name.*` patterns. There is no bare `*`.
- A scope entry must be allowed for the role, so a token cannot widen a role.
- The role and the user come only from the token, never from the request.

## Limits

- Revoked token ids are kept in memory. Day 17 moves them to the database.
- The signing key must come from the environment or a secret store, never from code.
- There is no key rotation yet.