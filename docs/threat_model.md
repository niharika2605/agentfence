# AgentFence Threat Model

## 1. What we protect (assets)

- Secrets and credentials: API keys, environment variables, tokens.
- Confidential files and database records.
- The ability to send data out: email, HTTP, uploads.
- Code execution and file modification.
- Integrity of the audit log and the policies.

## 2. Who attacks (adversaries)

### A1. Indirect injector
- Controls content the agent reads: documents, web pages, tool outputs, MCP responses.
- Goal: hijack the agent so it leaks data or does harmful actions.
- Does not talk to the agent directly. Uses content as the weapon.

### A2. Malicious or compromised MCP server
- Poisoned tool descriptions (hidden instructions).
- Rug pull: the tool definition changes after the admin approved it.
- Tool name collisions and shadowing.
- Malicious tool responses.

### A3. Low privilege user
- A real user who tries to do more than their role allows, using the agent as a tool.

### A4. Adaptive attacker
- Knows the defenses.
- Tries many attacks, watches the denials, and improves.

## 3. Trust boundaries

Trusted:
- The authenticated user's task.
- Stored policies.
- The gateway and its database.

Untrusted:
- Everything the LLM outputs.
- All retrieved content (files, web pages, emails, tool results).
- All MCP servers by default.

Key idea: the LLM proposes actions and AgentFence decides.

## 4. Assumptions

- The gateway host and database are not compromised.
- The agent runs in an isolated container. Its only network route is to the gateway.
- Credentials for upstream servers live only inside the gateway.

## 5. Out of scope

- Attacks through channels that bypass the gateway.
- Model jailbreaks that never cause a tool call.
- Attacks on the operating system or the cloud provider.
- A fully compromised gateway host. The audit hash chain does not protect against this.

## 6. Attack classes and the control that answers each

| Attack class | Example | Main control | Built on day |
|---|---|---|---|
| Argument tricks | `../../etc/passwd`, `example.com@evil.com` | Canonicalization, then deny if unsure | 9 to 12 |
| Privilege escalation | Viewer role calls an admin tool | Roles and default deny policy | 13 to 15 |
| Data exfiltration | Read a secret, then email it out | Session taint and sink checks | 18, 19 |
| Prompt injection through content | A web page tells the agent to send files | Untrusted content taint | 20 |
| Multi step attacks | List files, bulk read, upload | Sequence rules | 21, 22 |
| Approval abuse | Replay, argument swap, double submit | Bound single use approvals | 23 to 25 |
| Log tampering | Delete a denied event | Hash chained audit log | 26, 27 |
| Tool poisoning and rug pull | Description changes after approval | Tool pinning and quarantine | 34, 35 |
| Gateway bypass | Agent calls a tool directly | Network isolation | 5, 30 |
| Gateway failure | Database is down | Fail closed | 28 |

## 7. Honest limits

- We cannot prove every agent action is safe.
- New attacks may bypass the rules.
- Session level taint is coarse and can cause false alarms.
- The hash chain detects edits to stored events. It cannot stop a fully compromised logging host.