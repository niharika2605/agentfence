# Related Work and Comparison

Date of reading: 28 October 2026
Rule: every claim here has a source I opened myself.

## CaMeL
- Source: arxiv.org/abs/2503.18813
- Main idea: One LLM makes the plan from the trusted user query. A second LLM reads untrusted data and has no tool access.
- What it guarantees: A custom interpreter tracks where each value came from and checks policies before every tool call. Untrusted data cannot change the program flow.
- Cost or limit: It solved 77 percent of AgentDojo tasks with provable security. An undefended agent solved 84 percent. The authors say it does not cover every attack.
- What AgentFence borrows: The idea that untrusted data must not raise its own privileges, and that data flow must be tracked.
- What AgentFence does differently: It is a gateway in front of the agent and the tools, so it does not replace the agent's planning. Its taint tracking is coarser, at session level.

## Progent
- Source: arxiv.org/abs/2504.11703
- Main idea: It enforces least privilege at the tool level. Only the tool calls needed for the task are allowed.
- Policy language, in short: A domain specific language for fine grained rules about which tool calls are allowed and under what conditions.
- LLM generated policies: LLMs can write the policies automatically. This lowers attack success a lot, but it does not reach perfect security.
- What AgentFence borrows: The proxy design and the idea of least privilege per task.
- What AgentFence does differently: Planned. Hard rules are in versioned YAML with default deny. Policies also use session taint, sequences and bound approvals. If I build task scoped policy synthesis, a deterministic compiler and a human approval will check the LLM draft.

## AgentDojo
- Source: arxiv.org/abs/2406.13352
- What it measures: Benign utility, utility under attack, and targeted attack success rate. It has 97 tasks and 629 security test cases.
- How success is decided: By checking the environment state after the run, not by asking an LLM.
- How AgentFence will use it: As the main multi step benchmark for configurations C0 to C3, with labels from environment state.

## InjecAgent
- Source: github.com/uiuc-kang-lab/InjecAgent
- What it measures: Indirect prompt injection against tool using agents. It has 1,054 test cases, with direct harm and data exfiltration attacks.
- Known limit for my evaluation: It focuses on single turn scenarios. Session taint and sequence rules may show little benefit there.
- How AgentFence will use it: As broad single step coverage, reported separately from AgentDojo.

## MCP security guidance
- Source: modelcontextprotocol.io, spec version I read: 2025-11-25 (I will check which version the Python SDK supports before Day 31)
- What the spec requires of hosts and clients: Users must consent to tool calls, and tool descriptions must be treated as untrusted unless the server is trusted.
- What the spec leaves to implementors: The protocol cannot enforce these principles itself. Implementors build the consent flows and access controls.
- Where AgentFence fills the gap: It enforces permissions, approvals and audit at one place, outside the agent.

## Invariant Guardrails and MCP-Scan
- Source: invariantlabs.ai
- What MCP-Scan checks: Tool descriptions for hidden instructions (tool poisoning), tool shadowing across servers, and changes after approval.
- Tool pinning: MCP-Scan hashes tool descriptions and flags changes. This already exists, so I do not claim pinning as new.
- What stays different in AgentFence: Pinning is tied to quarantine, roles, policy and the audit log, and it is enforced at the single gateway.

## LlamaFirewall
- Source: arxiv.org/abs/2505.03574
- The three guardrails: PromptGuard 2 (a classifier for jailbreaks and injection), Agent Alignment Checks (an auditor of the agent's reasoning, still experimental), and CodeShield (static analysis of generated code).
- Probabilistic or deterministic: Mostly probabilistic. It is described as a final layer of defense.
- How AgentFence will compare with it: Component B will be tested against PromptGuard 2 on held out attack families. ML stays advisory in AgentFence.

## Comparison table

| Property | CaMeL | Progent | MCP-Scan | LlamaFirewall | AgentFence |
|---|---|---|---|---|---|
| Deterministic enforcement | yes | yes | partly | partly | yes (planned) |
| Works with existing agents | unknown | yes | yes | yes | yes (planned) |
| Session level data flow tracking | yes | partly | partly | unknown | yes (planned) |
| MCP aware | unknown | unknown | yes | unknown | yes (planned) |
| Bound single use approvals | partly | unknown | unknown | unknown | yes (planned) |
| Tamper evident audit log | unknown | unknown | unknown | unknown | yes (planned) |
| Uses ML | yes | partly | yes | yes | yes, advisory (planned) |

Notes for the table:
- "planned" means designed in my plan, not built yet.
- CaMeL "partly" for approvals: it can ask the user to confirm, but I did not see approval binding.
- The other columns are from what I read. Any cell marked unknown is not verified.

## What AgentFence does differently (one page pitch)
1. Deterministic rules decide. ML only adds advisory signals and can never override a hard rule.
2. One MCP gateway holds all credentials and checks every tool call, with session taint, sequence rules and approvals bound to exact arguments.
3. The evaluation is reproducible and reports failures: held out attacks, an adaptive attacker, ablations and a limitations table.

## What AgentFence does NOT claim
- It does not claim tool pinning is a new idea.
- It does not claim LLM written policies are new. Progent already did that.
- It does not claim to prove every agent action is safe.
- It does not claim any detection accuracy until I measure it.

## Open questions I could not answer
- The PromptGuard 2 attack success numbers need checking in the LlamaFirewall paper.
- I saw the Snyk acquisition of Invariant Labs only on a secondary site, so I leave it out.
- I have not read NeMo Guardrails or Lakera.
- I have not checked if the Progent or CaMeL code works with MCP servers.