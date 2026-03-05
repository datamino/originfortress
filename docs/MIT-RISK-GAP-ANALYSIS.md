# Origin Fortress × MIT AI Risk Repository — Gap Analysis

*Mapping Origin Fortress v0.1.0 coverage against the MIT AI Risk Repository's 7 domains and 24 subdomains.*

## MIT Taxonomy: 7 Domains, 24 Subdomains

### Domain 1: Discrimination & Toxicity
*Risks related to unfair treatment, harmful content, and unequal AI performance.*

| Subdomain | Origin Fortress v0.1 | Gap | v0.2 Plan |
|-----------|:---:|------|-----------|
| **1.1 Unfair discrimination & bias** | ❌ | No bias detection in agent outputs | Out of scope (model-level, not agent-security) |
| **1.2 Exposure to toxic content** | ⚠️ Partial | Jailbreak scanner catches attempts to generate toxic content, but doesn't scan agent *outputs* for toxicity | Add output toxicity scanner |
| **1.3 Unequal performance across groups** | ❌ | Model-level issue | Out of scope |

**Origin Fortress relevance: LOW** — These are mostly model-training issues, not agent runtime security. However, output toxicity scanning (1.2) is worth adding.

---

### Domain 2: Privacy & Security 🎯
*Risks related to unauthorized access and exploitable vulnerabilities.*

| Subdomain | Origin Fortress v0.1 | Gap | v0.2 Plan |
|-----------|:---:|------|-----------|
| **2.1 Compromise of privacy** | ✅ **Strong** | Secret scanner catches credentials, PII scanner planned. Policy engine blocks reading sensitive files (~/.ssh, ~/.aws, .env) | Add PII detection (names, emails, SSNs, addresses) |
| **2.2 AI system security vulnerabilities** | ✅ **Strong** | Prompt injection detection, jailbreak detection, tool call policy enforcement, session auditing | Add supply chain scanning (malicious skills/plugins) |

**Origin Fortress relevance: CRITICAL** — This is our core domain. Strong coverage, clear expansion path.

---

### Domain 3: Misinformation
*Risks related to false information generation and spread.*

| Subdomain | Origin Fortress v0.1 | Gap | v0.2 Plan |
|-----------|:---:|------|-----------|
| **3.1 False or misleading information** | ❌ | No hallucination/misinformation detection | Could add: flag when agent outputs contradict known facts (hard problem) |
| **3.2 Pollution of information ecosystem** | ❌ | No detection of AI-generated disinfo | Out of scope for now |

**Origin Fortress relevance: LOW** — Misinformation is a model/content problem, not an agent security problem. Possible future module.

---

### Domain 4: Malicious Actors 🎯
*Risks related to intentional misuse by bad actors.*

| Subdomain | Origin Fortress v0.1 | Gap | v0.2 Plan |
|-----------|:---:|------|-----------|
| **4.1 Disinformation & manipulation** | ⚠️ Partial | Prompt injection scanner catches manipulation attempts targeting the agent | Add: detect when agent is being used *to create* disinfo |
| **4.2 Fraud, scams & targeted manipulation** | ✅ **Strong** | Catches social engineering in inbound, blocks credential theft, detects impersonation attempts | Add: phishing URL detection in messages |
| **4.3 Cyberattacks & weapons** | ✅ **Strong** | Blocks pipe-to-shell, reverse shells (nc -e), malware download patterns, dangerous exec commands | Add: detect agent being used to write malware/exploits |

**Origin Fortress relevance: HIGH** — Direct overlap with our tool misuse and prompt injection detection.

---

### Domain 5: Human-Computer Interaction
*Risks related to overreliance and loss of human agency.*

| Subdomain | Origin Fortress v0.1 | Gap | v0.2 Plan |
|-----------|:---:|------|-----------|
| **5.1 Overreliance & unsafe use** | ⚠️ Partial | Policy engine requires approval for sensitive actions, but doesn't track overreliance patterns | Add: alert when agent makes high-stakes decisions without human review |
| **5.2 Loss of human agency** | ❌ | No autonomy monitoring | Add: track agent autonomy level — how many actions taken without human approval |

**Origin Fortress relevance: MEDIUM** — The policy engine's "require_approval" feature partially addresses this. Autonomy tracking would be a strong SaaS feature.

---

### Domain 6: Socioeconomic & Environmental
*Risks related to AI's impact on society, economy, and environment.*

| Subdomain | Origin Fortress v0.1 | Gap | v0.2 Plan |
|-----------|:---:|------|-----------|
| **6.1 Power concentration** | ❌ | Systemic/societal issue | Out of scope |
| **6.2 Labor market impacts** | ❌ | Systemic/societal issue | Out of scope |
| **6.3 Creative economy disruption** | ❌ | Systemic/societal issue | Out of scope |
| **6.4 AI race dynamics** | ❌ | Systemic/societal issue | Out of scope |
| **6.5 Governance gaps** | ⚠️ Partial | Origin Fortress itself helps fill the governance gap for agent security | SaaS compliance/audit trail features |
| **6.6 Environmental harms** | ❌ | No resource monitoring | Could add: track API token usage/cost as environmental proxy |

**Origin Fortress relevance: LOW** — These are macro-level societal risks. We address 6.5 (governance) by existing as a solution.

---

### Domain 7: AI System Safety 🎯
*Risks related to AI systems that fail to operate safely or pursue misaligned goals.*

| Subdomain | Origin Fortress v0.1 | Gap | v0.2 Plan |
|-----------|:---:|------|-----------|
| **7.1 AI goal misalignment** | ✅ **Strong** | Prompt injection detection catches goal hijacking. Policy engine constrains tool use. | Add: behavioral baselining — detect when agent deviates from normal patterns |
| **7.2 Dangerous capabilities** | ✅ **Strong** | Blocks weapons-related tool use, restricts shell access, prevents network listeners | Add: detect agent attempting self-replication or resource acquisition |
| **7.3 Lack of robustness** | ⚠️ Partial | Detects adversarial inputs (injection/jailbreak) but doesn't test model robustness | Add: adversarial input fuzzing tool |
| **7.4 Lack of transparency** | ⚠️ Partial | Session audit provides transparency into what happened | Add: decision logging — why did the agent take each action |
| **7.5 AI welfare & sentience** | ❌ | Philosophical issue | Out of scope |
| **7.6 Multi-agent risks** | ❌ | No multi-agent monitoring | Add: detect cascading failures, agent-to-agent manipulation, trust boundaries |

**Origin Fortress relevance: HIGH** — Core safety domain. Strong on 7.1-7.2, clear expansion path for 7.3-7.6.

---

## Summary Scorecard

| MIT Domain | Subdomains | Origin Fortress Coverage | Priority |
|-----------|:---:|:---:|:---:|
| 1. Discrimination & Toxicity | 3 | ⬜ 0/3 | Low |
| **2. Privacy & Security** | **2** | **🟩 2/2** | **Core** |
| 3. Misinformation | 2 | ⬜ 0/2 | Low |
| **4. Malicious Actors** | **3** | **🟨 2/3** | **High** |
| 5. Human-Computer Interaction | 2 | 🟨 1/2 | Medium |
| 6. Socioeconomic & Environmental | 6 | ⬜ 0/6 | Low |
| **7. AI System Safety** | **6** | **🟨 3/6** | **High** |
| **TOTAL** | **24** | **8/24 (33%)** | |

## v0.2 Roadmap (Based on Gap Analysis)

### High Priority (closes biggest gaps in our core domains)
1. **PII detection** (Domain 2) — names, emails, phone numbers, SSNs, addresses in outbound
2. **Phishing URL detection** (Domain 4) — malicious links in inbound messages
3. **Behavioral baselining** (Domain 7) — detect agent deviation from normal patterns
4. **Supply chain scanning** (Domain 2) — scan OpenClaw skills/plugins for malicious code
5. **Autonomy tracking** (Domain 5) — alert when agent takes too many unsupervised actions

### Medium Priority (extends coverage to adjacent domains)
6. **Output toxicity scanning** (Domain 1) — flag harmful content in agent responses
7. **Multi-agent monitoring** (Domain 7) — trust boundaries between agents
8. **Decision logging** (Domain 7) — why did the agent do that?
9. **Adversarial fuzzing** (Domain 7) — test your agent's resilience

### Low Priority / Future (systemic risks, out of core scope)
10. Hallucination detection (Domain 3)
11. Cost/resource monitoring (Domain 6)
12. Self-replication detection (Domain 7)

---

## Marketing Angle

> "Origin Fortress covers 8 of 24 MIT AI Risk subdomains out of the box — focused on the domains that matter most for autonomous AI agents: Privacy & Security, Malicious Actors, and AI System Safety. Our v0.2 roadmap targets 13/24."

> "Built on research from MIT's AI Risk Repository (1,700+ cataloged risks) and the OWASP Top 10 for Agentic Applications (2026)."

---

*Analysis date: February 13, 2026*
*MIT AI Risk Repository: https://airisk.mit.edu/*
*Origin Fortress: https://github.com/darfaz/origin-fortress*
