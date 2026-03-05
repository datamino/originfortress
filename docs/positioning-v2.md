# Origin Fortress v2 Positioning — "Run AI Agents on Your Laptop Without Fear"

## The Shift

**Before:** "Security scanner for AI agents" (feature)
**After:** "The trust layer between AI agents and your machine" (category)

## New Tagline Options

1. **"Run AI agents on your laptop. We watch your back."**
2. **"Your machine. Your agent. Your rules."**
3. **"The security moat between AI and your laptop."**
4. **"Self-host AI agents fearlessly."**

Recommended: **"Your machine. Your agent. Your rules."**

## Target Audience (Revised)

### Primary: Self-Hosting AI Agent Users
- People running OpenClaw, Claude Code, Cursor, Aider, etc. on their actual machines
- Want the power of local agents but scared of giving AI shell/file access
- Technical enough to install npm packages, not security experts
- **Pain point:** "I want to run this on my laptop but what if it reads my SSH keys?"

### Secondary: Agent Framework Developers
- Building with LangChain, CrewAI, AutoGen, OpenAI Agents SDK
- Need to ship security to their users without building it themselves
- Want to say "secured by Origin Fortress" as a trust signal

### Tertiary: Enterprise AI Teams
- Deploying agents internally on employee machines
- Need compliance, audit trails, policy enforcement
- Can't have agents accessing arbitrary credentials

## Value Proposition

```
Without Origin Fortress:
  AI Agent → Full access to everything → 😱

With Origin Fortress:
  AI Agent → Origin Fortress Guardian → Only what's allowed → 😌
  + Full audit trail of everything attempted
  + Forbidden zones auto-protect your credentials
  + Permission tiers you can dial up as trust grows
```

## New Pricing

### Free (Open Source)
- Host Guardian with all 4 permission tiers
- 20+ forbidden zone patterns
- Dangerous command blocking
- Audit trail (in-memory)
- All scanners (prompt injection, secrets, PII, etc.)
- Community support via GitHub
- **Everything you need to secure one machine**

### Pro — $14.99/mo or $149/yr
- Everything in Free
- **Threat intelligence feed** — new attack patterns pushed weekly
- **Persistent audit logs** — queryable, exportable, tamper-evident
- **Custom forbidden zones** — YAML-based, shareable configs
- **Real-time alerts** — Telegram, Slack, Discord, email notifications on violations
- **Dashboard** — web UI showing blocked attacks, audit trail, security score
- **Priority pattern updates** — when new agent exploits emerge, Pro gets patches first
- Email support

### Team — $49/mo or $499/yr (up to 10 machines)
- Everything in Pro
- **Centralized policy management** — one config, all machines
- **Fleet dashboard** — see all your agents/machines in one view
- **Shared threat intelligence** — attacks on any machine update all
- **Role-based policies** — different tiers for different team members
- **Compliance reports** — SOC2-style audit exports
- **Slack/Teams integration** — security alerts in your team channels
- Priority support

### Enterprise — Custom
- Everything in Team, unlimited machines
- **On-prem threat intelligence server**
- **Custom scanner development** — we build patterns for your stack
- **SLA** — guaranteed response times
- **SSO/SAML** — enterprise auth
- Dedicated support engineer

## Why This Pricing Works

1. **Free is genuinely useful** — not crippled. This drives adoption
2. **Pro sells peace of mind** — "I run an agent on my laptop, I need alerts when something weird happens"
3. **Team sells visibility** — "I have 5 engineers running agents, I need to see what they're doing"
4. **Enterprise sells compliance** — "Our security team needs audit trails and SLA"

## Competitive Landscape

| | Origin Fortress | Rebuff.ai | LLM Guard | Prompt Armor |
|---|---|---|---|---|
| Host/laptop protection | ✅ | ❌ | ❌ | ❌ |
| Permission tiers | ✅ | ❌ | ❌ | ❌ |
| Filesystem boundaries | ✅ | ❌ | ❌ | ❌ |
| Command blocking | ✅ | ❌ | ❌ | ❌ |
| Audit trail | ✅ | ❌ | Partial | ❌ |
| Prompt injection | ✅ | ✅ | ✅ | ✅ |
| Zero dependencies | ✅ | ❌ | ❌ | ❌ |
| Open source | ✅ | Partial | ✅ | ❌ |
| Framework agnostic | ✅ | ✅ | ✅ | ❌ |

**We're the only one protecting the HOST, not just the prompts.**

## Content Strategy

### Launch Blog Post
"We Run an AI Agent on Our Founder's Laptop — Here's How We Secured It"
- Real story of dogfooding Origin Fortress
- Show actual attack attempts and blocks
- "Try to break it" challenge

### Ongoing Content
- Weekly "Attack of the Week" — real patterns we caught
- "What Could Go Wrong" series — agent horror stories + how Origin Fortress prevents them
- Integration guides for every major framework
- "Security Score" badges for repos

### PR Angle
- "Come hack our agent" bounty program
- First open-source laptop security layer for AI agents
- OWASP Agentic AI alignment

## Go-to-Market

1. **Week 1:** Publish v0.4.0, blog post, update website
2. **Week 2:** Integration guides (OpenClaw, LangChain, CrewAI)
3. **Week 3:** "Come hack our agent" challenge launch
4. **Week 4:** HN Show HN, Reddit posts, Dev.to
5. **Month 2:** Pro tier launch with dashboard MVP
6. **Month 3:** Team tier with fleet management

## Stripe Updates Needed

Old prices → New prices:
- Pro: $9.99/mo → $14.99/mo (more value now)
- Pro Yearly: $99/yr → $149/yr
- Team: $49/mo → same
- Team Yearly: $499/yr → same

## Key Messages

**For individuals:**
"You wouldn't give a stranger the keys to your house. Why give an AI agent unrestricted access to your laptop?"

**For teams:**
"Your developers are running AI agents on their machines right now. Do you know what those agents can access?"

**For the market:**
"Prompt injection scanning is table stakes. Host protection is the real game."
