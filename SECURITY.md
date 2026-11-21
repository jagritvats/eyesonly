# Security policy

**Eyes Only is unaudited alpha software.** Don't make it the only thing protecting
production secrets yet. [THREAT_MODEL.md](THREAT_MODEL.md) lists what it defends against,
the test for each defense, and the known limitations.

## Reporting a vulnerability

Please report privately with GitHub's **[Report a vulnerability](../../security/advisories/new)**
button (Security tab → Advisories). Don't open a public issue for security bugs.

A useful report includes the component (client filter, proxy, pre-receive hook, crypto
envelope, mirror, signed policy), the version or commit, steps to reproduce (ideally a script
in the style of `test/*.sh`), and the impact.

What to expect:
- An acknowledgement within **72 hours**, and triage within **7 days**.
- A fix developed in a private advisory. Every fix lands with an adversarial test that fails
  before the fix.
- Coordinated disclosure within **90 days**, faster for critical issues, with credit in the
  advisory unless you'd rather stay anonymous.
- There's no bug bounty yet.

If a vulnerability is already public, report it anyway. We'll skip the embargo and ship a
fix and an advisory as quickly as we can.

## Scope

In scope: anything that lets someone read, write or learn of a protected file or private ref
that the policy says they shouldn't, bypass the pre-receive hook or proxy, forge or replay
envelopes, defeat the signed policy, or make the mirror push something it shouldn't.

Known limitations already documented in THREAT_MODEL.md (for example, metadata visible on
shared branches, or revocation not being retroactive) are out of scope. If you think one is
worse than we describe, we still want to hear it.

## Supported versions

During the alpha, only the latest release gets fixes.
