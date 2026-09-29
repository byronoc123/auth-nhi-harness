# Legal Position — auth-nhi

Read with [NOTICE](../NOTICE). This document states how we handle the legal risk
identified in the launch review (`docs/business/LAUNCH-REVIEW.md`).

## 1. What the harness supports (safe by construction)

- **First-party / owned systems**: your own services, your internal SSO,
  infrastructure you operate or are contractually authorized to automate.
- **Standards-based flows**: OAuth 2.1, OIDC step-up (RFC 9470), PAR (RFC 9126),
  RAR (RFC 9396), Token Exchange (RFC 8693).
- **Human-in-the-loop step-up**: the agent pauses; a human verifies out-of-band;
  the action completes with attestation. This is *strengthening* authentication,
  not circumventing it.

## 2. What is gated (enabled only by explicit, auditable configuration)

- **Legacy session replay** (`AUTH_NHI_LEGACY_REPLAY=1`): injecting stored
  session material for systems lacking modern auth. Permitted **only** for
  first-party systems where the operator's contract authorizes automation
  (e.g., your own SaaS product's staging environment).
- Enterprise tier adds per-tenant enablement, legal review workflow, and
  immutable audit of every gated operation.

## 3. What is prohibited (will not be built, contributions rejected)

- Interception of another person's authentication factors (SMS, email, push)
- Credential stuffing, CAPTCHA solving, bot-detection evasion
- Session capture against third-party systems without contractual authorization
- Any affordance framed or marketed as a "bypass"

## 4. Why this matters commercially

- Enterprise security review: this document + the NOTICE is the first artifact
  procurement reads. Cookie-replay-by-default is an automatic rejection.
- Distribution: OSS without clear lawful-use boundaries creates contributory
  liability risk for us and adoption risk for customers.
- The regulated path is also the defensible one: attestation of *authorized*
  automation is the product; unauthorized automation is somebody else's problem
  and we want no part of it.

## 5. Operator responsibilities

Operators are responsible for: allowlist accuracy, contractual authorization
for every target, lawful handling of any secrets they store in the vault, and
compliance with local law (CFAA 18 U.S.C. §1030; EU Directive 2013/40; ToS of
target systems).

This document is not legal advice. Before enterprise distribution of gated
capabilities, obtain counsel review per jurisdiction.