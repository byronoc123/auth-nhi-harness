# Contributing

Thanks for helping build the identity layer for agentic processes.

## Setup

```bash
npm install
npm run build
npm test
```

## Rules

1. **No secret material in code, tests, logs, or fixtures.** Test TOTP secrets
   must be RFC-realistic fixtures (`JBSWY3DPEHPK3PXP`), never real seeds.
2. **No "bypass" affordances.** PRs that add credential-stuffing, SMS
   interception, CAPTCHA solving, or default-on session replay will be rejected.
   The lawful-use NOTICE is enforced by review.
3. Every privileged action must remain ticketed + attested. If your change
   touches the state machine, update `docs/PROTOCOL.md` and add tests.
4. Node >= 20, TypeScript strict, no `any`.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`). One logical change
per PR. CI must pass (build + tests) before merge.

## Security

See [SECURITY.md](./SECURITY.md). Do not open public issues for vulnerabilities.