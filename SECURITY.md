# Security Policy

## Supported versions
| Version | Supported |
|---|---|
| 0.1.x   | ✅        |

## Reporting a vulnerability
Email **security@auth-nhi.dev** (PGP key published at /.well-known/security.txt).
Do not open public issues for security reports. We acknowledge within 48h and
coordinate disclosure within 90 days.

## Design guarantees (what we will never do)
- The agent runtime never holds 2FA shared secrets unless the operator explicitly
  stores them in the local vault (opt-in, encrypted at rest, documented risk).
- Challenge responses are never logged; attestations record only method + signer + timestamp.
- Session material is encrypted with AES-256-GCM; keys never leave the operator's machine
  in the OSS tier.
- Every privileged action carries a ticket ID traceable to a human approval event.

## Known limitations (v0.1)
- Local vault key derived from machine key file (`~/.auth-nhi/.key`) — production
  deployments should integrate OS keychain / KMS (enterprise tier).
- Ticket store is a local JSON file; concurrency across multiple agents on one host
  is not yet safe.