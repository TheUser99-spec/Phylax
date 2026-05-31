# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AgentGuard, please **do not** open a public issue.

Instead, report it privately:

1. **GitHub Security Advisory**: Use the [Security Advisory](https://github.com/TheUser99-spec/AgentGuard/security/advisories/new) page.
2. **Email**: If you prefer email, contact the maintainers directly.

We aim to respond within 48 hours and resolve critical issues within 7 days.

## Expectations

AgentGuard is a security tool, not a silver bullet. Please understand:

- **Phase 1** protects files while the daemon runs. See [Development Path](https://github.com/TheUser99-spec/AgentGuard#roadmap) for limitations.
- **Phase 2** (kernel minifilter) will provide deeper protection. The driver is under development.
- Always verify protections with `agentguard project verify`.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | No |

## Disclosure Policy

We follow a coordinated disclosure process:

1. Reporter submits vulnerability privately
2. Maintainers acknowledge within 48 hours
3. Fix is developed and tested
4. CVE is requested if applicable
5. Public disclosure after fix is released

We credit all reporters who follow responsible disclosure.
