# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

If you find a way SkillGuard can be made to execute untrusted content, leak
data, follow a symlink outside the scanned tree, or otherwise behave
unsafely, please report it privately: open an issue titled
"SECURITY: <short summary>" **without** including exploit details, real
secrets, or live malicious URLs, and the maintainer will ask for details
through a private channel.

Do not post real credentials, tokens, or private keys in any issue,
pull request, or test fixture. Redact them first; a token-shaped example
such as `ghp_EXAMPLE` is enough to reproduce a detector.

## Design notes (for reviewers)

- SkillGuard never executes scanned files, never makes network requests,
  and has no third-party dependencies.
- It reads files as UTF-8 text with a 1 MB cap, skips binary/unreadable
  files, and does not follow symlinks.
- Findings are patterns, not verdicts. A clean scan is not proof of safety.
