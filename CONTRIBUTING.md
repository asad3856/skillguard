# Contributing

Thanks for considering a contribution. SkillGuard stays small on purpose:
standard library only, offline, and defensive.

## Getting started

```bash
git clone https://github.com/asad3856/skillguard.git
cd skillguard
python -m unittest discover -s tests -v
```

## What makes a good contribution

- A new detector with: a rule ID, a focused pattern, a test fixture that
  triggers it, a fixture that must *not* trigger it, and a clear
  recommendation for the skill author.
- Fewer false positives on real-world skills (bring the example, redacted).
- Documentation and beginner-friendly error messages.

## What this project will not accept

- Code that executes, downloads, or exfiltrates anything.
- Offensive-security tooling, exploit code, or bypass techniques.
- New third-party dependencies without a strong justification.

## Pull requests

1. Keep the change focused; one detector or one fix per PR.
2. Add or update tests. `python -m unittest discover -s tests` must pass.
3. Update the rules table in `README.md` if you add or change a rule.
4. Do not include real secrets in fixtures or examples.

## Code style

Readable over clever. Short functions, explicit names, no clever regex
without a comment or a test showing what it matches.
