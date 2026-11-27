# CI/CD Rules (PART 28)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never add unpinned third-party actions, inline tool installation, or Dependabot.
- Never claim CI success without checking the provider's actual run after a push.

## CRITICAL - ALWAYS DO

- Keep all required provider pipelines aligned and run the required security scans.
- Use the Go rolling image directly without a custom build toolchain image.

## Key rules

- Include Jenkins and provider governance, workflow validation, releases, and vulnerability gates.

For complete details, see AI.md PART 28.
