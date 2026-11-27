# Docker Rules (PART 27)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never copy or symlink host-built binaries into images.
- Never place runtime volumes or generated data in the repository.

## CRITICAL - ALWAYS DO

- Follow the multi-stage, static-binary, entrypoint, labels, healthcheck, and permissions rules.
- Provide the required development, test, and deployment compose configurations.

## Key rules

- Keep container ports, networks, volumes, and runtime defaults aligned with AI.md.

For complete details, see AI.md PART 27.
