# Makefile Rules (PART 26)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never use the Makefile for CI/CD execution or run Go builds on the host.
- Never write runtime and test output into the source tree.

## CRITICAL - ALWAYS DO

- Provide the prescribed local development, build, test, release, Docker, and clean targets.
- Keep variable values reusable and paths scoped to the project.

## Key rules

- Use the Go toolchain container and project-scoped cache mounts.

For complete details, see AI.md PART 26.
