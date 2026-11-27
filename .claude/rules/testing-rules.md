# Testing Rules (PART 29, 30, 31)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never run Go tests or binaries on the host or write test output into the repository.
- Never treat green tests as proof that the application is complete.

## CRITICAL - ALWAYS DO

- Run toolchain tests in the prescribed container and validate integration behavior separately.
- Keep ReadTheDocs content, translations, accessibility, and UI behavior current.

## Key rules

- Cover the required behaviors, including server-page/API parity and content negotiation.

For complete details, see AI.md PART 29, 30, 31.
