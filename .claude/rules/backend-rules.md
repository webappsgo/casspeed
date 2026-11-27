# Backend Rules (PART 9, 10, 11, 32)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never interpolate user input into SQL, shell commands, or unsafe output.
- Never store raw credentials or expose secrets in logs or errors.

## CRITICAL - ALWAYS DO

- Use parameterized database operations, bounded resources, and secure defaults.
- Keep overlay services optional and make the server operate without them.

## Key rules

- Implement the specified error, caching, database, security, logging, and overlay behavior.

For complete details, see AI.md PART 9, 10, 11, 32.
