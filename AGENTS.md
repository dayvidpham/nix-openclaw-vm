# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress  # Claim work
bd close <id>         # Complete work
bd sync               # Sync with git
```

## Dependencies

Dependencies flow from **leaf work up to the user-facing request**. The leaf tasks (implementation details) must complete first, unblocking higher-level items, until the original request can be closed.

The chain reads left-to-right as "blocked by":

```
REQUEST -> URE -> PROPOSAL -> IMPLEMENTATION -> features, slices, plan
```

Meaning: REQUEST is blocked by URE, URE is blocked by PROPOSAL, etc.

### Correct: `--blocked-by` points at what must finish first

```bash
# "REQUEST is blocked by URE" — URE must complete before REQUEST can close
bd dep add request-id --blocked-by ure-id

# "PROPOSAL is blocked by IMPLEMENTATION"
bd dep add proposal-id --blocked-by impl-id
```

Produces the correct tree (leaf work at the bottom, user request at the top):

```
REQUEST
  └── blocked by URE
        └── blocked by PROPOSAL
              └── blocked by IMPLEMENTATION
                    ├── blocked by feature-slice-1
                    ├── blocked by feature-slice-2
                    └── blocked by impl-plan
```

### Wrong: reversed direction

```bash
# WRONG — this says "URE is blocked by REQUEST", meaning the request
# must finish before requirements gathering can start (backwards)
bd dep add ure-id --blocked-by request-id
```

Produces a nonsensical tree where implementation must wait for the request to close:

```
IMPLEMENTATION
  └── blocked by PROPOSAL
        └── blocked by URE
              └── blocked by REQUEST   # backwards — request can't block its own prerequisites
```

**Rule of thumb:** The `--blocked-by` target is always the thing you do *first*. Work flows bottom-up; closure flows top-down.

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

