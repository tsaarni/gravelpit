# Tool profiles

Tool profiles discover which file and network paths each tool needs when running inside the gravelpit sandbox. The discovered policies serve as input when writing sandbox policies for real projects.

## Directory layout

```
profiles/
  base-policy.yaml          shared base policy (system libs, /tmp, workspace)
  verify.go                 recording and verification driver
  tools/<name>/
    run.sh                  script that exercises the tool
    fixture/                optional source files the script needs
  generated/<name>.yaml     discovered policy (committed, regenerated on changes)
```

## How it works

`verify.go` copies `run.sh` and `fixture/` into a temporary workspace, runs the script inside the sandbox with audit logging, and collects denied paths. In record mode it iterates until no new denials appear, then writes a generated policy. In verify mode it runs once and fails if any denials occur.

The base policy covers paths every tool needs: system libraries, `/tmp`, the workspace itself. The generated policy covers only tool-specific paths outside the workspace, such as config files and caches under `$HOME`.

## Running

```bash
make profile-verify                          # verify all profiles
make profile-record                          # re-record all profiles
go run profiles/verify.go <name>             # verify one profile
go run profiles/verify.go --record <name>    # re-record one profile
```

## Creating a new profile

1. Create `profiles/tools/<name>/run.sh`. Start with a `--check` guard that exits 0 if the tool is installed, non-zero otherwise. The driver calls `run.sh --check` to skip profiles for tools that are not available. After the guard, exercise the tool:

```bash
#!/bin/bash
# Profile: short description.
[ "$1" = "--check" ] && { command -v mytool >/dev/null; exit; }
mytool build
mytool test
```

2. If the tool needs source files, put them in `profiles/tools/<name>/fixture/`. They are copied into the temporary workspace before running.

3. Record the profile: `go run profiles/verify.go --record <name>`. This creates `profiles/generated/<name>.yaml`.

4. Verify: `go run profiles/verify.go <name>`. Run it several times to check for non-determinism.

5. Commit both `run.sh` (and fixture if any) and the generated policy.

## Dealing with non-determinism

Recording must capture every path the tool might access. Tools have time-dependent behavior that makes some paths appear only under certain conditions. If a path is missed during recording, verification will fail intermittently.

Common causes and fixes:

| Cause | Example | Fix in run.sh |
|-------|---------|---------------|
| Time-based cache skip | pnpm skips metadata refresh when cache is recent | Clear cache entries before install |
| Daemon reuse | mvnd reuses a running daemon, skipping startup paths | Stop the daemon before the build |
| Cached flags | kubectl `--cached` skips server contact | Remove the flag so the network path is exercised |
| Periodic maintenance | Cargo auto-gc scans `~/.cargo/registry/` once per day | Set `CARGO_CACHE_AUTO_CLEAN_FREQUENCY=always` |

In each case, the fix is in `run.sh`: either reset state so the tool exercises all paths, remove flags that skip work, or set environment variables that trigger optional behavior. The generated policy is not edited by hand.

If verification passes sometimes but fails other times, suspect time-dependent behavior. Run with `--audit-level=all` to see which paths appear in each run.
