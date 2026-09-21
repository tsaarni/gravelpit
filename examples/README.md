# Example policies

A working policy set for a development machine. Copy to start using:

```bash
cp examples/*.yaml ~/.config/gravelpit/policies/
```

## Rule evaluation

Rules are defined in YAML files. All rules are checked on every operation. When
multiple rules match, the one whose pattern has the most literal characters wins. If an allow and a deny score the same, deny wins. If no
rule matches, the operation is blocked. File order and file boundaries do not
matter.

```yaml
- { name: block-hidden-files, verdict: deny,  match: pathMatch(path, "$HOME/.*") }
- { name: read-tool-settings, verdict: allow, match: pathMatch(path, "$HOME/.config/git/**") }
```

Reading `~/.config/git/config` is allowed: both rules match, but the second
names more of the path. Reading `~/.ssh/id_rsa` is blocked because only
the first rule matches. Use `policy eval` to see the scores:

```
$ gravelpit policy eval read ~/.config/git/config
action: read
target: /home/user/.config/git/config
verdict: allow
decided by: read-tool-settings (score 26)

matched rules:
   16  deny   block-hidden-files
   26  allow  read-tool-settings              <- wins, more literal characters
```

## Rule format

```yaml
- name: block-hidden-files
  action: read
  verdict: deny
  match: pathMatch(path, "$HOME/.*") || pathMatch(path, "$HOME/.*/**")
  message: >
    Reading '${path}' is blocked. Hidden files in the home directory are not
    readable unless a rule names them, because they usually hold credentials.
```

| Field | Meaning |
|-------|---------|
| `name` | Shown in logs and error messages. |
| `action` | Operation to match: one value or a list. |
| `verdict` | `allow` or `deny`. |
| `match` | [CEL](https://cel.dev) expression. If true, the rule applies. |
| `message` | Shown to the process on denial. Optional but recommended. |

Any `$VAR` in rule fields is expanded from the environment. `$WORKDIR` is
the one variable gravelpit adds: the directory where `gravelpit run` was
started. It equals the CEL variable `sandbox.workdir`.

In `pathMatch`, `*` matches one path component, `**` matches any depth,
and the pattern must match the whole path.

## Actions

| Action | Syscalls |
|--------|----------|
| `read` | Open a file for reading |
| `write` | Open a file for writing, creating, or appending; mkdir |
| `delete` | unlink, rmdir, rename, truncate |
| `metadata` | chmod, chown |
| `exec` | execve |
| `connect` | TCP and Unix socket connections |

## Policy files in this directory

| File | Purpose |
|------|---------|
| `reads.yaml` | What the agent can see. Reads, exec and network start open. Hidden files in `$HOME` are blocked, then specific paths are allowed back. |
| `writes.yaml` | What the agent can change. Writes and deletes start closed. Workspace, caches and tool state directories are allowed. Gravelpit's own files are protected. |

## Editing policies

Check what was denied (inside the sandbox):

```bash
gravelpit status denies
```

Test which rule matches a path (works anywhere):

```bash
gravelpit policy eval read "$HOME/.cargo/config.toml"
```

Edit the policy file, then reload (inside the sandbox):

```bash
gravelpit policy reload
```

Adding new paths to the allow rules is expected as you discover what your tools need.

To discover paths automatically (outside the sandbox):

```bash
gravelpit run --record discovered.yaml -- <command>
```

This runs the command and writes a policy covering all paths that were denied.

## Denial messages and agent prompts

Deny rules can have a `message` field. The message is printed to the
process's stderr with a `[gravelpit]` prefix:

```yaml
- name: block-hidden-files
  action: read
  verdict: deny
  match: pathMatch(path, "$HOME/.*") || pathMatch(path, "$HOME/.*/**")
  message: >
    Reading '${path}' is not allowed. Do not work around this.
```

```
[gravelpit] Reading '/home/user/.aws/credentials' is not allowed. Do not work around this.
```

Supported placeholders in `message`:

| Placeholder | Value |
|-------------|-------|
| `${path}` | Resolved absolute path |
| `${requestedPath}` | Original path before symlink resolution |
| `${socket}` | Unix socket path (for connect actions) |

Rules without a `message` use the default from config. The default is set
in `config.yaml` via `default_deny_message`.

Deny rules return EACCES by default. Most tools handle EACCES gracefully
when probing optional files, so the denial does not cause the command to
fail.

Rules without a `message` field use the default:

> [gravelpit] You are running in a sandbox and the request was denied by
> policy. Stop, describe what happened and ask the user for instructions.

This can be changed in `config.yaml` via `default_deny_message`. To suppress
the message entirely for a rule, set `notify: false`.

Suggested agent prompt snippet:

```
You are running inside a gravelpit sandbox. If a command fails and stderr
contains `[gravelpit]`, the failure is a sandbox restriction. Report the
message to the user and stop. Do not try to work around it with chmod or
sudo.
```

## Tips

Name narrow paths, not whole directories. `$HOME/.config/git/**`, not
`$HOME/.config/**`. Too narrow breaks one tool and the log tells you what to
add. Too wide leaks a secret silently.

Start patterns at a root, with `**` only at the end. `$HOME/.cache/**`, never
`**/.env`.

Put brackets around mixed `&&` and `||`. CEL reads `a || b && c` as
`a || (b && c)`. Gravelpit refuses to load a rule that mixes them without
brackets.

Run `gravelpit policy explain` for the full rule schema.
