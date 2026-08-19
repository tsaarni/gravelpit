# Gravelpit policy examples

Gravelpit watches what a program does — files it opens, programs it runs, connections it makes
— and allows or blocks each one. These files are the rules. They are a working set for a
normal development machine.

To use them:

```bash
cp *.yaml ~/.config/gravelpit/policies/
```

Gravelpit picks up changes as you save them. No restart.

## How a decision is made

Every rule is checked. Of the rules that match, **the one that names the most of the path
wins.**

```yaml
- { name: block-hidden-files, verdict: deny,  match: pathMatch(path, "$HOME/.*") }
- { name: read-tool-settings, verdict: allow, match: pathMatch(path, "$HOME/.config/git/**") }
```

Reading `~/.config/git/config` is allowed. Both rules match, but the second names more of
the path. Reading `~/.aws/credentials` is blocked: only the first rule matches.

If no rule matches, the answer is blocked. Nothing is permitted until a rule says so, and
that cannot be configured.

Order does not matter. Neither does which file a rule is in. Files group rules by subject so
you can find them.

Two details, for when you need them:

- A rule that names no path — `match: true` — counts as zero, so anything naming a path
  beats it. That is how `baseline.yaml` can allow all reads and still be overruled.
- If an allow and a deny name exactly the same amount, deny wins.

## A rule

```yaml
- name: block-hidden-files
  action: read
  verdict: deny
  match: pathMatch(path, "$HOME/.*") || pathMatch(path, "$HOME/.*/**")
  message: >
    Reading '${path}' is blocked by sandbox policy. Hidden files in the home directory
    are not readable unless a rule names them, because they usually hold credentials.
```

| Field | Meaning |
|-------|---------|
| `name` | Shown in the log and in error messages. |
| `action` | Which kind of operation this is about. One value or a list. |
| `verdict` | `allow` or `deny`. |
| `match` | A [CEL](https://cel.dev) expression. If it is true, the rule applies. |
| `message` | What the program is told when it is blocked. Optional. |

`message` is optional but it is the point of the tool. An agent told "policy blocked this"
stops looking for a way around it. An agent that gets a bare error keeps trying.

`$HOME`, `$WORKDIR`, `$TMPDIR` and `$XDG_*` are filled in when the file is loaded.

In `pathMatch`, `*` covers one name, `**` covers any number of directories, and a pattern
must match the whole path. `$HOME/.config/git/**` matches the directory itself and
everything under it.

## The six actions

| Action | What it covers |
|--------|----------------|
| `read` | Opening a file to read it |
| `write` | Opening a file to write, create, append or truncate, and creating a directory |
| `delete` | Deleting, renaming or truncating |
| `metadata` | `chmod` and `chown` |
| `exec` | Running a program |
| `connect` | Network connections and Unix sockets |

## The four files

| File | What it is about |
|------|------------------|
| `baseline.yaml` | How open the sandbox is. Four rules, no paths. |
| `secrets.yaml` | Keeping credentials in: hidden files in `$HOME`, project `.env` files, the keyring sockets. |
| `writes.yaml` | What the agent may change: the workspace, `/tmp`, build caches, tool settings. |
| `gravelpit.yaml` | Gravelpit's own rules, log and control socket. |

Read `baseline.yaml` first. It says what is open, and every other file narrows it.

Each file covers all actions for its subject, so everything about one topic is in one place.

## What the agent can do

| Action | Allowed | Blocked |
|--------|---------|---------|
| `read` | everything | hidden files in `$HOME`, project `.env` files |
| `write`, `delete` | the workspace, `/tmp`, build caches, tool settings | autorun files, gravelpit's own files |
| `metadata` | the workspace, `/tmp`, build caches | everywhere else, with an explanation |
| `exec` | everything | nothing. Recorded only. |
| `connect` | all network traffic, all Unix sockets | password stores, gravelpit's own socket |

Reads are opened and then narrowed. Writes are listed one path at a time. The difference is
which list a person can actually write: you cannot list every file a toolchain reads, but you
can list the places a machine writes to. Sockets go the first way, because a machine needs
many and only a few are worth blocking.

## When a tool breaks

The log names the exact path that was blocked:

```bash
gravelpit audit search --since 10m --verdict deny
```

Then ask why, if it is not obvious:

```bash
gravelpit policy eval read "$HOME/.cargo/config.toml"
```

To fix it, add the path to the allow rule it belongs with in `secrets.yaml`:

```yaml
- name: read-toolchains
  action: read
  verdict: allow
  match: >
    pathMatch(path, "$HOME/.cargo/registry/**") ||
    pathMatch(path, "$HOME/.cargo/config.toml")     // <- add lines here
```

Or put it in a file of your own, `mine.yaml`. It makes no difference which file it is in.

It works because `$HOME/.cargo/config.toml` names more of the path than the deny rule's
`$HOME/.*`. Growing this list is normal. It is meant to grow as you find out what your tools
read.

## Four things to get right

**Name narrow paths, not whole directories.** Add `$HOME/.config/git/**`, not
`$HOME/.config/**`. The short version also hands over `~/.config/gh/hosts.yml`, which holds
a GitHub token, and anything a future tool keeps there. The two mistakes are not equally
bad: too narrow breaks one tool and the log tells you which path to add, too wide leaks a
secret and tells you nothing.

**Start every pattern at a root, with `**` only at the end.** `$HOME/.cache/**`, never
`**/.env`. A pattern with no root can match anywhere, but it names almost nothing, so an
allow rule for a long path would beat it and you would not see why. `**` in the middle
(like `$HOME/work/**/.env`) is not supported because the characters after it float and
make specificity scoring unreliable.

**Comments inside `match` start with `//`.** The file around it is YAML, where comments start
with `#`, but `#` inside an expression is an error and gravelpit will not load the rule.

**Put brackets around mixed `&&` and `||`.** CEL reads `a || b && c` as `a || (b && c)`,
which is usually not what you meant. Gravelpit refuses to load a rule that mixes them without
brackets.

## Checking a change before you rely on it

```bash
gravelpit policy test              # against ../../testdata/policy/expectations.yaml
gravelpit policy test --coverage   # which rules no test touches
```

`expectations.yaml` lists an operation, the answer it should get, and which rule should
decide. Run it after changing a rule. It also catches a case that passes for the wrong
reason, because the expected rule name is part of the test — which matters here, since a new
rule naming a long path can quietly take over a decision another rule used to make.
