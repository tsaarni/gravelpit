# Policy examples

A working policy set for a development machine. Two files, ready to copy:

```bash
cp *.yaml ~/.config/gravelpit/policies/
```

Gravelpit picks up changes as you save them. No restart needed.

## The two files

| File | What it covers |
|------|----------------|
| `reads.yaml` | What the agent can see. Reads, exec and network start open. Hidden files in `$HOME` are blocked, then safe paths are named back. |
| `writes.yaml` | What the agent can change. Write, delete and metadata start closed. Writable paths are listed, and autorun files and gravelpit's own files are protected. |

## How a decision is made

Every rule is checked. Of the rules that match, the one that names the most of the path wins.

```yaml
- { name: block-hidden-files, verdict: deny,  match: pathMatch(path, "$HOME/.*") }
- { name: read-tool-settings, verdict: allow, match: pathMatch(path, "$HOME/.config/git/**") }
```

Reading `~/.config/git/config` is allowed — both rules match, but the second names more of
the path. Reading `~/.aws/credentials` is blocked — only the first rule matches.

If no rule matches, the operation is blocked. A rule with `match: "true"` scores zero, so
anything naming a path beats it. If an allow and a deny name the same amount, deny wins.

Order does not matter. Neither does which file a rule is in.

## A rule

```yaml
- name: block-hidden-files
  action: read
  verdict: deny
  match: pathMatch(path, "$HOME/.*") || pathMatch(path, "$HOME/.*/**")
  message: >
    Reading '${path}' is blocked. Hidden files in the home directory are not readable
    unless a rule names them, because they usually hold credentials.
```

| Field | Meaning |
|-------|---------|
| `name` | Shown in the log and in error messages. |
| `action` | Which operation: one value or a list. |
| `verdict` | `allow` or `deny`. |
| `match` | A [CEL](https://cel.dev) expression. If true, the rule applies. |
| `message` | What the program is told when blocked. Optional but recommended. |

`$HOME`, `$WORKDIR`, `$TMPDIR` and `$XDG_*` are filled in when the file is loaded.

In `pathMatch`, `*` matches one name, `**` matches any depth, and the pattern must match
the whole path.

## The six actions

| Action | What it covers |
|--------|----------------|
| `read` | Opening a file to read it |
| `write` | Opening a file to write, create, append or truncate, and creating a directory |
| `delete` | Deleting, renaming or truncating |
| `metadata` | `chmod` and `chown` |
| `exec` | Running a program |
| `connect` | Network connections and Unix sockets |

## When a tool breaks

Check what was denied:

```bash
gravelpit status denies
```

Test which rule matches a path:

```bash
gravelpit policy eval read "$HOME/.cargo/config.toml"
```

Then add the path to the matching allow rule. Growing the allow list is normal — it is
meant to grow as you find out what your tools need.

To discover what paths a tool needs, run it with `--record`:

```bash
gravelpit run --record tool-policy.yaml -- <command>
```

## Tips

**Name narrow paths, not whole directories.** `$HOME/.config/git/**`, not
`$HOME/.config/**`. Too narrow breaks one tool and the log tells you what to add.
Too wide leaks a secret silently.

**Start patterns at a root, with `**` only at the end.** `$HOME/.cache/**`, never
`**/.env`.

**Comments inside `match` use `//`, not `#`.** The file is YAML where `#` starts a
comment, but inside a CEL expression `#` is an error.

**Put brackets around mixed `&&` and `||`.** CEL reads `a || b && c` as `a || (b && c)`.
Gravelpit refuses to load a rule that mixes them without brackets.

Run `gravelpit policy explain` for the full rule schema.
