![Gravelpit - security through low expectations](assets/banner.jpg)

Gravelpit is a sandbox for LLM coding agents on Linux.
The aim is that the agent can run nearly without per-command approval prompts.

## Threat model

The agent isn't malicious. It is just careless, unpredictable, and a little unhinged.
Gravelpit stops accidents like reading credential files, accessing sensitive sockets, deleting files outside the workspace, or overwriting user configs.
It is not a hard security boundary and a process trying to escape will get out.

Goals:

1. Let the agent work. Do not break normal development by asking user to press Y.
2. Stop obvious damage.
3. Explain denials. The agent gets a message saying it should not try to work around the limitation.
4. Log every operation.

## How it works

Gravelpit installs a [BPF filter](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html) via seccomp to intercept system calls in the sandboxed processes. Intercepted calls are routed to a supervisor process via [`SECCOMP_RET_USER_NOTIF`](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html). The supervisor reads syscall arguments (file paths, addresses) from the target process memory using [`process_vm_readv`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html), evaluates [CEL](https://cel.dev/) policy rules, and responds with allow or deny. Denials are printed to the process's stderr.

Only `open()` and `connect()` are intercepted, not `read()`/`write()`. Decisions are cached and simple rules use a fast path that skips the CEL engine, so overhead is low in practice.

The [`SECCOMP_RET_USER_NOTIF`](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html) mechanism has an inherent TOCTOU race: another thread can rewrite syscall arguments while the supervisor inspects them. Allowing docker also means the agent can escalate to root.

## Quick start

Build the `bin/gravelpit` binary:

```bash
make build
```

Create a minimal policy that only allows writes to the workspace:

```bash
mkdir -p ~/.config/gravelpit/policies
cat > ~/.config/gravelpit/policies/test.yaml << 'EOF'
- name: allow-reads
  action: read
  verdict: allow
  match: "true"

- name: allow-exec
  action: exec
  verdict: allow
  match: "true"

- name: allow-network
  action: connect
  verdict: allow
  match: "true"

- name: allow-writes
  action: [write, delete]
  verdict: allow
  match: pathMatch(path, "$WORKDIR/**") || pathMatch(path, "/tmp/**")

- name: deny-writes-elsewhere
  action: [write, delete]
  verdict: deny
  match: "true"
  message: "Writing to '${path}' is not allowed. Only writes to the workspace are permitted."
EOF
```

`$WORKDIR` expands to the current directory where you start the sandbox, and `$HOME` to the home directory.

Run a command inside the sandbox:

```console
$ bin/gravelpit run --env PS1="gravelpit> " -- bash --norc --noprofile
▶ gravelpit sandbox policy=~/.config/gravelpit/policies
gravelpit> echo "hello from sandbox" > ~/cannot-write.txt
[gravelpit] Writing to '/home/tsaarni/cannot-write.txt' is not allowed. Only writes to the workspace are permitted.
bash: /home/tsaarni/cannot-write.txt: Permission denied
gravelpit> bin/gravelpit status
UPTIME  REQUESTS  ALLOWED  DENIED  RELOADS
33s     29        28       1       0

CACHE      ENTRIES  MEMORY  HITS  MISSES  HIT RATE
decisions  4/10000  861 B   1     4       20.0%
processes  6/4096   763 B   24    2       92.3%

ACTION   ALLOW  DENY
read     22     0
write    1      1
exec     2      0
connect  3      0
gravelpit> bin/gravelpit status denies
AGE  VERDICT  ACTION  RULE                   PATH
11s  deny     write   deny-writes-elsewhere  /home/tsaarni/cannot-write.txt
```

See [`examples/`](examples/) for fuller policies and `gravelpit policy explain` for the rule schema.

## CLI commands

```bash
gravelpit run [flags] -- <command> [args...]   # Run command in sandbox
gravelpit status [denies|recent]               # Show stats or recent syscalls (from inside sandbox)
gravelpit policy lint                          # Check policy files for errors
gravelpit policy eval <action> <target>        # Test which rule matches (<target> is path, tcp:H:P, or unix:P)
gravelpit policy reload                         # Reload policies in running supervisor
gravelpit policy explain                        # Show rule schema documentation
gravelpit config show                           # Show effective configuration
gravelpit config explain                        # Show config schema documentation
```

Useful `run` flags: `--policy-dir` (default `~/.config/gravelpit/policies`), `--env KEY=VALUE`, `--audit-file`, `--audit-level all|denials`, `--log-level`, `--record` (write discovered policy to a file on exit).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
