# Gravelpit

Gravelpit is a sandbox for LLM coding agents on Linux.
The aim is that the agent can run nearly without per-command approval prompts.

It works by installing [BPF filter](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html) via seccomp to interceptssystem calls in the sandboxed processes. Intercepted calls are routed to a supervisor process via [`SECCOMP_RET_USER_NOTIF`](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html). The supervisor reads syscall arguments (file paths, addresses) from the target process memory using [`process_vm_readv`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html), evaluates [CEL](https://cel.dev/) policy rules, and responds with allow or deny.

## Quick start

```bash
make build
```

Create a minimal policy that only allows writes to the current directory:

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

- name: allow-writes-in-workdir
  action: [write, delete]
  verdict: allow
  match: pathMatch(path, "$WORKDIR/**")

- name: allow-writes-tmp
  action: [write, delete]
  verdict: allow
  match: pathMatch(path, "/tmp/**")

- name: allow-writes-dev
  action: [write, delete]
  verdict: allow
  match: pathMatch(path, "/dev/**")

- name: deny-writes-elsewhere
  action: [write, delete]
  verdict: deny
  match: "true"
  message: "Writing to '${path}' is not allowed. Only writes to the workspace are permitted."
EOF
```

Run a command inside the sandbox:

```console
$ bin/gravelpit run -e PS1="gravelpit> " -- bash --norc --noprofile
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

## CLI commands

```bash
gravelpit run [flags] -- <command> [args...]   # Run command in sandbox
gravelpit status [denies|recent]               # Show stats or recent syscalls (from inside sandbox)
gravelpit policy lint                          # Check policy files for errors
gravelpit policy eval <action> <target>        # Test which rule matches (<target> is path, tcp:H:P, or unix:P)
gravelpit policy reload                        # Reload policies in running supervisor
gravelpit policy explain                       # Show rule schema documentation
gravelpit config show                          # Show effective configuration
gravelpit config explain                       # Show config schema documentation
```

## Threat model

The agent isn't malicious. It is just very careless and unpredictable.
Gravelpit stops accidents like reading credential files, accessing sensitive sockets, deleting files outside the workspace, or overwriting user configs.
It is not a hard security boundary and a process trying to escape will get out.

Goals:

1. Let the agent work. Do not break normal development by asking user to press Y.
2. Stop obvious damage.
3. Explain denials. The agent gets a message saying it should not try to work around the limitation.
4. Allow logging every operation.
