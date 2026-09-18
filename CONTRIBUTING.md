# Contributing

## Build and test

```bash
make build                # -> bin/gravelpit
make test                 # unit tests
make integration-test     # integration tests
make bench                # benchmarks
make lint                 # golangci-lint
```

## Tool profiles

Each directory under [`profiles/tools/`](profiles/tools/) has a `run.sh` that exercises a toolchain (go, cargo, docker, etc.) inside the sandbox. Generated minimal policies are stored in [`profiles/generated/`](profiles/generated/).

```bash
make profile-verify                       # verify all profiles have zero denials
make profile-record                       # re-generate all policies
go run profiles/verify.go go              # verify one
go run profiles/verify.go --record go     # re-generate one
```
