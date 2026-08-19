# Contributing

## Build

```bash
make build
```

This produces `bin/gravelpit`.

## Test

Unit tests:

```bash
make test
```

Integration tests require Linux x86_64 with kernel 5.19+ and seccomp user notification support:

```bash
make integration-test
```

Benchmarks:

```bash
make bench
```

## Lint

```bash
make lint
```

Requires [golangci-lint](https://golangci-lint.run/).

