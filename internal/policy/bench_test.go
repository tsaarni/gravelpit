// bench_test.go benchmarks the policy engine evaluation path.
package policy

import (
	"fmt"
	"testing"
)

// BenchmarkEvalFastPath benchmarks a pure-pathMatch rule (no CEL interpreter).
func BenchmarkEvalFastPath(b *testing.B) {
	rules := []Rule{
		{
			Name:    "block-hidden",
			Actions: []Action{ActionRead},
			Verdict: VerdictDeny,
			Match:   `pathMatch(path, "/home/user/.*") || pathMatch(path, "/home/user/.*/**")`,
		},
		{
			Name:    "allow-cache",
			Actions: []Action{ActionRead},
			Verdict: VerdictAllow,
			Match:   `pathMatch(path, "/home/user/.cache/**")`,
		},
	}

	compiled := compileTestRules(b, rules)
	engine := NewEngine(compiled)

	ev := &Event{Action: ActionRead, Path: "/home/user/.cache/go-build/x"}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		engine.Evaluate(ev)
	}
}

// BenchmarkEvalCEL benchmarks a rule that requires CEL (uses family field).
func BenchmarkEvalCEL(b *testing.B) {
	rules := []Rule{
		{
			Name:    "allow-unix",
			Actions: []Action{ActionConnect},
			Verdict: VerdictAllow,
			Match:   `family == "AF_UNIX"`,
		},
		{
			Name:    "block-bus",
			Actions: []Action{ActionConnect},
			Verdict: VerdictDeny,
			Match:   `family == "AF_UNIX" && pathMatch(socket, "/run/user/*/bus")`,
		},
	}

	compiled := compileTestRules(b, rules)
	engine := NewEngine(compiled)

	ev := &Event{Action: ActionConnect, Socket: "/run/docker.sock", Family: "AF_UNIX"}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		engine.Evaluate(ev)
	}
}

// BenchmarkEvalMiss benchmarks the case where no rule matches (default deny).
func BenchmarkEvalMiss(b *testing.B) {
	rules := []Rule{
		{
			Name:    "allow-workspace",
			Actions: []Action{ActionWrite},
			Verdict: VerdictAllow,
			Match:   `pathMatch(path, "/home/user/work/**")`,
		},
	}

	compiled := compileTestRules(b, rules)
	engine := NewEngine(compiled)

	ev := &Event{Action: ActionWrite, Path: "/home/user/notes.txt"}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		engine.Evaluate(ev)
	}
}

// BenchmarkEvalManyPatterns benchmarks a rule with many patterns (like read-toolchains).
func BenchmarkEvalManyPatterns(b *testing.B) {
	rules := []Rule{
		{
			Name:    "read-toolchains",
			Actions: []Action{ActionRead},
			Verdict: VerdictAllow,
			Match: `pathMatch(path, "/home/user/.cargo/registry/**") ||
				pathMatch(path, "/home/user/.cargo/bin/**") ||
				pathMatch(path, "/home/user/.cargo/env") ||
				pathMatch(path, "/home/user/.rustup/**") ||
				pathMatch(path, "/home/user/.nvm/**") ||
				pathMatch(path, "/home/user/.pyenv/**") ||
				pathMatch(path, "/home/user/.rbenv/**") ||
				pathMatch(path, "/home/user/.sdkman/**") ||
				pathMatch(path, "/home/user/.local/bin/**") ||
				pathMatch(path, "/home/user/.local/lib/**") ||
				pathMatch(path, "/home/user/.local/share/**") ||
				pathMatch(path, "/home/user/.local/state/**") ||
				pathMatch(path, "/home/user/.krew/**")`,
		},
		{
			Name:    "block-hidden",
			Actions: []Action{ActionRead},
			Verdict: VerdictDeny,
			Match:   `pathMatch(path, "/home/user/.*") || pathMatch(path, "/home/user/.*/**")`,
		},
	}
	compiled := compileTestRules(b, rules)
	engine := NewEngine(compiled)

	b.Run("hit-last-pattern", func(b *testing.B) {
		ev := &Event{Action: ActionRead, Path: "/home/user/.krew/bin/kubectl-ctx"}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			engine.Evaluate(ev)
		}
	})

	b.Run("miss-all-patterns", func(b *testing.B) {
		ev := &Event{Action: ActionRead, Path: "/home/user/.ssh/id_rsa"}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			engine.Evaluate(ev)
		}
	})

	b.Run("hit-first-pattern", func(b *testing.B) {
		ev := &Event{Action: ActionRead, Path: "/home/user/.cargo/registry/crates.io/tokio-1.0.0/src/lib.rs"}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			engine.Evaluate(ev)
		}
	})
}

// BenchmarkCacheHit benchmarks a decision cache hit, which is what every
// repeated syscall on the same path pays instead of an evaluation. Compare it
// against BenchmarkEvalFastPath to see what the cache buys.
func BenchmarkCacheHit(b *testing.B) {
	c := NewCache(10000)
	keys := make([]CacheKey, 1000)
	for i := range keys {
		keys[i] = CacheKey{Action: ActionRead, Target: fmt.Sprintf("/usr/include/dir%d/header.h", i)}
		c.Put(keys[i], Decision{Verdict: VerdictAllow})
	}

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		c.Get(keys[i%len(keys)])
	}
}
