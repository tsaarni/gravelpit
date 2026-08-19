// Package policy provides built-in rules that protect gravelpit's own files and socket.
// These are loaded before any user policy so deleting the user rules does not open holes.
package policy

import "fmt"

// builtinYAML holds the two mandatory rules for protecting gravelpit itself.
// They mirror the rules in policies/examples/gravelpit.yaml but are compiled
// programmatically so they cannot be removed by deleting that file.
const builtinYAML = `
- name: protect-gravelpit-files
  action: [write, delete]
  verdict: deny
  match: >
    pathMatch(path, "$HOME/.config/gravelpit/**") ||
    pathMatch(path, "$XDG_DATA_HOME/gravelpit/**")
  message: >
    Writing '${path}' is blocked. These are gravelpit's own rules and its record of what
    happened, and they cannot be changed from inside the sandbox.
    If a rule is genuinely wrong, say so and stop. The user will change it.

- name: protect-gravelpit-socket
  action: connect
  verdict: deny
  match: >
    family == "AF_UNIX" && (
      pathMatch(socket, "$XDG_RUNTIME_DIR/gravelpit/**") ||
      pathMatch(socket, "/tmp/gravelpit-*/**")
    )
  message: >
    This is gravelpit's control socket. It is blocked, and reaching it would let you stop the
    sandbox you are running in. If a rule is genuinely wrong, say so and stop. The user
    will change it.
`

// BuiltinRules returns the compiled built-in protection rules. They must be
// prepended to the user rules before creating the engine.
func BuiltinRules() ([]*CompiledRule, error) {
	loader, err := NewLoader()
	if err != nil {
		return nil, fmt.Errorf("creating loader for built-in rules: %w", err)
	}

	rules, errs := loader.LoadBytes([]byte(builtinYAML), "<builtin>")
	if len(errs) > 0 {
		return nil, fmt.Errorf("compiling built-in rules: %v", errs[0])
	}
	return rules, nil
}
