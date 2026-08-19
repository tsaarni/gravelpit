// rule.go defines the policy rule as represented in YAML configuration files.
package schema

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Rule is a policy rule as defined in YAML configuration files.
type Rule struct {
	// Name of the rule. Used in logging and diagnostics.
	Name string `yaml:"name" json:"name" jsonschema:"description=Name of the rule. Used in logging and diagnostics."`
	// Human-readable explanation of what this rule does.
	Description string `yaml:"description" json:"description,omitempty" jsonschema:"description=Human-readable explanation of what this rule does."`
	// Operation to match. A single string or a list: read, write, delete, metadata, exec, connect.
	Actions Actions `yaml:"action" json:"actions" jsonschema:"description=Operation to match. A single string or a list: read\\, write\\, delete\\, metadata\\, exec\\, connect."`
	// Decision when the rule matches: allow or deny.
	Verdict Verdict `yaml:"verdict" json:"verdict" jsonschema:"description=Decision when the rule matches: allow or deny."`
	// CEL expression evaluated against the event.
	Match string `yaml:"match" json:"match" jsonschema:"description=CEL expression evaluated against the event. Available variables: path\\, requestedPath\\, action\\, syscall.name\\, syscall.number\\, process.pid\\, process.tgid\\, process.ppid\\, process.exe\\, process.comm\\, process.cwd\\, host\\, port\\, family\\, socket\\, ancestors\\, sandbox.id\\, sandbox.command\\, sandbox.workdir. Functions: pathMatch(path\\, pattern)\\, startedBy(name). process.cmdline is declared but never populated\\, so a rule reading it never matches."`
	// Notification shown to the user on denial. Supports ${path} and ${requestedPath} placeholders.
	Message string `yaml:"message" json:"message,omitempty" jsonschema:"description=Notification shown to the user on denial. Supports ${path} and ${requestedPath} placeholders."`
	// Error code returned on denial: EACCES, ENOENT, EROFS, EPERM. Defaults to EACCES.
	Errno string `yaml:"errno" json:"errno,omitempty" jsonschema:"description=Error code returned on denial: EACCES\\, ENOENT\\, EROFS\\, EPERM. Defaults to EACCES."`
	// Whether to write this decision to the audit log. Defaults to true. Set to false to suppress high-volume noise.
	Audit *bool `yaml:"audit" json:"audit,omitempty" jsonschema:"description=Whether to write this decision to the audit log. Defaults to true. Set to false to suppress high-volume noise. Does not affect the message delivered to the process (see notify) or the counters in 'gravelpit status'."`
	// Whether to deliver the denial message to the process's stderr. Defaults to true. Set to false to deny silently.
	Notify *bool `yaml:"notify" json:"notify,omitempty" jsonschema:"description=Whether to deliver the denial message to the sandboxed process's stderr. Defaults to true. Set to false to deny silently\\, suppressing both the rule message and the configured default_deny_message. Use for denials the process handles on its own\\, where a message would only mislead the reader. Ignored for allow verdicts."`
	// Source file path (set by loader, not in YAML).
	File string `yaml:"-" json:"file,omitempty"`
	// Line the rule starts on in its source file (set by loader, not in YAML).
	// Real line number, so file:line can be opened in an editor.
	Line int `yaml:"-" json:"-"`
}

// ShouldAudit reports whether a decision from this rule is written to the audit
// log. Unset means true.
//
// Nil-safe: a nil rule is the default-deny case, where no rule matched. That
// denial is always audited, since a policy gap is the last thing that should be
// invisible.
func (r *Rule) ShouldAudit() bool {
	if r == nil || r.Audit == nil {
		return true
	}
	return *r.Audit
}

// ShouldNotify reports whether a denial from this rule delivers a message to the
// sandboxed process. Unset means true. Nil-safe for the same reason as
// ShouldAudit.
func (r *Rule) ShouldNotify() bool {
	if r == nil || r.Notify == nil {
		return true
	}
	return *r.Notify
}

// Actions is a list of actions that unmarshals from either a single string or a YAML list.
type Actions []Action

func (a *Actions) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		action, ok := ParseAction(value.Value)
		if !ok {
			return fmt.Errorf("unknown action %q", value.Value)
		}
		*a = Actions{action}
		return nil
	case yaml.SequenceNode:
		var strs []string
		if err := value.Decode(&strs); err != nil {
			return err
		}
		result := make(Actions, 0, len(strs))
		for _, s := range strs {
			action, ok := ParseAction(s)
			if !ok {
				return fmt.Errorf("unknown action %q", s)
			}
			result = append(result, action)
		}
		*a = result
		return nil
	default:
		return fmt.Errorf("action must be a string or list of strings")
	}
}
