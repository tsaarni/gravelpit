// explain.go implements kubectl-style schema documentation for policy rules and events.
package policy

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/tsaarni/gravelpit/pkg/schema"
)

// FieldDoc describes a single field in a schema.
type FieldDoc struct {
	Name        string
	Type        string
	Required    bool
	Description string
	Children    []FieldDoc
}

// SchemaDoc holds the top-level documentation for a schema kind.
type SchemaDoc struct {
	Kind        string
	Description string
	Fields      []FieldDoc
}

// ExplainRule returns documentation for the rule YAML schema.
func ExplainRule() *SchemaDoc {
	t := reflect.TypeOf(Rule{})
	fields := extractFields(t, "yaml")

	return &SchemaDoc{
		Kind:        "Rule",
		Description: "A policy rule defines access control for filesystem and network operations.\nRules are defined in YAML files inside the policy directory.",
		Fields:      fields,
	}
}

// ExplainEvent returns documentation for the event variables available in
// CEL match expressions.
func ExplainEvent() *SchemaDoc {
	t := reflect.TypeOf(schema.Event{})
	fields := extractFields(t, "json")

	return &SchemaDoc{
		Kind:        "Event",
		Description: "Variables available in rule match expressions.\nThese are populated from the intercepted syscall and passed to CEL evaluation.",
		Fields:      fields,
	}
}

// extractFields reads schema fields from struct tags. nameTag specifies which
// tag to use for field names ("yaml" or "json").
func extractFields(t reflect.Type, nameTag string) []FieldDoc {
	docs := make([]FieldDoc, 0, t.NumField())

	for i := range t.NumField() {
		f := t.Field(i)

		name := f.Tag.Get(nameTag)
		if name == "" || name == "-" {
			continue
		}
		if idx := strings.Index(name, ","); idx >= 0 {
			name = name[:idx]
		}

		typeName := schemaTypeName(f.Type)
		required := name == "name" || name == "action" || name == "verdict" || name == "match"
		desc := parseDescription(f.Tag.Get("jsonschema"))

		// Recurse into nested structs for children.
		var children []FieldDoc
		ft := f.Type
		if ft.Kind() == reflect.Struct && ft.PkgPath() != "" {
			children = extractFields(ft, nameTag)
			if len(children) > 0 {
				typeName = "map"
			}
		}

		docs = append(docs, FieldDoc{
			Name:        name,
			Type:        typeName,
			Required:    required,
			Description: desc,
			Children:    children,
		})
	}

	return docs
}

// FormatExplain formats a SchemaDoc as kubectl-explain-style text.
func FormatExplain(doc *SchemaDoc) string {
	var b strings.Builder

	fmt.Fprintf(&b, "KIND:    %s\n\n", doc.Kind)
	b.WriteString("DESCRIPTION:\n")
	for _, line := range strings.Split(doc.Description, "\n") {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	b.WriteString("\nFIELDS:\n")

	formatFields(&b, doc.Fields, "  ")

	return b.String()
}

func formatFields(b *strings.Builder, fields []FieldDoc, indent string) {
	for _, d := range fields {
		req := ""
		if d.Required {
			req = " -required-"
		}
		fmt.Fprintf(b, "%s%s\t<%s>%s\n", indent, d.Name, d.Type, req)
		if d.Description != "" {
			for _, line := range wrapText(d.Description, 72) {
				fmt.Fprintf(b, "%s  %s\n", indent, line)
			}
		}
		if len(d.Children) > 0 {
			formatFields(b, d.Children, indent+"  ")
		}
		b.WriteString("\n")
	}
}

// schemaTypeName returns a human-readable type name for display.
func schemaTypeName(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "integer"
	case reflect.Pointer:
		return schemaTypeName(t.Elem())
	case reflect.Slice:
		elem := schemaTypeName(t.Elem())
		return "[]" + elem
	default:
		return t.Name()
	}
}

// parseDescription extracts the description value from a jsonschema tag string.
// Tag format: "description=some text,other=value".
// Escaped commas (\,) within a value are preserved as literal commas.
func parseDescription(tag string) string {
	const prefix = "description="
	idx := strings.Index(tag, prefix)
	if idx < 0 {
		return ""
	}

	rest := tag[idx+len(prefix):]

	var b strings.Builder
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\\' && i+1 < len(rest) && rest[i+1] == ',' {
			b.WriteByte(',')
			i++
			continue
		}
		if rest[i] == ',' {
			// Unescaped comma: end of value if followed by key=.
			remaining := rest[i+1:]
			if eqIdx := strings.Index(remaining, "="); eqIdx >= 0 {
				key := remaining[:eqIdx]
				if len(key) > 0 && !strings.Contains(key, " ") {
					break
				}
			}
			b.WriteByte(',')
			continue
		}
		b.WriteByte(rest[i])
	}

	return b.String()
}

// wrapText breaks text into lines of at most maxWidth characters at word boundaries.
func wrapText(text string, maxWidth int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}

	var lines []string
	current := words[0]

	for _, w := range words[1:] {
		if len(current)+1+len(w) > maxWidth {
			lines = append(lines, current)
			current = w
		} else {
			current += " " + w
		}
	}
	lines = append(lines, current)
	return lines
}
