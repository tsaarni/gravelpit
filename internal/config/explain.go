// explain.go provides self-documentation and display of effective configuration.
package config

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// FieldDoc describes a single configuration field.
type FieldDoc struct {
	Name        string
	Type        string
	Description string
	Children    []FieldDoc
}

// ExplainConfig returns documentation for the config file schema, extracted
// from struct tags.
func ExplainConfig() []FieldDoc {
	return extractConfigFields(reflect.TypeOf(Config{}))
}

// Show returns the effective merged configuration as YAML.
func Show() (string, error) {
	cfg, err := Load()
	if err != nil {
		return "", err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshaling config: %w", err)
	}
	return string(data), nil
}

// FormatExplainConfig formats field docs as kubectl-explain-style text.
func FormatExplainConfig(fields []FieldDoc) string {
	var b strings.Builder
	b.WriteString("KIND:    Config\n\n")
	b.WriteString("DESCRIPTION:\n")
	b.WriteString("  Configuration file for gravelpit.\n")
	b.WriteString("  Location: ~/.config/gravelpit/config.yaml\n")
	b.WriteString("\nFIELDS:\n")
	formatConfigFields(&b, fields, "  ")
	return b.String()
}

func formatConfigFields(b *strings.Builder, fields []FieldDoc, indent string) {
	for _, d := range fields {
		fmt.Fprintf(b, "%s%s\t<%s>\n", indent, d.Name, d.Type)
		if d.Description != "" {
			for _, line := range wrapText(d.Description, 72) {
				fmt.Fprintf(b, "%s  %s\n", indent, line)
			}
		}
		if len(d.Children) > 0 {
			formatConfigFields(b, d.Children, indent+"  ")
		}
		b.WriteString("\n")
	}
}

func extractConfigFields(t reflect.Type) []FieldDoc {
	docs := make([]FieldDoc, 0, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)

		name := f.Tag.Get("yaml")
		if name == "" || name == "-" {
			continue
		}
		if idx := strings.Index(name, ","); idx >= 0 {
			name = name[:idx]
		}

		typeName := configTypeName(f.Type)
		desc := parseDescription(f.Tag.Get("jsonschema"))

		var children []FieldDoc
		ft := f.Type
		if ft.Kind() == reflect.Struct && ft.PkgPath() != "" {
			children = extractConfigFields(ft)
			if len(children) > 0 {
				typeName = "map"
			}
		}

		docs = append(docs, FieldDoc{
			Name:        name,
			Type:        typeName,
			Description: desc,
			Children:    children,
		})
	}
	return docs
}

func configTypeName(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if t.String() == "time.Duration" {
			return "duration"
		}
		return "integer"
	case reflect.Pointer:
		return configTypeName(t.Elem())
	case reflect.Slice:
		return "[]" + configTypeName(t.Elem())
	default:
		return t.Name()
	}
}

// parseDescription extracts the description value from a jsonschema tag.
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
