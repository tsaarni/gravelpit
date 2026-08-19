// Tests for audit logger creation and level validation.
package audit

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/tsaarni/gravelpit/pkg/schema"
)

func TestNewRejectsInvalidLevel(t *testing.T) {
	tests := []struct {
		level   string
		wantErr bool
	}{
		{"all", false},
		{"denials", false},
		{"", true},
		{"invalid", true},
		{"ALL", true},
		{"everything", true},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			dir := t.TempDir()
			l, err := New(dir+"/audit.jsonl", tt.level)
			if tt.wantErr {
				if err == nil {
					l.Close()
					t.Fatalf("New(%q) = nil error, want error", tt.level)
				}
			} else {
				if err != nil {
					t.Fatalf("New(%q) = %v, want nil", tt.level, err)
				}
				l.Close()
			}
		})
	}
}

func TestLevelFiltering(t *testing.T) {
	allow := &schema.AuditRecord{
		Timestamp: time.Now().UTC(),
		Event:     schema.Event{Action: schema.ActionRead},
		Verdict:   schema.VerdictAllow,
	}
	deny := &schema.AuditRecord{
		Timestamp: time.Now().UTC(),
		Event:     schema.Event{Action: schema.ActionWrite},
		Verdict:   schema.VerdictDeny,
	}

	tests := []struct {
		name      string
		level     string
		wantCount int
	}{
		{"all logs everything", "all", 2},
		{"denials skips allows", "denials", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := t.TempDir() + "/audit.jsonl"
			l, err := New(path, tt.level)
			if err != nil {
				t.Fatal(err)
			}
			l.Log(allow)
			l.Log(deny)
			l.Close()

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			var count int
			for _, line := range splitLines(data) {
				if len(line) == 0 {
					continue
				}
				var rec schema.AuditRecord
				if err := json.Unmarshal(line, &rec); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				count++
			}

			if count != tt.wantCount {
				t.Fatalf("got %d records, want %d", count, tt.wantCount)
			}
		})
	}
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
