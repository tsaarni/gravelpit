// cgroup.go creates and manages cgroup v2 groups for sandboxes.
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
)

const cgroupBase = "/sys/fs/cgroup"

// CgroupCreate creates a cgroup v2 group for a sandbox.
// Returns the cgroup path (e.g. /sys/fs/cgroup/gravelpit/sandbox-abc123).
// The gravelpit parent cgroup is created if it does not already exist.
func CgroupCreate(sandboxID string) (string, error) {
	parent := filepath.Join(cgroupBase, "gravelpit")
	if err := os.MkdirAll(parent, 0755); err != nil {
		return "", fmt.Errorf("creating gravelpit cgroup: %w", err)
	}

	cgPath := filepath.Join(parent, "sandbox-"+sandboxID)
	if err := os.Mkdir(cgPath, 0755); err != nil {
		return "", fmt.Errorf("creating sandbox cgroup: %w", err)
	}

	return cgPath, nil
}

// CgroupAddPid adds a process to the sandbox's cgroup by writing to cgroup.procs.
func CgroupAddPid(cgroupPath string, pid int) error {
	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	data := fmt.Sprintf("%d\n", pid)
	if err := os.WriteFile(procsPath, []byte(data), 0); err != nil {
		return fmt.Errorf("adding pid %d to cgroup: %w", pid, err)
	}
	return nil
}

// CgroupKill kills all processes in the cgroup by writing 1 to cgroup.kill.
func CgroupKill(cgroupPath string) error {
	killPath := filepath.Join(cgroupPath, "cgroup.kill")
	if err := os.WriteFile(killPath, []byte("1\n"), 0); err != nil {
		return fmt.Errorf("killing cgroup: %w", err)
	}
	return nil
}

// CgroupRemove removes the cgroup directory. The cgroup must be empty
// (no live processes) before it can be removed.
func CgroupRemove(cgroupPath string) error {
	if err := os.Remove(cgroupPath); err != nil {
		return fmt.Errorf("removing cgroup: %w", err)
	}
	return nil
}
