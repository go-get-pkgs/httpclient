//go:build !windows

package browser

import "os/exec"

func prepareBackgroundCommand(cmd *exec.Cmd) {
	// на Linux / macOS дополнительных флагов подавления не требуется
}
