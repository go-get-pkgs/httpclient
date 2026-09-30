//go:build windows

package browser

import (
	"os/exec"
	"syscall"
)

func prepareBackgroundCommand(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// CREATE_NO_WINDOW = 0x08000000 (окно консоли не всплывает)
	cmd.SysProcAttr.CreationFlags = 0x08000000
	cmd.SysProcAttr.HideWindow = true
}
