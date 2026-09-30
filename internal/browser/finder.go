package browser

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/go-get-pkgs/httpclient/internal/types"
)

// FindSystemBrowser выполняет скрупулезный поиск установленного браузера в ОС.
func FindSystemBrowser() (*types.BrowserInfo, bool) {
	switch runtime.GOOS {
	case "windows":
		return findWindowsBrowser()
	case "darwin":
		return findDarwinBrowser()
	default:
		return findLinuxBrowser()
	}
}

func findWindowsBrowser() (*types.BrowserInfo, bool) {
	localAppData := os.Getenv("LOCALAPPDATA")
	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")

	candidates := []struct {
		path  string
		bType types.BrowserType
	}{
		{filepath.Join(programFiles, "Google", "Chrome", "Application", "chrome.exe"), types.BrowserChrome},
		{filepath.Join(programFilesX86, "Google", "Chrome", "Application", "chrome.exe"), types.BrowserChrome},
		{filepath.Join(localAppData, "Google", "Chrome", "Application", "chrome.exe"), types.BrowserChrome},

		{filepath.Join(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe"), types.BrowserEdge},
		{filepath.Join(programFiles, "Microsoft", "Edge", "Application", "msedge.exe"), types.BrowserEdge},

		{filepath.Join(localAppData, "Chromium", "Application", "chrome.exe"), types.BrowserChrome},
	}

	for _, c := range candidates {
		if fileExists(c.path) {
			return &types.BrowserInfo{Path: c.path, Type: c.bType}, true
		}
	}

	// Попытка через PATH
	if p, err := exec.LookPath("chrome.exe"); err == nil {
		return &types.BrowserInfo{Path: p, Type: types.BrowserChrome}, true
	}
	if p, err := exec.LookPath("msedge.exe"); err == nil {
		return &types.BrowserInfo{Path: p, Type: types.BrowserEdge}, true
	}

	return nil, false
}

func findLinuxBrowser() (*types.BrowserInfo, bool) {
	commands := []struct {
		cmd   string
		bType types.BrowserType
	}{
		{"google-chrome-stable", types.BrowserChrome},
		{"google-chrome", types.BrowserChrome},
		{"chromium-browser", types.BrowserChrome},
		{"chromium", types.BrowserChrome},
		{"microsoft-edge-stable", types.BrowserEdge},
		{"microsoft-edge", types.BrowserEdge},
	}

	for _, c := range commands {
		if path, err := exec.LookPath(c.cmd); err == nil {
			return &types.BrowserInfo{Path: path, Type: c.bType}, true
		}
	}

	fixedPaths := []struct {
		path  string
		bType types.BrowserType
	}{
		{"/usr/bin/google-chrome", types.BrowserChrome},
		{"/usr/bin/chromium", types.BrowserChrome},
		{"/usr/bin/chromium-browser", types.BrowserChrome},
		{"/snap/bin/chromium", types.BrowserChrome},
		{"/opt/google/chrome/chrome", types.BrowserChrome},
		{"/usr/bin/microsoft-edge", types.BrowserEdge},
	}

	for _, f := range fixedPaths {
		if fileExists(f.path) {
			return &types.BrowserInfo{Path: f.path, Type: f.bType}, true
		}
	}

	return nil, false
}

func findDarwinBrowser() (*types.BrowserInfo, bool) {
	candidates := []struct {
		path  string
		bType types.BrowserType
	}{
		{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", types.BrowserChrome},
		{"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", types.BrowserEdge},
		{"/Applications/Chromium.app/Contents/MacOS/Chromium", types.BrowserChrome},
	}

	for _, c := range candidates {
		if fileExists(c.path) {
			return &types.BrowserInfo{Path: c.path, Type: c.bType}, true
		}
	}
	return nil, false
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
