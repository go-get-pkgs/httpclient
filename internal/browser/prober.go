package browser

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/go-get-pkgs/httpclient/internal/sniffer"
	"github.com/go-get-pkgs/httpclient/internal/types"
)

// ProbeLocalBrowser выполняет скрытый захват отпечатка через установленный в ОС браузер.
func ProbeLocalBrowser(ctx context.Context) (*types.CapturedProfile, *types.BrowserInfo, error) {
	browser, found := FindSystemBrowser()
	if !found {
		return nil, nil, fmt.Errorf("no supported browser found on host")
	}

	// 1. Запускаем локальный сниффер
	srv, err := sniffer.NewSnifferServer()
	if err != nil {
		return nil, nil, fmt.Errorf("start sniffer: %w", err)
	}
	defer srv.Close()

	// 2. Создаем изолированную директорию профиля
	tmpUserDataDir, err := os.MkdirTemp("", "httpclient-probe-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create temp profile: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpUserDataDir)
	}()

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// 3. Исправленный список аргументов:
	// - `--allow-insecure-localhost` разрешает наш сертификат
	// - `--dump-dom` идет отдельно
	// - URL идет последним позиционным параметром
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-setuid-sandbox",
		"--disable-dev-shm-usage",
		"--test-type",
		"--allow-insecure-localhost",
		"--ignore-certificate-errors",
		"--disable-default-apps",
		"--disable-extensions",
		"--mute-audio",
		"--no-first-run",
		fmt.Sprintf("--user-data-dir=%s", tmpUserDataDir),
		"--dump-dom",
		srv.URL(), // URL идет отдельным позиционным аргументом!
	}

	cmd := exec.CommandContext(probeCtx, browser.Path, args...)

	// Захватываем вывод ошибок браузера на случай проблем с запуском
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	prepareBackgroundCommand(cmd)

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start browser process: %w", err)
	}

	// 4. Ожидаем перехвата запроса в сниффере
	profile, err := srv.CaptureOne(probeCtx)
	if err != nil {
		_ = cmd.Process.Kill()
		errMsg := stderrBuf.String()
		if len(errMsg) > 0 {
			return nil, nil, fmt.Errorf("capture probe: %w (browser stderr: %s)", err, errMsg)
		}
		return nil, nil, fmt.Errorf("capture probe: %w", err)
	}

	// Дожидаемся завершения процесса
	_ = cmd.Wait()

	return profile, browser, nil
}
