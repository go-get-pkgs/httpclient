package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/go-get-pkgs/httpclient/internal/browser"
	"github.com/go-get-pkgs/httpclient/internal/sniffer"
	"github.com/go-get-pkgs/httpclient/internal/types"
)

func main() {
	outPath := flag.String("out", "profiles/chrome_latest.json", "Путь для сохранения эталонного профиля")
	customBrowser := flag.String("browser-path", "", "Путь к конкретному браузеру (если не указан, скачивается Chrome for Testing)")
	forceDownload := flag.Bool("download-cft", true, "Принудительно скачать свежий Chrome for Testing")
	timeoutSec := flag.Int("timeout", 60, "Таймаут выполнения в секундах")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
	defer cancel()

	var browserExe string
	var chromeVersion string

	tempDir, err := os.MkdirTemp("", "cft-capture-*")
	if err != nil {
		log.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Получаем исполняемый файл браузера
	if *customBrowser != "" {
		browserExe = *customBrowser
		fmt.Printf("Using specified browser: %s\n", browserExe)
	} else if *forceDownload {
		exe, ver, err := DownloadChromeForTesting(ctx, tempDir)
		if err != nil {
			log.Fatalf("Failed to download Chrome for Testing: %v", err)
		}
		browserExe = exe
		chromeVersion = ver
		fmt.Printf("Downloaded Chrome for Testing v%s: %s\n", ver, browserExe)
	} else {
		bInfo, found := browser.FindSystemBrowser()
		if !found {
			log.Fatal("No system browser found and download is disabled")
		}
		browserExe = bInfo.Path
		fmt.Printf("Using system browser: %s\n", browserExe)
	}

	// 2. Запускаем локальный сниффер
	srv, err := sniffer.NewSnifferServer()
	if err != nil {
		log.Fatalf("Failed to start sniffer: %v", err)
	}
	defer srv.Close()

	// 3. Запускаем Chrome для зондирования
	userDataDir := filepath.Join(tempDir, "user_data")
	_ = os.MkdirAll(userDataDir, 0o755)

	// Аргументы с полной поддержкой Linux / GitHub Actions runner:
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-setuid-sandbox",
		"--disable-dev-shm-usage", // Критично для GitHub Actions / Docker
		"--test-type",             // Критично: включает работу --ignore-certificate-errors в Linux!
		"--allow-insecure-localhost",
		"--ignore-certificate-errors",
		"--disable-default-apps",
		"--disable-extensions",
		"--mute-audio",
		"--no-first-run",
		fmt.Sprintf("--user-data-dir=%s", userDataDir),
		"--dump-dom",
		srv.URL(),
	}

	cmd := exec.CommandContext(ctx, browserExe, args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	fmt.Println("Triggering browser request to local sniffer...")
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start browser: %v", err)
	}

	// 4. Перехватываем профиль
	profile, err := srv.CaptureOne(ctx)
	if err != nil {
		_ = cmd.Process.Kill()
		log.Fatalf("Failed to capture profile: %v (stderr: %s)", err, stderrBuf.String())
	}
	_ = cmd.Wait()

	// 5. Сохраняем в указанный файл
	_ = os.MkdirAll(filepath.Dir(*outPath), 0o755)
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal profile: %v", err)
	}

	if err := os.WriteFile(*outPath, data, 0o644); err != nil {
		log.Fatalf("Failed to write profile to %s: %v", *outPath, err)
	}
	fmt.Printf("Successfully captured and saved profile to %s (%d bytes)\n", *outPath, len(data))

	// 6. Если известно имя версии — сохраняем именованную копию
	if chromeVersion != "" {
		versionFile := filepath.Join(filepath.Dir(*outPath), fmt.Sprintf("chrome_%s.json", chromeVersion))
		_ = os.WriteFile(versionFile, data, 0o644)
		fmt.Printf("Also saved versioned profile to %s\n", versionFile)
	}

	// 7. Выводим красивый отчет для CI/CD
	printSummary(profile, chromeVersion)
}

func printSummary(prof *types.CapturedProfile, version string) {
	fmt.Println("\n================ CAPTURE SUMMARY ================")
	if version != "" {
		fmt.Printf("Browser Version: %s\n", version)
	}
	fmt.Printf("TLS Ciphers Count: %d\n", len(prof.TLS.CipherSuites))
	fmt.Printf("TLS Extensions Count: %d\n", len(prof.TLS.Extensions))
	if prof.HTTP2 != nil {
		fmt.Printf("HTTP/2 Settings Count: %d\n", len(prof.HTTP2.Settings))
		fmt.Printf("Pseudo-header Order: %v\n", prof.HTTP2.PseudoHeaderOrder)
	}
	fmt.Println("=================================================")

	// Если запущено внутри GitHub Actions — пишем в $GITHUB_STEP_SUMMARY
	summaryPath := os.Getenv("GITHUB_STEP_SUMMARY")
	if summaryPath == "" {
		return
	}

	md := fmt.Sprintf(`### 🛡️ Fingerprint Capture Completed
- **Version:** %s
- **Captured At:** %s
- **TLS Ciphers:** %d
- **TLS Extensions:** %d
- **HTTP/2 Settings:** %d
`, version, prof.CapturedAt.Format(time.RFC3339), len(prof.TLS.CipherSuites), len(prof.TLS.Extensions), len(prof.HTTP2.Settings))

	_ = os.WriteFile(summaryPath, []byte(md), 0o644)
}
