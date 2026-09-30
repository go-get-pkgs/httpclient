package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const cftVersionsURL = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"

type cftResponse struct {
	Channels struct {
		Stable struct {
			Version   string `json:"version"`
			Downloads struct {
				Chrome []struct {
					Platform string `json:"platform"`
					URL      string `json:"url"`
				} `json:"chrome"`
			} `json:"downloads"`
		} `json:"Stable"`
	} `json:"channels"`
}

// DownloadChromeForTesting скачивает официальный релиз Chrome for Testing с CDN Google и возвращает путь к бинарнику.
func DownloadChromeForTesting(ctx context.Context, destDir string) (string, string, error) {
	platform := resolvePlatformKey()
	if platform == "" {
		return "", "", fmt.Errorf("unsupported OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// 1. Узнаем ссылку на скачивание
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cftVersionsURL, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var data cftResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", "", fmt.Errorf("decode cft json: %w", err)
	}

	downloadURL := ""
	version := data.Channels.Stable.Version
	for _, item := range data.Channels.Stable.Downloads.Chrome {
		if item.Platform == platform {
			downloadURL = item.URL
			break
		}
	}

	if downloadURL == "" {
		return "", "", fmt.Errorf("no download URL found for platform %q", platform)
	}

	// 2. Скачиваем zip архив
	fmt.Printf("Downloading Chrome for Testing v%s for %s ...\n", version, platform)
	zipPath := filepath.Join(destDir, "chrome.zip")
	if err := downloadFile(ctx, downloadURL, zipPath); err != nil {
		return "", "", fmt.Errorf("download zip: %w", err)
	}
	defer os.Remove(zipPath)

	// 3. Распаковываем архив
	fmt.Println("Extracting archive...")
	extractedDir := filepath.Join(destDir, "extracted")
	if err := unzip(zipPath, extractedDir); err != nil {
		return "", "", fmt.Errorf("unzip: %w", err)
	}

	// 4. Находим исполняемый файл
	chromeExe := findExecutable(extractedDir)
	if chromeExe == "" {
		return "", "", errors.New("chrome binary not found in extracted archive")
	}

	_ = os.Chmod(chromeExe, 0o755)
	return chromeExe, version, nil
}

func resolvePlatformKey() string {
	switch runtime.GOOS {
	case "linux":
		return "linux64"
	case "windows":
		if runtime.GOARCH == "arm64" {
			return "win64"
		}
		return "win64"
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return "mac-arm64"
		}
		return "mac-x64"
	default:
		return ""
	}
}

func downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status: %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func findExecutable(root string) string {
	var target string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		name := strings.ToLower(info.Name())
		if name == "chrome" || name == "chrome.exe" || name == "google chrome" {
			target = p
			return filepath.SkipAll
		}
		return nil
	})
	return target
}
