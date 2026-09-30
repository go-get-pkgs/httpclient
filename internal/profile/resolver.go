// ./internal/profile/resolver.go
package profile

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/go-get-pkgs/httpclient/internal/browser"
	"github.com/go-get-pkgs/httpclient/internal/probes"
	"github.com/go-get-pkgs/httpclient/internal/types"

	"github.com/bogdanfinn/tls-client/profiles"
)

// ResolveConfig содержит настройки для каскадного получения отпечатка.
type ResolveConfig struct {
	CachePath            string
	CacheTTL             time.Duration
	BrowserType          types.BrowserType
	FallbackVersion      types.BrowserVersion
	GitHubRepo           string // Репозиторий проекта, например "imbecility/httpclient"
	RemoteManifestURLs   []string
	DisableLocalProbe    bool
	DisableExternalProbe bool
}

// ResolveProfile выполняет 5-уровневый каскадный поиск эталонного профиля.
func ResolveProfile(ctx context.Context, cfg ResolveConfig) (profiles.ClientProfile, types.BrowserVersion) {
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 7 * 24 * time.Hour
	}
	if cfg.CachePath == "" {
		cfg.CachePath = filepath.Join(os.TempDir(), "httpclient_captured_profile.json")
	}

	// -------------------------------------------------------------
	// УРОВЕНЬ 1: Проверка дискового кэша
	// -------------------------------------------------------------
	if capProfile, ok := LoadCapturedProfile(cfg.CachePath, cfg.CacheTTL); ok {
		if prof, ver, err := BuildClientProfile(capProfile, cfg.BrowserType, cfg.FallbackVersion); err == nil {
			return prof, ver
		}
	}

	// -------------------------------------------------------------
	// УРОВЕНЬ 2: Локальный сниффер через браузер хоста (без сети)
	// -------------------------------------------------------------
	if !cfg.DisableLocalProbe {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		capProfile, _, err := browser.ProbeLocalBrowser(probeCtx)
		cancel()

		if err == nil && capProfile != nil {
			_ = SaveCapturedProfile(cfg.CachePath, capProfile)
			if prof, ver, err := BuildClientProfile(capProfile, cfg.BrowserType, cfg.FallbackVersion); err == nil {
				return prof, ver
			}
		}

		// ---------------------------------------------------------
		// УРОВЕНЬ 3: Резервный CDP-зонд (если сокет сниффера заблокирован брандмауэром)
		// ---------------------------------------------------------
		cdpCtx, cdpCancel := context.WithTimeout(ctx, 8*time.Second)
		capProfile, _, err = browser.ProbeLocalBrowserCDP(cdpCtx, "")
		cdpCancel()

		if err == nil && capProfile != nil {
			_ = SaveCapturedProfile(cfg.CachePath, capProfile)
			if prof, ver, err := BuildClientProfile(capProfile, cfg.BrowserType, cfg.FallbackVersion); err == nil {
				return prof, ver
			}
		}
	}

	// -------------------------------------------------------------
	// УРОВЕНЬ 4: Репозиторий GitHub (коммиты/релизы) + пул анализаторов
	// -------------------------------------------------------------
	if !cfg.DisableExternalProbe {
		// 4а. Пытаемся забрать отпечаток из нашего GitHub репозитория
		if cfg.GitHubRepo != "" {
			ghProvider := probes.NewGitHubProfileProvider(cfg.GitHubRepo)
			ghCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if capProfile, err := ghProvider.FetchProfile(ghCtx); err == nil && capProfile != nil {
				cancel()
				_ = SaveCapturedProfile(cfg.CachePath, capProfile)
				if prof, ver, err := BuildClientProfile(capProfile, cfg.BrowserType, cfg.FallbackVersion); err == nil {
					return prof, ver
				}
			}
			cancel()
		}

		// 4б. Пул внешних независимых анализаторов (BrowserLeaks / PeetWS)
		probeCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		extProvider := probes.NewExternalProbeProvider(cfg.RemoteManifestURLs...)
		capProfile, err := extProvider.FetchCapturedProfile(probeCtx)
		cancel()

		if err == nil && capProfile != nil {
			_ = SaveCapturedProfile(cfg.CachePath, capProfile)
			if prof, ver, err := BuildClientProfile(capProfile, cfg.BrowserType, cfg.FallbackVersion); err == nil {
				return prof, ver
			}
		}
	}

	// -------------------------------------------------------------
	// УРОВЕНЬ 5: Вкомпилированный пресет (гарантия старта при изоляции)
	// -------------------------------------------------------------
	baseProfile, _ := GetLatestChromeProfile()
	return baseProfile, cfg.FallbackVersion
}
