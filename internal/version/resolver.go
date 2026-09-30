package version

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-get-pkgs/httpclient/internal/types"
)

const (
	googleAPIURL        = "https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions/all/releases"
	chromeForTestingURL = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
	msEdgeRepoURL       = "https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-stable"

	defaultCacheFileName = "httpclient_versions.json"
	defaultCacheTTL      = 7 * 24 * time.Hour
)

var msEdgeVersionRegex = regexp.MustCompile(
	`<a href="([^"]+\.deb)">[^<]+</a>\s+(\d{1,2}-[A-Za-z]{3}-\d{4})\s+(\d{1,2}:\d{2})`,
)

type cacheFile struct {
	Timestamp time.Time `json:"timestamp"`
	Versions  []string  `json:"versions"`
}

type VersionResolver struct {
	httpClient    *http.Client
	cachePath     string
	cacheTTL      time.Duration
	maxDriftMajor int
	mu            sync.RWMutex
	versions      []string
}

// NewVersionResolver создает отказоустойчивый резолвер версий.
func NewVersionResolver(cacheDir string, maxDriftMajor int) *VersionResolver {
	if cacheDir == "" {
		cacheDir = os.TempDir()
	}
	return &VersionResolver{
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		cachePath:     filepath.Join(cacheDir, defaultCacheFileName),
		cacheTTL:      defaultCacheTTL,
		maxDriftMajor: maxDriftMajor,
	}
}

// GetLatestVersion возвращает актуальную версию браузера с защитой от рассинхрона.
func (r *VersionResolver) GetLatestVersion() types.BrowserVersion {
	r.mu.RLock()
	if len(r.versions) > 0 {
		v := r.versions[0]
		r.mu.RUnlock()
		return parseBrowserVersion(v, r.maxDriftMajor)
	}
	r.mu.RUnlock()

	// 1. Чтение из дискового кэша
	if r.loadFromDiskCache() {
		return parseBrowserVersion(r.versions[0], r.maxDriftMajor)
	}

	// 2. Сетевая гонка или математика
	_ = r.updateVersions()

	if r.cachePath != "" {
		r.saveToDiskCache()
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	return parseBrowserVersion(r.versions[0], r.maxDriftMajor)
}

func (r *VersionResolver) updateVersions() error {
	ctx, cancel := context.WithTimeout(context.Background(), r.httpClient.Timeout)
	defer cancel()

	resultsChan := make(chan []string, 3)
	var wg sync.WaitGroup
	wg.Add(3)

	// Источник 1: Google Version History API
	go func() {
		defer wg.Done()
		if vers, err := r.fetchGoogleVersions(ctx); err == nil && len(vers) > 0 {
			select {
			case resultsChan <- vers:
			case <-ctx.Done():
			}
		}
	}()

	// Источник 2: Chrome for Testing JSON
	go func() {
		defer wg.Done()
		if vers, err := r.fetchChromeForTesting(ctx); err == nil && len(vers) > 0 {
			select {
			case resultsChan <- vers:
			case <-ctx.Done():
			}
		}
	}()

	// Источник 3: Microsoft Edge Repo
	go func() {
		defer wg.Done()
		if vers, err := r.fetchMicrosoftVersions(ctx); err == nil && len(vers) > 0 {
			select {
			case resultsChan <- vers:
			case <-ctx.Done():
			}
		}
	}()

	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()

	select {
	case vers := <-resultsChan:
		r.mu.Lock()
		r.versions = vers
		r.mu.Unlock()
		return nil
	case <-allDone:
	case <-ctx.Done():
	}

	// 3. Фоллбэк на календарную математику, если сеть легла
	r.mu.Lock()
	r.versions = r.approximateVersions()
	r.mu.Unlock()
	return nil
}

func (r *VersionResolver) fetchGoogleVersions(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleAPIURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d", resp.StatusCode)
	}

	var data struct {
		Releases []struct {
			Version string `json:"version"`
		} `json:"releases"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var out []string
	for _, rel := range data.Releases {
		if rel.Version != "" {
			out = append(out, rel.Version)
		}
	}
	return out, nil
}

func (r *VersionResolver) fetchChromeForTesting(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, chromeForTestingURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d", resp.StatusCode)
	}

	var data struct {
		Channels struct {
			Stable struct {
				Version string `json:"version"`
			} `json:"Stable"`
		} `json:"channels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	if data.Channels.Stable.Version != "" {
		return []string{data.Channels.Stable.Version}, nil
	}
	return nil, errors.New("empty version in chrome for testing")
}

func (r *VersionResolver) fetchMicrosoftVersions(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, msEdgeRepoURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	matches := msEdgeVersionRegex.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		return nil, errors.New("no regex match")
	}

	var out []string
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		ver := strings.TrimPrefix(match[1], "microsoft-edge-stable_")
		ver = strings.TrimSuffix(ver, "_amd64.deb")
		ver = strings.TrimSuffix(ver, "-1")
		out = append(out, ver)
	}
	return out, nil
}

func (r *VersionResolver) approximateVersions() []string {
	t0 := time.Date(2025, 5, 14, 0, 0, 0, 0, time.UTC)
	t := time.Now().Sub(t0).Hours() / 24

	M := 136 + (t / 31)
	knownBuild := map[int]float64{136: 7103, 137: 7151, 138: 7204, 139: 7258}
	B := 0.0
	if build, ok := knownBuild[int(M)]; ok {
		B = build
	} else {
		B = 7103 + 52*(M-136)
	}
	p := math.Round(0.88*t + 62.55)

	return []string{fmt.Sprintf("%d.0.%d.%d", int(M), int(B), int(p))}
}

func parseBrowserVersion(full string, maxCompiledMajor int) types.BrowserVersion {
	parts := strings.Split(full, ".")
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		major = 154 // безопасный дефолт
	}

	// Drift Clamp: если вычисленная версия опережает скомпилированный профиль
	// больше чем на 3 версии, ограничиваем мажор, чтобы не получить бан за расхождение с TLS
	if maxCompiledMajor > 0 && major > maxCompiledMajor+3 {
		major = maxCompiledMajor + 3
		p1, p2 := "0", "0"
		if len(parts) > 1 {
			p1 = parts[1]
		}
		if len(parts) > 2 {
			p2 = parts[2]
		}
		full = fmt.Sprintf("%d.0.%s.%s", major, p1, p2)
	}

	return types.BrowserVersion{
		FullVersion:  full,
		MajorVersion: major,
	}
}

func (r *VersionResolver) loadFromDiskCache() bool {
	data, err := os.ReadFile(r.cachePath)
	if err != nil {
		return false
	}
	var cache cacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return false
	}
	if time.Since(cache.Timestamp) > r.cacheTTL || len(cache.Versions) == 0 {
		return false
	}
	r.mu.Lock()
	r.versions = cache.Versions
	r.mu.Unlock()
	return true
}

func (r *VersionResolver) saveToDiskCache() {
	r.mu.RLock()
	vers := r.versions
	r.mu.RUnlock()
	if len(vers) == 0 {
		return
	}

	data, err := json.Marshal(cacheFile{Timestamp: time.Now(), Versions: vers})
	if err != nil {
		return
	}

	dir := filepath.Dir(r.cachePath)
	_ = os.MkdirAll(dir, 0o755)
	tmp, err := os.CreateTemp(dir, "ver-*.tmp")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return
	}
	_ = tmp.Close()
	_ = os.Rename(tmp.Name(), r.cachePath)
}
