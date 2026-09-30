// ./internal/probes/github.go
package probes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-get-pkgs/httpclient/internal/types"
)

// GitHubProfileProvider забирает актуальные слепки напрямую из репозитория проекта.
type GitHubProfileProvider struct {
	owner      string
	repo       string
	branch     string
	profileRel string // относительный путь, например "profiles/chrome_latest.json"
	httpClient *http.Client
}

// NewGitHubProfileProvider создает провайдер для указанного репозитория.
func NewGitHubProfileProvider(repoFullName string) *GitHubProfileProvider {
	parts := strings.Split(repoFullName, "/")
	owner := "your-org"
	repo := "httpclient"
	if len(parts) == 2 {
		owner = parts[0]
		repo = parts[1]
	}

	return &GitHubProfileProvider{
		owner:      owner,
		repo:       repo,
		branch:     "main",
		profileRel: "profiles/chrome_latest.json",
		httpClient: &http.Client{Timeout: 8 * time.Second},
	}
}

// FetchProfile пробует скачать отпечаток сначала из Raw-файла ветки, затем из Latest Release.
func (g *GitHubProfileProvider) FetchProfile(ctx context.Context) (*types.CapturedProfile, error) {
	// 1. Попытка через GitHub Raw (самый быстрый путь)
	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s",
		g.owner, g.repo, g.branch, g.profileRel)

	if prof, err := g.fetchJSON(ctx, rawURL); err == nil && prof != nil {
		return prof, nil
	}

	// 2. Попытка через GitHub Releases API
	releaseAssetURL, err := g.getLatestReleaseAssetURL(ctx)
	if err == nil && releaseAssetURL != "" {
		if prof, err := g.fetchJSON(ctx, releaseAssetURL); err == nil && prof != nil {
			return prof, nil
		}
	}

	return nil, errors.New("failed to fetch profile from github repository")
}

func (g *GitHubProfileProvider) fetchJSON(ctx context.Context, url string) (*types.CapturedProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "httpclient-sync-engine")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d", resp.StatusCode)
	}

	var prof types.CapturedProfile
	if err := json.NewDecoder(resp.Body).Decode(&prof); err != nil {
		return nil, err
	}

	if prof.TLS == nil || len(prof.TLS.CipherSuites) == 0 {
		return nil, errors.New("empty profile payload")
	}

	return &prof, nil
}

func (g *GitHubProfileProvider) getLatestReleaseAssetURL(ctx context.Context) (string, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", g.owner, g.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "httpclient-sync-engine")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("release api status: %d", resp.StatusCode)
	}

	var data struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}

	for _, a := range data.Assets {
		if strings.HasSuffix(a.Name, ".json") && (strings.Contains(a.Name, "profile") || strings.Contains(a.Name, "chrome")) {
			return a.BrowserDownloadURL, nil
		}
	}

	return "", errors.New("no json profile asset found in release")
}
