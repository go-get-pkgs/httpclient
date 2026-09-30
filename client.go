package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-get-pkgs/httpclient/internal/profile"
	"github.com/go-get-pkgs/httpclient/internal/transport"
	"github.com/go-get-pkgs/httpclient/internal/types"
	"github.com/go-get-pkgs/httpclient/internal/version"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// NetworkMode определяет предпочтительный сетевой протокол (IPv4 / IPv6).
type NetworkMode string

const (
	NetworkModeAuto NetworkMode = ""
	NetworkModeIPv4 NetworkMode = "ipv4"
	NetworkModeIPv6 NetworkMode = "ipv6"
)

// ClientSettings конфигурация для инициализации клиента.
type ClientSettings struct {
	Timeout              time.Duration                                      // Общий таймаут на запрос (по умолчанию 30s)
	StrictSSL            bool                                               // Проверять SSL сертификаты (true = строгая проверка)
	NetMode              NetworkMode                                        // IPv4, IPv6 или Auto
	ProxyURI             string                                             // Стартовый прокси по умолчанию
	ProxyRotator         transport.ProxyRotator                             // Пул прокси для автоматической ротации
	Browser              types.BrowserType                                  // BrowserChrome или BrowserEdge
	FollowRedirects      bool                                               // Следовать ли редиректам (по умолчанию true)
	MaxRedirects         int                                                // Максимальное количество редиректов (дефолт 10)
	CheckRedirect        func(req *http.Request, via []*http.Request) error // Кастомный обработчик редиректов
	Retry                transport.RetryConfig                              // Политика повторов (или DefaultRetryConfig)
	CacheDir             string                                             // Путь для кэширования версий (по умолчанию os.TempDir())
	ProfilePath          string                                             // Путь к файлу кэша захваченного профиля (опционально)
	ProfileCacheTTL      time.Duration                                      // Время жизни кэша отпечатка (по умолчанию 7 дней)
	RemoteManifestURLs   []string                                           // Ссылки на собственные зеркала профилей (S3 / GitHub Raw)
	GitHubRepo           string                                             // Репозиторий проекта (например "imbecility/httpclient") для автоподтягивания отпечатков
	DisableLocalProbe    bool                                               // Отключить вызов локального браузера
	DisableExternalProbe bool                                               // Отключить внешние анализаторы
	CookieJar            tlsclient.CookieJar                                // Пользовательский Jar
}

// Client — обертка над http.Client с расширенными возможностями.
type Client struct {
	*http.Client
	Jar            tlsclient.CookieJar
	BrowserVersion types.BrowserVersion
	Profile        profiles.ClientProfile
	Rotator        transport.ProxyRotator
}

// New создает готовый к работе HTTP-клиент с антидетектом и отказоустойчивой версионизацией.
func New(s ClientSettings) (*Client, error) {
	if s.Timeout <= 0 {
		s.Timeout = 30 * time.Second
	}
	if s.Browser == "" {
		s.Browser = types.BrowserChrome
	}
	if s.MaxRedirects <= 0 {
		s.MaxRedirects = 10
	}

	// 1. Определение мажорной версии и базового пресета
	_, maxCompiledMajor := profile.GetLatestChromeProfile()
	resolver := version.NewVersionResolver(s.CacheDir, maxCompiledMajor)
	dynamicVersion := resolver.GetLatestVersion()

	// 2. Автоматическое 4-уровневое получение эталонного отпечатка
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	clientProfile, finalVersion := profile.ResolveProfile(ctx, profile.ResolveConfig{
		CachePath:            s.ProfilePath,
		CacheTTL:             s.ProfileCacheTTL,
		BrowserType:          s.Browser,
		FallbackVersion:      dynamicVersion,
		GitHubRepo:           s.GitHubRepo, // Проброс репозитория
		RemoteManifestURLs:   s.RemoteManifestURLs,
		DisableLocalProbe:    s.DisableLocalProbe,
		DisableExternalProbe: s.DisableExternalProbe,
	})

	// 3. Инициализация CookieJar
	jar := s.CookieJar
	if jar == nil {
		jar = tlsclient.NewCookieJar()
	}

	// Опции для внутреннего tls-client
	timeoutSeconds := int(s.Timeout.Seconds())
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}

	// 4. Фабрика для сборки клиентов под разные прокси с единым CookieJar и Profile
	buildOptions := func(proxyURI string) []tlsclient.HttpClientOption {
		opts := []tlsclient.HttpClientOption{
			tlsclient.WithTimeoutSeconds(timeoutSeconds),
			tlsclient.WithClientProfile(clientProfile),
			tlsclient.WithRandomTLSExtensionOrder(),
			tlsclient.WithCookieJar(jar),
			tlsclient.WithProtocolRacing(),
			// Отключаем внутренние редиректы tlsclient, чтобы ими полностью
			// управлял внешний http.Client через CheckRedirect!
			tlsclient.WithNotFollowRedirects(),
		}

		switch s.NetMode {
		case NetworkModeIPv4:
			opts = append(opts, tlsclient.WithDisableIPV6())
		case NetworkModeIPv6:
			opts = append(opts, tlsclient.WithDisableIPV4())
		}

		if !s.StrictSSL {
			opts = append(opts, tlsclient.WithInsecureSkipVerify())
		}
		if proxyURI != "" {
			opts = append(opts, tlsclient.WithProxyUrl(proxyURI))
		}
		return opts
	}

	factory := func(proxyURI string) (tlsclient.HttpClient, error) {
		return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), buildOptions(proxyURI)...)
	}

	// 5. Создаем клиент по умолчанию
	defaultInner, err := factory(s.ProxyURI)
	if err != nil {
		return nil, fmt.Errorf("create base tls client: %w", err)
	}

	// 6. Формируем транспортную цепочку с пулом прокси
	headerFactory := transport.NewHeaderFactory(finalVersion, s.Browser)
	tlsTrans := transport.NewTLSTransport(defaultInner, factory, headerFactory)

	// Настройка ретраев и ротации
	retryCfg := s.Retry
	if s.ProxyRotator != nil {
		retryCfg.Rotator = s.ProxyRotator
	}

	var finalRoundTripper http.RoundTripper = tlsTrans
	if retryCfg.MaxAttempts > 0 {
		finalRoundTripper = &transport.RetryTransport{Inner: tlsTrans, Config: retryCfg}
	}

	// 7. Конфигурация редиректов
	checkRedirect := s.CheckRedirect
	if checkRedirect == nil {
		if !s.FollowRedirects && s.MaxRedirects != 0 {
			// Остановка на первом редиректе (возврат 301/302)
			checkRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		} else {
			// Стандартный лимит редиректов Go
			checkRedirect = func(req *http.Request, via []*http.Request) error {
				if len(via) >= s.MaxRedirects {
					return fmt.Errorf("stopped after %d redirects", s.MaxRedirects)
				}
				return nil
			}
		}
	}

	stdClient := &http.Client{
		Transport:     finalRoundTripper,
		CheckRedirect: checkRedirect,
		Timeout:       0,
	}

	return &Client{
		Client:         stdClient,
		Jar:            jar,
		BrowserVersion: finalVersion,
		Profile:        clientProfile,
		Rotator:        s.ProxyRotator,
	}, nil
}

// SessionState представляет сохраненное состояние сессии для экспорта/импорта.
type SessionState struct {
	Cookies        []*http.Cookie       `json:"cookies"`
	BrowserVersion types.BrowserVersion `json:"browser_version"`
	ExportedAt     time.Time            `json:"exported_at"`
}

// ExportSession сериализует все куки и состояние в JSON.
func (c *Client) ExportSession(u *url.URL) ([]byte, error) {
	cookies := c.Cookies(u)
	state := SessionState{
		Cookies:        cookies,
		BrowserVersion: c.BrowserVersion,
		ExportedAt:     time.Now(),
	}
	return json.MarshalIndent(state, "", "  ")
}

// ImportSession восстанавливает куки из сохраненного JSON.
func (c *Client) ImportSession(u *url.URL, data []byte) error {
	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("unmarshal session state: %w", err)
	}
	c.SetCookies(u, state.Cookies)
	return nil
}

// Get выполняет быстрый GET запрос.
func (c *Client) Get(ctx context.Context, targetURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// PostJSON отправляет POST запрос с JSON структурой.
func (c *Client) PostJSON(ctx context.Context, targetURL string, payload any) (*http.Response, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal json payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.Do(req)
}

// GetString выполняет GET запрос и возвращает тело ответа в виде строки.
func (c *Client) GetString(ctx context.Context, targetURL string) (string, int, error) {
	resp, err := c.Get(ctx, targetURL)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("read response body: %w", err)
	}
	return string(body), resp.StatusCode, nil
}

// Cookies возвращает сохраненные куки для указанного URL в стандартном формате net/http.
func (c *Client) Cookies(u *url.URL) []*http.Cookie {
	if c.Jar == nil || u == nil {
		return nil
	}

	fCookies := c.Jar.Cookies(u)
	if len(fCookies) == 0 {
		return nil
	}

	netCookies := make([]*http.Cookie, len(fCookies))
	for i, fc := range fCookies {
		netCookies[i] = &http.Cookie{
			Name:       fc.Name,
			Value:      fc.Value,
			Path:       fc.Path,
			Domain:     fc.Domain,
			Expires:    fc.Expires,
			RawExpires: fc.RawExpires,
			MaxAge:     fc.MaxAge,
			Secure:     fc.Secure,
			HttpOnly:   fc.HttpOnly,
			SameSite:   http.SameSite(fc.SameSite),
			Raw:        fc.Raw,
			Unparsed:   fc.Unparsed,
		}
	}
	return netCookies
}

// SetCookies сохраняет net/http куки в Jar клиента.
func (c *Client) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if c.Jar == nil || u == nil || len(cookies) == 0 {
		return
	}

	fCookies := make([]*fhttp.Cookie, len(cookies))
	for i, nc := range cookies {
		fCookies[i] = &fhttp.Cookie{
			Name:       nc.Name,
			Value:      nc.Value,
			Path:       nc.Path,
			Domain:     nc.Domain,
			Expires:    nc.Expires,
			RawExpires: nc.RawExpires,
			MaxAge:     nc.MaxAge,
			Secure:     nc.Secure,
			HttpOnly:   nc.HttpOnly,
			SameSite:   fhttp.SameSite(nc.SameSite),
			Raw:        nc.Raw,
			Unparsed:   nc.Unparsed,
		}
	}
	c.Jar.SetCookies(u, fCookies)
}
