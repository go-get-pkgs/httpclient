package httpclient

import (
	"github.com/go-get-pkgs/httpclient/internal/browser"
	"github.com/go-get-pkgs/httpclient/internal/transport"
	"github.com/go-get-pkgs/httpclient/internal/types"
)

// Реэкспорт базовых типов
type (
	BrowserType            = types.BrowserType
	BrowserVersion         = types.BrowserVersion
	BrowserInfo            = types.BrowserInfo
	CapturedProfile        = types.CapturedProfile
	TLSFingerprint         = types.TLSFingerprint
	HTTP2Fingerprint       = types.HTTP2Fingerprint
	RetryConfig            = transport.RetryConfig
	ProxyRotator           = transport.ProxyRotator
	RoundRobinProxyRotator = transport.RoundRobinProxyRotator
)

const (
	BrowserChrome = types.BrowserChrome
	BrowserEdge   = types.BrowserEdge
)

// DefaultRetryConfig реэкспортируем готовую конфигурацию ретраев
var DefaultRetryConfig = transport.DefaultRetryConfig

// WithProxy прикрепляет прокси к контексту конкретного запроса
var WithProxy = transport.WithProxy

// NewRoundRobinProxyRotator создает пул прокси с round-robin ротацией
var NewRoundRobinProxyRotator = transport.NewRoundRobinProxyRotator

// ProbeLocalBrowser выносим как публичную функцию для тестов/диагностики
var ProbeLocalBrowser = browser.ProbeLocalBrowser
