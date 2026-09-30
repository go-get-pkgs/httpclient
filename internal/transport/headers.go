package transport

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-get-pkgs/httpclient/internal/types"

	fhttp "github.com/bogdanfinn/fhttp"
)

// RequestType определяет контекст запроса для формирования Sec-Fetch заголовков.
type RequestType int

const (
	RequestTypeNavigate RequestType = iota // переход пользователя на HTML страницу
	RequestTypeFetch                       // AJAX / Fetch / API запрос (JSON, subresource)
)

// HeaderFactory генерирует согласованные заголовки под конкретную версию браузера.
type HeaderFactory struct {
	version     types.BrowserVersion
	browserType types.BrowserType
	platform    string // "Windows"
}

// NewHeaderFactory создает новую фабрику заголовков для сессии.
func NewHeaderFactory(ver types.BrowserVersion, bType types.BrowserType) *HeaderFactory {
	if bType == "" {
		bType = types.BrowserChrome
	}
	return &HeaderFactory{
		version:     ver,
		browserType: bType,
		platform:    "Windows",
	}
}

// UserAgent возвращает строку User-Agent.
func (h *HeaderFactory) UserAgent() string {
	if h.browserType == types.BrowserEdge {
		return fmt.Sprintf(
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36 Edg/%s",
			h.version.FullVersion, h.version.FullVersion,
		)
	}
	return fmt.Sprintf(
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
		h.version.FullVersion,
	)
}

// SecChUa формирует значение заголовка sec-ch-ua.
func (h *HeaderFactory) SecChUa() string {
	major := h.version.MajorVersion
	if h.browserType == types.BrowserEdge {
		return fmt.Sprintf(`"Microsoft Edge";v="%d", "Chromium";v="%d", "Not_A Brand";v="24"`, major, major)
	}
	return fmt.Sprintf(`"Google Chrome";v="%d", "Chromium";v="%d", "Not_A Brand";v="24"`, major, major)
}

// ApplyHeaders накладывает браузерные заголовки и строгий порядок следования на fhttp.Request.
func (h *HeaderFactory) ApplyHeaders(fReq *fhttp.Request, stdReq *http.Request) {
	// Определяем тип запроса
	reqType := RequestTypeNavigate
	accept := stdReq.Header.Get("Accept")
	contentType := stdReq.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") ||
		strings.Contains(accept, "application/json") ||
		stdReq.Method == http.MethodPost ||
		stdReq.Method == http.MethodPut ||
		stdReq.Method == http.MethodPatch {
		reqType = RequestTypeFetch
	}

	// 1. Базовые Low-Entropy заголовки браузера
	fReq.Header.Set("sec-ch-ua", h.SecChUa())
	fReq.Header.Set("sec-ch-ua-mobile", "?0")
	fReq.Header.Set("sec-ch-ua-platform", fmt.Sprintf(`"%s"`, h.platform))
	fReq.Header.Set("user-agent", h.UserAgent())
	fReq.Header.Set("accept-encoding", "gzip, deflate, br, zstd")
	fReq.Header.Set("accept-language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")

	if reqType == RequestTypeNavigate {
		fReq.Header.Set("upgrade-insecure-requests", "1")
		if accept == "" {
			fReq.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		} else {
			fReq.Header.Set("accept", accept)
		}
		fReq.Header.Set("sec-fetch-site", "none")
		fReq.Header.Set("sec-fetch-mode", "navigate")
		fReq.Header.Set("sec-fetch-user", "?1")
		fReq.Header.Set("sec-fetch-dest", "document")
		fReq.Header.Set("priority", "u=0, i")
	} else {
		// AJAX / Fetch запрос
		if accept == "" {
			fReq.Header.Set("accept", "*/*")
		} else {
			fReq.Header.Set("accept", accept)
		}
		fReq.Header.Set("sec-fetch-site", "same-origin")
		fReq.Header.Set("sec-fetch-mode", "cors")
		fReq.Header.Set("sec-fetch-dest", "empty")
		fReq.Header.Set("priority", "u=1, i")
	}

	// 2. Перенос пользовательских заголовков из stdReq (с перезаписью, а не дублированием!)
	for k, vv := range stdReq.Header {
		lowerK := strings.ToLower(k)
		// Пропускаем псевдо-заголовки или те, что мы уже тонко настроили, если пользователь их явно не переопределил
		fReq.Header.Del(lowerK)
		for _, v := range vv {
			fReq.Header.Add(lowerK, v)
		}
	}

	// 3. Детерминированный порядок следования заголовков (JA4H)
	fReq.Header[fhttp.HeaderOrderKey] = []string{
		"host",
		"connection",
		"content-length",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"upgrade-insecure-requests",
		"user-agent",
		"content-type",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"accept-language",
		"cookie",
		"priority",
	}

	// 4. Порядок псевдо-заголовков HTTP/2
	fReq.Header[fhttp.PHeaderOrderKey] = []string{
		":method",
		":authority",
		":scheme",
		":path",
	}
}
