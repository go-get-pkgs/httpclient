package transport

import (
	"fmt"
	"net/http"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

// ClientFactory создает новый инстанс tlsclient.HttpClient под указанный прокси.
type ClientFactory func(proxyURI string) (tlsclient.HttpClient, error)

// TLSTransport реализует http.RoundTripper с поддержкой пула прокси
// и гарантирует консистентность браузерного отпечатка.
type TLSTransport struct {
	defaultClient tlsclient.HttpClient
	factory       ClientFactory
	headers       *HeaderFactory
	poolMu        sync.RWMutex
	clientPool    map[string]tlsclient.HttpClient
}

// NewTLSTransport создает транспорт с поддержкой пула прокси.
func NewTLSTransport(defaultClient tlsclient.HttpClient, factory ClientFactory, headers *HeaderFactory) *TLSTransport {
	return &TLSTransport{
		defaultClient: defaultClient,
		factory:       factory,
		headers:       headers,
		clientPool:    make(map[string]tlsclient.HttpClient),
	}
}

// getClientForProxy возвращает клиент под конкретный прокси из пула или создает новый.
func (t *TLSTransport) getClientForProxy(proxyURI string) (tlsclient.HttpClient, error) {
	if proxyURI == "" {
		return t.defaultClient, nil
	}

	t.poolMu.RLock()
	client, exists := t.clientPool[proxyURI]
	t.poolMu.RUnlock()
	if exists {
		return client, nil
	}

	t.poolMu.Lock()
	defer t.poolMu.Unlock()

	// Double check
	if client, exists = t.clientPool[proxyURI]; exists {
		return client, nil
	}

	newClient, err := t.factory(proxyURI)
	if err != nil {
		return nil, fmt.Errorf("create client for proxy %q: %w", proxyURI, err)
	}

	t.clientPool[proxyURI] = newClient
	return newClient, nil
}

// RoundTrip выполняет конвертацию запроса, применяет контекстный прокси и браузерные заголовки.
func (t *TLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 1. Выбираем инстанс клиента: контекстный прокси или дефолтный
	activeProxy, _ := ProxyFromContext(req.Context())
	innerClient, err := t.getClientForProxy(activeProxy)
	if err != nil {
		return nil, err
	}

	// 2. Создаем fhttp.Request
	fReq, err := fhttp.NewRequestWithContext(
		req.Context(),
		req.Method,
		req.URL.String(),
		req.Body,
	)
	if err != nil {
		return nil, fmt.Errorf("build fhttp request: %w", err)
	}

	// 3. Накладываем выверенные браузерные заголовки и порядок их следования
	t.headers.ApplyHeaders(fReq, req)

	// 4. Выполняем запрос через выбранный клиент
	fResp, err := innerClient.Do(fReq)
	if err != nil {
		return nil, err
	}

	// 5. Упаковываем ответ обратно в стандартный http.Response
	netResp := &http.Response{
		Status:           fResp.Status,
		StatusCode:       fResp.StatusCode,
		Proto:            fResp.Proto,
		ProtoMajor:       fResp.ProtoMajor,
		ProtoMinor:       fResp.ProtoMinor,
		ContentLength:    fResp.ContentLength,
		Body:             fResp.Body,
		Header:           make(http.Header, len(fResp.Header)),
		Trailer:          make(http.Header, len(fResp.Trailer)),
		Close:            fResp.Close,
		Uncompressed:     fResp.Uncompressed,
		TransferEncoding: fResp.TransferEncoding,
		Request:          req,
	}

	// Копируем заголовки
	for k, vv := range fResp.Header {
		netResp.Header[k] = vv
	}
	// Копируем трейлеры (если есть)
	for k, vv := range fResp.Trailer {
		netResp.Trailer[k] = vv
	}

	return netResp, nil
}
