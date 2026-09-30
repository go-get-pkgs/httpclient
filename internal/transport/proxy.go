// ./internal/transport/proxy.go
package transport

import (
	"context"
	"sync"
	"sync/atomic"
)

type proxyCtxKey struct{}

// WithProxy прикрепляет прокси к контексту конкретного запроса.
// URI формат: "http://user:pass@host:port" или "socks5://host:port".
func WithProxy(ctx context.Context, proxyURI string) context.Context {
	return context.WithValue(ctx, proxyCtxKey{}, proxyURI)
}

// ProxyFromContext извлекает прокси из контекста запроса.
func ProxyFromContext(ctx context.Context) (string, bool) {
	val, ok := ctx.Value(proxyCtxKey{}).(string)
	return val, ok && val != ""
}

// ProxyRotator интерфейс для динамического выбора прокси.
type ProxyRotator interface {
	NextProxy() string
}

// RoundRobinProxyRotator простая и быстрая потокобезопасная реализация round-robin пула.
type RoundRobinProxyRotator struct {
	proxies []string
	counter uint64
	mu      sync.RWMutex
}

// NewRoundRobinProxyRotator создает ротатор из списка адресов.
func NewRoundRobinProxyRotator(proxies []string) *RoundRobinProxyRotator {
	clean := make([]string, 0, len(proxies))
	for _, p := range proxies {
		if p != "" {
			clean = append(clean, p)
		}
	}
	return &RoundRobinProxyRotator{proxies: clean}
}

// NextProxy возвращает следующий прокси по кругу.
func (r *RoundRobinProxyRotator) NextProxy() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.proxies) == 0 {
		return ""
	}
	idx := atomic.AddUint64(&r.counter, 1) - 1
	return r.proxies[idx%uint64(len(r.proxies))]
}

// Add добавляет новый прокси в ротацию на лету.
func (r *RoundRobinProxyRotator) Add(proxyURI string) {
	if proxyURI == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.proxies = append(r.proxies, proxyURI)
}

// Len возвращает количество прокси в пуле.
func (r *RoundRobinProxyRotator) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.proxies)
}
