package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// DefaultMaxBodyBuffer — максимальный размер тела запроса (4 МБ),
// который буферизируется в памяти для безопасного повтора.
const DefaultMaxBodyBuffer int64 = 4 * 1024 * 1024

// maxDrainBytes — максимальный объем байт тела ответа, который считывается в Discard при ошибке.
const maxDrainBytes int64 = 64 * 1024

// RetryConfig задает политику повтора запросов.
type RetryConfig struct {
	MaxAttempts        int           // Количество повторных попыток (0 = выключено)
	BaseDelay          time.Duration // Начальная задержка
	MaxDelay           time.Duration // Верхний предел задержки
	RetryOnCodes       []int         // HTTP-статусы для повтора (например: 429, 500, 502, 503, 504)
	MaxBodyBuffer      int64         // Лимит буфера памяти (0 = дефолт 4МБ, -1 = отключить буферизацию)
	Rotator            ProxyRotator  // Опциональный пул прокси для смены IP при ретрае
	RotateProxyOnRetry bool          // Менять ли прокси при каждой повторной попытке
}

// DefaultRetryConfig — сбалансированная конфигурация по умолчанию.
var DefaultRetryConfig = RetryConfig{
	MaxAttempts:   3,
	BaseDelay:     300 * time.Millisecond,
	MaxDelay:      10 * time.Second,
	RetryOnCodes:  []int{429, 500, 502, 503, 504},
	MaxBodyBuffer: DefaultMaxBodyBuffer,
}

type RetryTransport struct {
	Inner  http.RoundTripper
	Config RetryConfig
}

// backoff рассчитывает задержку с экспоненциальным ростом и Full Jitter рандомизацией.
func (r *RetryTransport) backoff(attempt int) time.Duration {
	base := float64(r.Config.BaseDelay) * math.Pow(2, float64(attempt-1))
	maxD := float64(r.Config.MaxDelay)
	if base > maxD {
		base = maxD
	}
	// Full Jitter: случайное число в диапазоне [0, base]
	jitter := rand.Float64() * base
	return time.Duration(jitter)
}

// checkRetryAfter парсит заголовок Retry-After от сервера.
func parseRetryAfter(resp *http.Response) (time.Duration, bool) {
	if resp == nil {
		return 0, false
	}
	header := resp.Header.Get("Retry-After")
	if header == "" {
		return 0, false
	}

	// 1. Попытка распарсить как секунды (целое число)
	if seconds, err := strconv.Atoi(header); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second, true
	}

	// 2. Попытка распарсить как дату HTTP-Date (RFC1123 / RFC850)
	if t, err := http.ParseTime(header); err == nil {
		until := time.Until(t)
		if until > 0 {
			return until, true
		}
	}

	return 0, false
}

func (r *RetryTransport) shouldRetry(code int) bool {
	for _, c := range r.Config.RetryOnCodes {
		if c == code {
			return true
		}
	}
	return false
}

// prepareBodyForRetry делает тело запроса переиспользуемым для ретраев.
func prepareBodyForRetry(req *http.Request, maxBuf int64) (bool, error) {
	if req.Body == nil || req.GetBody != nil {
		return true, nil
	}

	if maxBuf < 0 {
		return false, nil
	}
	if maxBuf == 0 {
		maxBuf = DefaultMaxBodyBuffer
	}

	if req.ContentLength > maxBuf {
		return false, nil
	}

	buf, err := io.ReadAll(io.LimitReader(req.Body, maxBuf+1))
	if err != nil {
		_ = req.Body.Close()
		return false, fmt.Errorf("retry buffer: %w", err)
	}

	if int64(len(buf)) > maxBuf {
		// Тело превысило лимит — сшиваем обратно и отправляем разово
		remainder := req.Body
		req.Body = struct {
			io.Reader
			io.Closer
		}{
			Reader: io.MultiReader(bytes.NewReader(buf), remainder),
			Closer: remainder,
		}
		return false, nil
	}

	_ = req.Body.Close()
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf)), nil
	}
	req.Body, _ = req.GetBody()
	return true, nil
}

func (r *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	canRetry, err := prepareBodyForRetry(req, r.Config.MaxBodyBuffer)
	if err != nil {
		return nil, err
	}

	maxAttempts := r.Config.MaxAttempts
	if !canRetry {
		maxAttempts = 0
	}

	var resp *http.Response
	currentReq := req

	for attempt := 0; attempt <= maxAttempts; attempt++ {
		if attempt > 0 {
			// Ротация прокси при повторной попытке
			if r.Config.RotateProxyOnRetry && r.Config.Rotator != nil {
				nextProxy := r.Config.Rotator.NextProxy()
				if nextProxy != "" {
					newCtx := WithProxy(currentReq.Context(), nextProxy)
					currentReq = currentReq.WithContext(newCtx)
				}
			}

			delay := r.backoff(attempt)

			// Если сервер прислал Retry-After, ориентируемся на него
			if serverDelay, ok := parseRetryAfter(resp); ok {
				if serverDelay <= r.Config.MaxDelay {
					delay = serverDelay
				} else {
					delay = r.Config.MaxDelay
				}
			}

			// Безопасное ожидание через Timer без утечек памяти
			timer := time.NewTimer(delay)
			select {
			case <-currentReq.Context().Done():
				timer.Stop()
				return nil, currentReq.Context().Err()
			case <-timer.C:
			}

			if currentReq.GetBody != nil {
				currentReq.Body, err = currentReq.GetBody()
				if err != nil {
					return nil, fmt.Errorf("retry restore body: %w", err)
				}
			}
		}

		resp, err = r.Inner.RoundTrip(currentReq)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			continue
		}

		if !r.shouldRetry(resp.StatusCode) {
			return resp, nil
		}

		// Безопасный сброс тела с ограничением чтения перед закрытием
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))
		_ = resp.Body.Close()
	}

	return resp, err
}
