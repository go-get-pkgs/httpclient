package probes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-get-pkgs/httpclient/internal/types"
)

const (
	browserLeaksURL = "https://tls.browserleaks.com/json"
	peetURL         = "https://tls.peet.ws/api/all"
	howsMySSLURL    = "https://www.howsmyssl.com/a/check"
)

// ExternalProbeProvider опрашивает пул независимых сетевых анализаторов отпечатков.
type ExternalProbeProvider struct {
	httpClient *http.Client
	remoteURLs []string
}

// NewExternalProbeProvider создает провайдер внешних пробников.
func NewExternalProbeProvider(customManifestURLs ...string) *ExternalProbeProvider {
	return &ExternalProbeProvider{
		httpClient: &http.Client{Timeout: 7 * time.Second},
		remoteURLs: customManifestURLs,
	}
}

// FetchCapturedProfile опрашивает доступные источники до первого валидного ответа.
func (p *ExternalProbeProvider) FetchCapturedProfile(ctx context.Context) (*types.CapturedProfile, error) {
	// 1. Сначала проверяем пользовательские удаленные манифесты (если переданы)
	for _, u := range p.remoteURLs {
		if prof, err := p.fetchDirectManifest(ctx, u); err == nil && prof != nil {
			return prof, nil
		}
	}

	// 2. Гонка публичных анализаторов: BrowserLeaks vs PeetWS
	type result struct {
		profile *types.CapturedProfile
		err     error
	}

	resChan := make(chan result, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	probeCtx, cancel := context.WithTimeout(ctx, p.httpClient.Timeout)
	defer cancel()

	// Источник 1: BrowserLeaks (основной)
	go func() {
		defer wg.Done()
		prof, err := p.fetchBrowserLeaks(probeCtx)
		if err == nil && prof != nil {
			select {
			case resChan <- result{profile: prof}:
			case <-probeCtx.Done():
			}
		}
	}()

	// Источник 2: PeetWS (резервный)
	go func() {
		defer wg.Done()
		prof, err := p.fetchPeetWS(probeCtx)
		if err == nil && prof != nil {
			select {
			case resChan <- result{profile: prof}:
			case <-probeCtx.Done():
			}
		}
	}()

	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()

	select {
	case res := <-resChan:
		return res.profile, nil
	case <-allDone:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return nil, errors.New("all external fingerprint probes failed")
}

// fetchDirectManifest загружает готовый CapturedProfile JSON напрямую (например, из GitHub Raw/S3).
func (p *ExternalProbeProvider) fetchDirectManifest(ctx context.Context, url string) (*types.CapturedProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.httpClient.Do(req)
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
	return &prof, nil
}

// fetchBrowserLeaks парсит ответ от https://tls.browserleaks.com/json
func (p *ExternalProbeProvider) fetchBrowserLeaks(ctx context.Context) (*types.CapturedProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, browserLeaksURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("browserleaks status: %d", resp.StatusCode)
	}

	var data struct {
		UserAgent string `json:"user_agent"`
		JA3       struct {
			Ciphers    []uint16 `json:"ciphers"`
			Extensions []uint16 `json:"extensions"`
			Curves     []uint16 `json:"curves"`
			Points     []byte   `json:"points"`
		} `json:"ja3_details"`
		HTTP2 struct {
			Settings map[string]uint32 `json:"settings"`
			Order    []string          `json:"order"`
		} `json:"http2"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	if len(data.JA3.Ciphers) == 0 {
		return nil, errors.New("empty ciphers in browserleaks response")
	}

	tlsFp := &types.TLSFingerprint{
		RecordVersion:       771,
		HandshakeVersion:    771,
		CipherSuites:        data.JA3.Ciphers,
		Extensions:          data.JA3.Extensions,
		SupportedCurves:     data.JA3.Curves,
		SupportedPoints:     data.JA3.Points,
		ALPNProtocols:       []string{"h2", "http/1.1"},
		SignatureAlgorithms: []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}, // стандарт Chrome
		RawExtensions:       make(map[uint16][]byte),
	}

	h2Settings := make(map[uint16]uint32)
	var h2Order []uint16
	for k, v := range data.HTTP2.Settings {
		if id, err := strconv.Atoi(k); err == nil {
			h2Settings[uint16(id)] = v
			h2Order = append(h2Order, uint16(id))
		}
	}

	h2Fp := &types.HTTP2Fingerprint{
		Settings:          h2Settings,
		SettingsOrder:     h2Order,
		ConnectionFlow:    15663105,
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		CapturedHeaders: map[string]string{
			"user-agent": data.UserAgent,
		},
	}

	return &types.CapturedProfile{
		TLS:        tlsFp,
		HTTP2:      h2Fp,
		CapturedAt: time.Now(),
	}, nil
}

// fetchPeetWS парсит ответ от https://tls.peet.ws/api/all
func (p *ExternalProbeProvider) fetchPeetWS(ctx context.Context) (*types.CapturedProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, peetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peetws status: %d", resp.StatusCode)
	}

	var data struct {
		UserAgent string `json:"user_agent"`
		TLS       struct {
			Ciphers    []string `json:"ciphers"`
			Extensions []struct {
				Name string `json:"name"`
				Data string `json:"data"`
			} `json:"extensions"`
			SupportedGroups []string `json:"supported_groups"`
		} `json:"tls"`
		HTTP2 struct {
			SentFrames []struct {
				FrameType string   `json:"frame_type"`
				Settings  []string `json:"settings"`
				Headers   []string `json:"headers"`
				Increment uint32   `json:"increment"`
			} `json:"sent_frames"`
		} `json:"http2"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	// Нормализуем Ciphers
	var ciphers []uint16
	for _, c := range data.TLS.Ciphers {
		if id := parseCipherID(c); id > 0 {
			ciphers = append(ciphers, id)
		}
	}

	// Нормализуем Extensions
	var extensions []uint16
	rawExts := make(map[uint16][]byte)
	for _, ext := range data.TLS.Extensions {
		if id := parseExtensionID(ext.Name); id > 0 {
			extensions = append(extensions, id)
			if ext.Data != "" {
				if b, err := hex.DecodeString(ext.Data); err == nil {
					rawExts[id] = b
				}
			}
		}
	}

	var curves []uint16
	for _, g := range data.TLS.SupportedGroups {
		if id := parseCurveID(g); id > 0 {
			curves = append(curves, id)
		}
	}

	tlsFp := &types.TLSFingerprint{
		RecordVersion:       771,
		HandshakeVersion:    771,
		CipherSuites:        ciphers,
		Extensions:          extensions,
		SupportedCurves:     curves,
		ALPNProtocols:       []string{"h2", "http/1.1"},
		SignatureAlgorithms: []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
		RawExtensions:       rawExts,
	}

	h2Settings := make(map[uint16]uint32)
	var h2Order []uint16
	connFlow := uint32(15663105)

	for _, frame := range data.HTTP2.SentFrames {
		if frame.FrameType == "SETTINGS" {
			for _, s := range frame.Settings {
				if id, val, ok := parseH2SettingLine(s); ok {
					h2Settings[id] = val
					h2Order = append(h2Order, id)
				}
			}
		}
		if frame.FrameType == "WINDOW_UPDATE" && frame.Increment > 0 {
			connFlow = frame.Increment
		}
	}

	h2Fp := &types.HTTP2Fingerprint{
		Settings:          h2Settings,
		SettingsOrder:     h2Order,
		ConnectionFlow:    connFlow,
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		CapturedHeaders: map[string]string{
			"user-agent": data.UserAgent,
		},
	}

	return &types.CapturedProfile{
		TLS:        tlsFp,
		HTTP2:      h2Fp,
		CapturedAt: time.Now(),
	}, nil
}

func parseCipherID(str string) uint16 {
	if strings.Contains(str, "0x") {
		idx := strings.Index(str, "0x")
		sub := str[idx+2:]
		if end := strings.IndexAny(sub, " )"); end != -1 {
			sub = sub[:end]
		}
		if v, err := strconv.ParseUint(sub, 16, 16); err == nil {
			return uint16(v)
		}
	}
	known := map[string]uint16{
		"TLS_AES_128_GCM_SHA256":                        0x1301,
		"TLS_AES_256_GCM_SHA384":                        0x1302,
		"TLS_CHACHA20_POLY1305_SHA256":                  0x1303,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       0xc02b,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         0xc02f,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       0xc02c,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         0xc030,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xcca9,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   0xcca8,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            0xc013,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            0xc014,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":               0x009c,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":               0x009d,
		"TLS_RSA_WITH_AES_128_CBC_SHA":                  0x002f,
		"TLS_RSA_WITH_AES_256_CBC_SHA":                  0x0035,
	}
	for k, id := range known {
		if strings.Contains(str, k) {
			return id
		}
	}
	return 0
}

func parseExtensionID(str string) uint16 {
	if strings.Contains(str, "(") && strings.Contains(str, ")") {
		start := strings.LastIndex(str, "(")
		end := strings.LastIndex(str, ")")
		if start < end {
			valStr := str[start+1 : end]
			if v, err := strconv.Atoi(valStr); err == nil {
				return uint16(v)
			}
		}
	}
	return 0
}

func parseCurveID(str string) uint16 {
	if strings.Contains(str, "(") && strings.Contains(str, ")") {
		start := strings.LastIndex(str, "(")
		end := strings.LastIndex(str, ")")
		if start < end {
			valStr := str[start+1 : end]
			if v, err := strconv.Atoi(valStr); err == nil {
				return uint16(v)
			}
		}
	}
	return 0
}

func parseH2SettingLine(s string) (uint16, uint32, bool) {
	parts := strings.Split(s, "=")
	if len(parts) != 2 {
		return 0, 0, false
	}
	key := strings.TrimSpace(parts[0])
	valStr := strings.TrimSpace(parts[1])
	val, err := strconv.ParseUint(valStr, 10, 32)
	if err != nil {
		return 0, 0, false
	}

	mapping := map[string]uint16{
		"HEADER_TABLE_SIZE":      1,
		"ENABLE_PUSH":            2,
		"MAX_CONCURRENT_STREAMS": 3,
		"INITIAL_WINDOW_SIZE":    4,
		"MAX_FRAME_SIZE":         5,
		"MAX_HEADER_LIST_SIZE":   6,
	}
	if id, ok := mapping[key]; ok {
		return id, uint32(val), true
	}
	return 0, 0, false
}
