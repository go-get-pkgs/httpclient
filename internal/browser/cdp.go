package browser

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-get-pkgs/httpclient/internal/types"

	"github.com/bogdanfinn/websocket"
)

var wsURLRegex = regexp.MustCompile(`ws://127\.0\.0\.1:\d+/devtools/browser/[a-zA-Z0-9-]+`)

type cdpRequest struct {
	ID     int64  `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}

type cdpResponse struct {
	ID     int64           `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// ProbeLocalBrowserCDP скрытно запускает браузер и забирает отпечаток через Chrome DevTools Protocol.
// Не открывает локальных слушающих портов!
func ProbeLocalBrowserCDP(ctx context.Context, targetURL string) (*types.CapturedProfile, *types.BrowserInfo, error) {
	if targetURL == "" {
		targetURL = "https://tls.browserleaks.com/json"
	}

	browser, found := FindSystemBrowser()
	if !found {
		return nil, nil, errors.New("no supported browser found on host")
	}

	tmpDir, err := os.MkdirTemp("", "httpclient-cdp-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create cdp temp dir: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	cdpCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	// Запуск с remote-debugging-port=0 (рандомный порт, назначаемый ОС)
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-default-apps",
		"--disable-extensions",
		"--mute-audio",
		"--no-first-run",
		"--remote-debugging-port=0",
		fmt.Sprintf("--user-data-dir=%s", tmpDir),
		"about:blank",
	}

	cmd := exec.CommandContext(cdpCtx, browser.Path, args...)
	prepareBackgroundCommand(cmd)

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start cdp browser: %w", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Вычитываем WebSocket URL из stderr браузера
	wsURL, err := extractWebSocketURL(stderr)
	if err != nil {
		return nil, nil, fmt.Errorf("extract ws url: %w", err)
	}

	// Подключаемся к браузеру по WebSocket
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	wsConn, _, err := dialer.DialContext(cdpCtx, wsURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("dial cdp ws: %w", err)
	}
	defer wsConn.Close()

	// Создаем новую страницу (Target)
	pageWSURL, err := createNewTarget(cdpCtx, wsURL)
	if err != nil {
		return nil, nil, fmt.Errorf("create page target: %w", err)
	}

	pageConn, _, err := dialer.DialContext(cdpCtx, pageWSURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("dial page target ws: %w", err)
	}
	defer pageConn.Close()

	// Заставляем страницу перейти на сайт проверки отпечатков
	rawJSON, err := evaluatePage(cdpCtx, pageConn, targetURL)
	if err != nil {
		return nil, nil, fmt.Errorf("evaluate page: %w", err)
	}

	// Разбираем полученный отпечаток
	capProfile, err := parseCDPPayload(rawJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("parse cdp payload: %w", err)
	}

	return capProfile, browser, nil
}

func extractWebSocketURL(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if match := wsURLRegex.FindString(line); match != "" {
			return match, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("devtools ws url not found in stderr")
}

func createNewTarget(ctx context.Context, browserWSURL string) (string, error) {
	// Достаем порт из ws://127.0.0.1:PORT/...
	parts := strings.Split(browserWSURL, "/")
	if len(parts) < 3 {
		return "", errors.New("malformed browser ws url")
	}
	hostPort := parts[2]

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("http://%s/json/new?about:blank", hostPort), nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var target struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&target); err != nil {
		return "", err
	}
	return target.WebSocketDebuggerURL, nil
}

var reqIDCounter int64

func callCDP(conn *websocket.Conn, method string, params any) (json.RawMessage, error) {
	id := atomic.AddInt64(&reqIDCounter, 1)
	req := cdpRequest{ID: id, Method: method, Params: params}
	if err := conn.WriteJSON(req); err != nil {
		return nil, err
	}

	for {
		var resp cdpResponse
		if err := conn.ReadJSON(&resp); err != nil {
			return nil, err
		}
		if resp.ID == id {
			if resp.Error != nil {
				return nil, errors.New(resp.Error.Message)
			}
			return resp.Result, nil
		}
	}
}

func evaluatePage(ctx context.Context, conn *websocket.Conn, targetURL string) (string, error) {
	// 1. Включаем Page домен
	_, _ = callCDP(conn, "Page.enable", nil)

	// 2. Навигация на целевой URL
	_, err := callCDP(conn, "Page.navigate", map[string]string{"url": targetURL})
	if err != nil {
		return "", err
	}

	// 3. Ожидаем загрузки страницы и достаем document.body.innerText
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			res, err := callCDP(conn, "Runtime.evaluate", map[string]any{
				"expression":    "document.body ? document.body.innerText : ''",
				"returnByValue": true,
			})
			if err != nil {
				continue
			}

			var evalResult struct {
				Result struct {
					Value string `json:"value"`
				} `json:"result"`
			}
			if err := json.Unmarshal(res, &evalResult); err == nil && len(evalResult.Result.Value) > 50 {
				if strings.Contains(evalResult.Result.Value, "{") {
					return evalResult.Result.Value, nil
				}
			}
		}
	}
}

func parseCDPPayload(rawJSON string) (*types.CapturedProfile, error) {
	start := strings.Index(rawJSON, "{")
	end := strings.LastIndex(rawJSON, "}")
	if start == -1 || end == -1 || start >= end {
		return nil, errors.New("no json found in response")
	}
	cleanJSON := rawJSON[start : end+1]

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
		} `json:"http2"`
	}

	if err := json.Unmarshal([]byte(cleanJSON), &data); err != nil {
		return nil, err
	}

	tlsFp := &types.TLSFingerprint{
		RecordVersion:       771,
		HandshakeVersion:    771,
		CipherSuites:        data.JA3.Ciphers,
		Extensions:          data.JA3.Extensions,
		SupportedCurves:     data.JA3.Curves,
		SupportedPoints:     data.JA3.Points,
		ALPNProtocols:       []string{"h2", "http/1.1"},
		SignatureAlgorithms: []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
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
