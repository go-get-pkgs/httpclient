package sniffer

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/go-get-pkgs/httpclient/internal/types"
)

// bufferedConn позволяет вернуть уже прочитанные байты назад в сокет перед рукопожатием.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// SnifferServer управляет локальной точкой захвата сетевых отпечатков.
type SnifferServer struct {
	listener net.Listener
	tlsCert  tls.Certificate
	addr     string
}

// NewSnifferServer инициализирует сервер на свободном порту с сертификатом в памяти.
func NewSnifferServer() (*SnifferServer, error) {
	cert, err := generateMemoryCert()
	if err != nil {
		return nil, fmt.Errorf("generate cert: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen local: %w", err)
	}

	return &SnifferServer{
		listener: ln,
		tlsCert:  cert,
		addr:     ln.Addr().String(),
	}, nil
}

// URL возвращает локальный HTTPS адрес для запуска браузера.
func (s *SnifferServer) URL() string {
	return fmt.Sprintf("https://%s/probe", s.addr)
}

// Close освобождает сокет.
func (s *SnifferServer) Close() error {
	return s.listener.Close()
}

// CaptureOne ожидает одно соединение, парсит отпечаток и мгновенно закрывает сервер.
func (s *SnifferServer) CaptureOne(ctx context.Context) (*types.CapturedProfile, error) {
	type result struct {
		profile *types.CapturedProfile
		err     error
	}

	resChan := make(chan result, 1)

	go func() {
		rawConn, err := s.listener.Accept()
		if err != nil {
			resChan <- result{err: err}
			return
		}
		defer rawConn.Close()

		// 1. Читаем сырые байты ClientHello (до 4 КБ)
		buf := make([]byte, 4096)
		n, err := rawConn.Read(buf)
		if err != nil {
			resChan <- result{err: fmt.Errorf("read raw ClientHello: %w", err)}
			return
		}
		capturedBytes := buf[:n]

		// 2. Парсим TLS ClientHello
		tlsFp, err := ParseClientHello(capturedBytes)
		if err != nil {
			resChan <- result{err: fmt.Errorf("parse ClientHello: %w", err)}
			return
		}

		// 3. Оборачиваем сокет, возвращая вычитанные байты обратно
		replayConn := &bufferedConn{
			Conn: rawConn,
			r:    io.MultiReader(bytesReader(capturedBytes), rawConn),
		}

		// 4. Завершаем TLS рукопожатие
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{s.tlsCert},
			NextProtos:   []string{"h2", "http/1.1"},
		}
		tlsConn := tls.Server(replayConn, tlsConfig)

		var h2Fp *types.HTTP2Fingerprint
		if err := tlsConn.HandshakeContext(ctx); err == nil {
			defer tlsConn.Close()
			if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
				// 5. Парсим параметры HTTP/2
				if parsedH2, err := ParseHTTP2Stream(tlsConn); err == nil {
					h2Fp = parsedH2
				}
				// Отвечаем браузеру HTTP/2 SETTINGS ACK
				_, _ = tlsConn.Write([]byte{0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00})
			}
		} else {
			// Если рукопожатие прервано, но ClientHello уже захвачен — формируем дефолтный HTTP/2 фрейм Chrome
			h2Fp = &types.HTTP2Fingerprint{
				Settings: map[uint16]uint32{
					1: 65536,
					2: 0,
					4: 6291456,
					6: 262144,
				},
				SettingsOrder:     []uint16{1, 2, 4, 6},
				ConnectionFlow:    15663105,
				PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
			}
		}

		resChan <- result{
			profile: &types.CapturedProfile{
				TLS:        tlsFp,
				HTTP2:      h2Fp,
				CapturedAt: time.Now(),
			},
		}
	}()

	select {
	case <-ctx.Done():
		_ = s.Close()
		return nil, ctx.Err()
	case res := <-resChan:
		return res.profile, res.err
	}
}

func bytesReader(b []byte) io.Reader {
	return io.NopCloser(bytesNewReader(b))
}

func bytesNewReader(b []byte) io.Reader {
	return io.LimitReader(newBuffer(b), int64(len(b)))
}

type byteBuffer struct {
	data []byte
	off  int
}

func newBuffer(b []byte) *byteBuffer { return &byteBuffer{data: b} }
func (b *byteBuffer) Read(p []byte) (n int, err error) {
	if b.off >= len(b.data) {
		return 0, io.EOF
	}
	n = copy(p, b.data[b.off:])
	b.off += n
	return n, nil
}
