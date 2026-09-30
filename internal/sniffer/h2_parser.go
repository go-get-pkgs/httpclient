package sniffer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/go-get-pkgs/httpclient/internal/types"

	"golang.org/x/net/http2/hpack"
)

const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// ParseHTTP2Stream вычитывает первые фреймы HTTP/2 от клиента и формирует фингерпринт.
func ParseHTTP2Stream(r io.Reader) (*types.HTTP2Fingerprint, error) {
	// 1. Проверяем 24-байтный префейс HTTP/2
	preface := make([]byte, len(http2ClientPreface))
	if _, err := io.ReadFull(r, preface); err != nil {
		return nil, fmt.Errorf("read http2 preface: %w", err)
	}
	if string(preface) != http2ClientPreface {
		return nil, errors.New("invalid http2 client preface")
	}

	fp := &types.HTTP2Fingerprint{
		Settings:        make(map[uint16]uint32),
		CapturedHeaders: make(map[string]string),
	}

	headerPayloadBuf := new(bytes.Buffer)
	gotHeaders := false

	// 2. Читаем первые фреймы до завершения первого блока HEADERS
	for !gotHeaders {
		frameHeader := make([]byte, 9)
		if _, err := io.ReadFull(r, frameHeader); err != nil {
			return nil, fmt.Errorf("read frame header: %w", err)
		}

		length := int(frameHeader[0])<<16 | int(frameHeader[1])<<8 | int(frameHeader[2])
		frameType := frameHeader[3]
		flags := frameHeader[4]
		streamID := binary.BigEndian.Uint32(frameHeader[5:9]) & 0x7fffffff

		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read frame payload: %w", err)
		}

		switch frameType {
		case 0x04: // SETTINGS Frame
			if streamID == 0 {
				for i := 0; i+6 <= len(payload); i += 6 {
					id := binary.BigEndian.Uint16(payload[i : i+2])
					val := binary.BigEndian.Uint32(payload[i+2 : i+6])
					fp.Settings[id] = val
					fp.SettingsOrder = append(fp.SettingsOrder, id)
				}
			}

		case 0x08: // WINDOW_UPDATE Frame
			if streamID == 0 && len(payload) >= 4 {
				increment := binary.BigEndian.Uint32(payload[0:4]) & 0x7fffffff
				fp.ConnectionFlow = increment
			}

		case 0x01: // HEADERS Frame
			// Отсекаем паддинг и приоритеты, если выставлены соответствующие флаги
			offset := 0
			if flags&0x08 != 0 { // FLAG_PADDED
				padLen := int(payload[0])
				offset++
				payload = payload[:len(payload)-padLen]
			}
			if flags&0x20 != 0 { // FLAG_PRIORITY
				offset += 5 // Stream Dependency (4) + Weight (1)
			}
			if offset <= len(payload) {
				headerPayloadBuf.Write(payload[offset:])
			}
			if flags&0x04 != 0 { // END_HEADERS
				gotHeaders = true
			}

		case 0x09: // CONTINUATION Frame
			headerPayloadBuf.Write(payload)
			if flags&0x04 != 0 { // END_HEADERS
				gotHeaders = true
			}
		}
	}

	// 3. Декодируем заголовки через HPACK
	hpackDecoder := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {
		name := strings.ToLower(hf.Name)
		if strings.HasPrefix(name, ":") {
			fp.PseudoHeaderOrder = append(fp.PseudoHeaderOrder, name)
		} else {
			fp.HeaderOrder = append(fp.HeaderOrder, name)
		}
		fp.CapturedHeaders[name] = hf.Value
	})

	if _, err := hpackDecoder.Write(headerPayloadBuf.Bytes()); err != nil {
		return nil, fmt.Errorf("decode hpack headers: %w", err)
	}

	return fp, nil
}
