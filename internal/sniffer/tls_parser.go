package sniffer

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/go-get-pkgs/httpclient/internal/types"
)

// IsGREASE проверяет, является ли значение GREASE-идентификатором (RFC 8701).
// Значения вида 0x?A?A (например: 0x0a0a, 0x1a1a, ..., 0xfafa).
func IsGREASE(val uint16) bool {
	return (val&0x0f0f) == 0x0a0a && ((val >> 8) == (val & 0xff))
}

// ParseClientHello парсит сырой TLS ClientHello из буфера первого TCP пакета.
func ParseClientHello(data []byte) (*types.TLSFingerprint, error) {
	if len(data) < 5 {
		return nil, errors.New("packet too short for TLS record")
	}

	// 1. Проверяем TLS Record Header
	// 0x16 = Handshake
	if data[0] != 0x16 {
		return nil, fmt.Errorf("not a TLS handshake record: 0x%02x", data[0])
	}
	recordVersion := binary.BigEndian.Uint16(data[1:3])
	recordLength := int(binary.BigEndian.Uint16(data[3:5]))

	if len(data) < 5+recordLength {
		return nil, errors.New("incomplete TLS record")
	}

	handshake := data[5 : 5+recordLength]
	if len(handshake) < 4 {
		return nil, errors.New("handshake payload too short")
	}

	// 0x01 = ClientHello
	if handshake[0] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello: 0x%02x", handshake[0])
	}

	// Длина ClientHello (3 байта)
	helloLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+helloLen {
		return nil, errors.New("incomplete ClientHello message")
	}

	payload := handshake[4 : 4+helloLen]
	if len(payload) < 34 {
		return nil, errors.New("ClientHello payload too short")
	}

	fp := &types.TLSFingerprint{
		RecordVersion: recordVersion,
		RawExtensions: make(map[uint16][]byte),
	}

	fp.HandshakeVersion = binary.BigEndian.Uint16(payload[0:2])
	// payload[2:34] — Random (32 байта)
	offset := 34

	// Session ID
	if offset >= len(payload) {
		return nil, errors.New("unexpected EOF reading SessionID")
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	// Cipher Suites
	if offset+2 > len(payload) {
		return nil, errors.New("unexpected EOF reading CipherSuites length")
	}
	ciphersLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	if offset+ciphersLen > len(payload) {
		return nil, errors.New("unexpected EOF reading CipherSuites")
	}
	for i := 0; i < ciphersLen; i += 2 {
		cipher := binary.BigEndian.Uint16(payload[offset+i : offset+i+2])
		fp.CipherSuites = append(fp.CipherSuites, cipher)
	}
	offset += ciphersLen

	// Compression Methods
	if offset >= len(payload) {
		return nil, errors.New("unexpected EOF reading CompressionMethods length")
	}
	compLen := int(payload[offset])
	offset++
	if offset+compLen > len(payload) {
		return nil, errors.New("unexpected EOF reading CompressionMethods")
	}
	fp.CompressionMethods = append([]byte(nil), payload[offset:offset+compLen]...)
	offset += compLen

	// Extensions
	if offset == len(payload) {
		// Без расширений (для старых клиентов)
		return fp, nil
	}
	if offset+2 > len(payload) {
		return nil, errors.New("unexpected EOF reading Extensions length")
	}
	extsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	if offset+extsLen > len(payload) {
		return nil, errors.New("unexpected EOF reading Extensions block")
	}

	extsData := payload[offset : offset+extsLen]
	extOffset := 0

	for extOffset+4 <= len(extsData) {
		extType := binary.BigEndian.Uint16(extsData[extOffset : extOffset+2])
		extLen := int(binary.BigEndian.Uint16(extsData[extOffset+2 : extOffset+4]))
		extOffset += 4

		if extOffset+extLen > len(extsData) {
			return nil, errors.New("malformed extension length")
		}

		body := extsData[extOffset : extOffset+extLen]
		extOffset += extLen

		fp.Extensions = append(fp.Extensions, extType)
		fp.RawExtensions[extType] = append([]byte(nil), body...)

		// Детальный парсинг критичных расширений для фингерпринта
		switch extType {
		case 10: // supported_groups (curves)
			if len(body) >= 2 {
				curvesLen := int(binary.BigEndian.Uint16(body[0:2]))
				for i := 2; i+2 <= 2+curvesLen && i+2 <= len(body); i += 2 {
					fp.SupportedCurves = append(fp.SupportedCurves, binary.BigEndian.Uint16(body[i:i+2]))
				}
			}
		case 11: // ec_point_formats
			if len(body) >= 1 {
				pLen := int(body[0])
				if len(body) >= 1+pLen {
					fp.SupportedPoints = append([]byte(nil), body[1:1+pLen]...)
				}
			}
		case 13: // signature_algorithms
			if len(body) >= 2 {
				sigLen := int(binary.BigEndian.Uint16(body[0:2]))
				for i := 2; i+2 <= 2+sigLen && i+2 <= len(body); i += 2 {
					fp.SignatureAlgorithms = append(fp.SignatureAlgorithms, binary.BigEndian.Uint16(body[i:i+2]))
				}
			}
		case 16: // application_layer_protocol_negotiation (ALPN)
			if len(body) >= 2 {
				alpnListLen := int(binary.BigEndian.Uint16(body[0:2]))
				alpnOffset := 2
				for alpnOffset < 2+alpnListLen && alpnOffset < len(body) {
					protoLen := int(body[alpnOffset])
					alpnOffset++
					if alpnOffset+protoLen <= len(body) {
						fp.ALPNProtocols = append(fp.ALPNProtocols, string(body[alpnOffset:alpnOffset+protoLen]))
						alpnOffset += protoLen
					}
				}
			}
		case 51: // key_share
			if len(body) >= 2 {
				ksLen := int(binary.BigEndian.Uint16(body[0:2]))
				ksOffset := 2
				for ksOffset+4 <= 2+ksLen && ksOffset+4 <= len(body) {
					group := binary.BigEndian.Uint16(body[ksOffset : ksOffset+2])
					keyLen := int(binary.BigEndian.Uint16(body[ksOffset+2 : ksOffset+4]))
					ksOffset += 4 + keyLen
					fp.KeyShareGroups = append(fp.KeyShareGroups, group)
				}
			}
		}
	}

	return fp, nil
}
