package types

import "time"

// TLSFingerprint содержит разобранные сырые параметры TLS-рукопожатия.
type TLSFingerprint struct {
	RecordVersion       uint16            `json:"record_version"`
	HandshakeVersion    uint16            `json:"handshake_version"`
	CipherSuites        []uint16          `json:"cipher_suites"`
	CompressionMethods  []byte            `json:"compression_methods"`
	Extensions          []uint16          `json:"extensions"`
	SupportedCurves     []uint16          `json:"supported_curves,omitempty"`
	SupportedPoints     []byte            `json:"supported_points,omitempty"`
	ALPNProtocols       []string          `json:"alpn_protocols,omitempty"`
	KeyShareGroups      []uint16          `json:"key_share_groups,omitempty"`
	SignatureAlgorithms []uint16          `json:"signature_algorithms,omitempty"`
	RawExtensions       map[uint16][]byte `json:"raw_extensions,omitempty"`
}

// HTTP2Fingerprint содержит разобранные сетевые настройки HTTP/2.
type HTTP2Fingerprint struct {
	Settings          map[uint16]uint32 `json:"settings"`
	SettingsOrder     []uint16          `json:"settings_order"`
	ConnectionFlow    uint32            `json:"connection_flow"`
	PseudoHeaderOrder []string          `json:"pseudo_header_order"`
	HeaderOrder       []string          `json:"header_order"`
	CapturedHeaders   map[string]string `json:"captured_headers"`
}

// CapturedProfile содержит полный подлинный слепок браузера.
type CapturedProfile struct {
	TLS        *TLSFingerprint   `json:"tls"`
	HTTP2      *HTTP2Fingerprint `json:"http2"`
	CapturedAt time.Time         `json:"captured_at"`
}
