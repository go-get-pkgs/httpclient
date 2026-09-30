package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-get-pkgs/httpclient/internal/sniffer"
	"github.com/go-get-pkgs/httpclient/internal/types"

	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// BuildClientProfile преобразует сырой CapturedProfile в рабочий profiles.ClientProfile для tls-client.
// Если в CapturedProfile версия не определена, используется fallbackVer из VersionResolver.
func BuildClientProfile(cap *types.CapturedProfile, browserType types.BrowserType, fallbackVer types.BrowserVersion) (profiles.ClientProfile, types.BrowserVersion, error) {
	if cap == nil || cap.TLS == nil {
		return profiles.ClientProfile{}, types.BrowserVersion{}, fmt.Errorf("empty captured profile")
	}

	// 1. Извлекаем версию из заголовков захваченного профиля либо берем динамический fallback
	bVer := fallbackVer
	if cap.HTTP2 != nil {
		if ua, ok := cap.HTTP2.CapturedHeaders["user-agent"]; ok {
			if parsed, ok := parseVersionFromUA(ua); ok {
				bVer = parsed
			}
		}
	}

	clientName := "Chrome"
	if browserType == types.BrowserEdge {
		clientName = "Edge"
	}

	// 2. Фабрика ClientHelloSpec для uTLS
	specFactory := func() (tls.ClientHelloSpec, error) {
		// Подготовка Ciphers: заменяем GREASE на placeholder
		var ciphers []uint16
		for _, c := range cap.TLS.CipherSuites {
			if sniffer.IsGREASE(c) {
				ciphers = append(ciphers, tls.GREASE_PLACEHOLDER)
			} else {
				ciphers = append(ciphers, c)
			}
		}

		// Подготовка Curves
		var curves []tls.CurveID
		for _, curve := range cap.TLS.SupportedCurves {
			if sniffer.IsGREASE(curve) {
				curves = append(curves, tls.CurveID(tls.GREASE_PLACEHOLDER))
			} else {
				curves = append(curves, tls.CurveID(curve))
			}
		}

		// Подготовка Signature Schemes
		var sigAlgs []tls.SignatureScheme
		for _, s := range cap.TLS.SignatureAlgorithms {
			if sniffer.IsGREASE(s) {
				sigAlgs = append(sigAlgs, tls.SignatureScheme(tls.GREASE_PLACEHOLDER))
			} else {
				sigAlgs = append(sigAlgs, tls.SignatureScheme(s))
			}
		}

		// Сборка Extensions в том порядке, в котором их прислал браузер
		var extensions []tls.TLSExtension
		for _, extID := range cap.TLS.Extensions {
			if sniffer.IsGREASE(extID) {
				extensions = append(extensions, &tls.UtlsGREASEExtension{})
				continue
			}

			switch extID {
			case 0: // server_name (SNI)
				extensions = append(extensions, &tls.SNIExtension{})

			case 5: // status_request (OCSP)
				extensions = append(extensions, &tls.StatusRequestExtension{})

			case 10: // supported_groups
				extensions = append(extensions, &tls.SupportedCurvesExtension{Curves: curves})

			case 11: // ec_point_formats
				extensions = append(extensions, &tls.SupportedPointsExtension{
					SupportedPoints: cap.TLS.SupportedPoints,
				})

			case 13: // signature_algorithms
				extensions = append(extensions, &tls.SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: sigAlgs,
				})

			case 16: // ALPN
				extensions = append(extensions, &tls.ALPNExtension{
					AlpnProtocols: cap.TLS.ALPNProtocols,
				})

			case 18: // SCT
				extensions = append(extensions, &tls.SCTExtension{})

			case 23: // extended_master_secret
				extensions = append(extensions, &tls.ExtendedMasterSecretExtension{})

			case 27: // compress_certificate
				extensions = append(extensions, &tls.UtlsCompressCertExtension{
					Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
				})

			case 35: // session_ticket
				extensions = append(extensions, &tls.SessionTicketExtension{})

			case 43: // supported_versions
				extensions = append(extensions, &tls.SupportedVersionsExtension{
					Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					},
				})

			case 45: // psk_key_exchange_modes
				extensions = append(extensions, &tls.PSKKeyExchangeModesExtension{
					Modes: []uint8{tls.PskModeDHE},
				})

			case 51: // key_share
				var keyShares []tls.KeyShare
				for _, g := range cap.TLS.KeyShareGroups {
					if sniffer.IsGREASE(g) {
						keyShares = append(keyShares, tls.KeyShare{
							Group: tls.CurveID(tls.GREASE_PLACEHOLDER),
							Data:  []byte{0},
						})
					} else {
						keyShares = append(keyShares, tls.KeyShare{Group: tls.CurveID(g)})
					}
				}
				extensions = append(extensions, &tls.KeyShareExtension{KeyShares: keyShares})

			case 17613: // application_settings (ALPS)
				extensions = append(extensions, &tls.ApplicationSettingsExtensionNew{
					SupportedProtocols: []string{"h2"},
				})

			case 65037: // ECH (Encrypted Client Hello)
				extensions = append(extensions, tls.BoringGREASEECH())

			case 65281: // renegotiation_info
				extensions = append(extensions, &tls.RenegotiationInfoExtension{
					Renegotiation: tls.RenegotiateOnceAsClient,
				})

			default:
				rawData := cap.TLS.RawExtensions[extID]
				extensions = append(extensions, &tls.GenericExtension{
					Id:   extID,
					Data: rawData,
				})
			}
		}

		return tls.ClientHelloSpec{
			CipherSuites:       ciphers,
			CompressionMethods: cap.TLS.CompressionMethods,
			Extensions:         extensions,
		}, nil
	}

	// 3. Настройки HTTP/2
	h2Settings := make(map[http2.SettingID]uint32)
	var h2SettingsOrder []http2.SettingID
	connFlow := uint32(15663105)
	pseudoOrder := []string{":method", ":authority", ":scheme", ":path"}

	if cap.HTTP2 != nil {
		for k, v := range cap.HTTP2.Settings {
			h2Settings[http2.SettingID(k)] = v
		}
		for _, k := range cap.HTTP2.SettingsOrder {
			h2SettingsOrder = append(h2SettingsOrder, http2.SettingID(k))
		}
		if cap.HTTP2.ConnectionFlow > 0 {
			connFlow = cap.HTTP2.ConnectionFlow
		}
		if len(cap.HTTP2.PseudoHeaderOrder) > 0 {
			pseudoOrder = cap.HTTP2.PseudoHeaderOrder
		}
	}

	helloID := tls.ClientHelloID{
		Client:               clientName,
		Version:              strconv.Itoa(bVer.MajorVersion),
		RandomExtensionOrder: false,
		SpecFactory:          specFactory,
	}

	// Вызов со всеми 14 аргументами tls-client v1.15.1
	profile := profiles.NewClientProfile(
		helloID,
		h2Settings,
		h2SettingsOrder,
		pseudoOrder,
		connFlow,
		nil,   // priorities
		nil,   // headerPriority
		0,     // streamID
		false, // allowHTTP
		nil,   // http3Settings
		nil,   // http3SettingsOrder
		0,     // http3PriorityParam
		nil,   // http3PseudoHeaderOrder
		false, // http3SendGreaseFrames
	)

	return profile, bVer, nil
}

func parseVersionFromUA(ua string) (types.BrowserVersion, bool) {
	parts := strings.Fields(ua)
	for _, p := range parts {
		if strings.HasPrefix(p, "Chrome/") || strings.HasPrefix(p, "HeadlessChrome/") || strings.HasPrefix(p, "Edg/") {
			sub := strings.Split(p, "/")
			if len(sub) < 2 {
				continue
			}
			val := sub[1]
			subParts := strings.Split(val, ".")
			if len(subParts) > 0 {
				if m, err := strconv.Atoi(subParts[0]); err == nil {
					return types.BrowserVersion{
						FullVersion:  val,
						MajorVersion: m,
					}, true
				}
			}
		}
	}
	return types.BrowserVersion{}, false
}

// SaveCapturedProfile сохраняет слепок в файл кэша.
func SaveCapturedProfile(path string, cap *types.CapturedProfile) error {
	data, err := json.MarshalIndent(cap, "", "  ")
	if err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	return os.WriteFile(path, data, 0o644)
}

// LoadCapturedProfile читает слепок из файла кэша.
func LoadCapturedProfile(path string, maxAge time.Duration) (*types.CapturedProfile, bool) {
	info, err := os.Stat(path)
	if err != nil || time.Since(info.ModTime()) > maxAge {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var cap types.CapturedProfile
	if err := json.Unmarshal(data, &cap); err != nil {
		return nil, false
	}
	return &cap, true
}
