package profile

import (
	"strconv"
	"strings"
	"sync"

	"github.com/bogdanfinn/tls-client/profiles"
)

var (
	profileOnce         sync.Once
	cachedChromeProfile profiles.ClientProfile
	cachedMaxMajor      int
)

// GetLatestChromeProfile находит максимально свежий вкомпилированный профиль Chrome
// в реестре bogdanfinn/tls-client и возвращает его вместе с номером мажорной версии.
func GetLatestChromeProfile() (profiles.ClientProfile, int) {
	profileOnce.Do(func() {
		maxVer := 0
		selected := profiles.DefaultClientProfile

		for key, profile := range profiles.MappedTLSClients {
			if !strings.HasPrefix(key, "chrome_") {
				continue
			}
			rawVer := strings.TrimPrefix(key, "chrome_")
			if idx := strings.Index(rawVer, "_"); idx != -1 {
				rawVer = rawVer[:idx]
			}
			ver, err := strconv.Atoi(rawVer)
			if err != nil {
				continue
			}
			if ver > maxVer {
				maxVer = ver
				selected = profile
			}
		}

		if maxVer == 0 {
			maxVer = 152
		}

		cachedChromeProfile = selected
		cachedMaxMajor = maxVer
	})

	return cachedChromeProfile, cachedMaxMajor
}
