package types

type BrowserType string

const (
	BrowserChrome BrowserType = "chrome"
	BrowserEdge   BrowserType = "edge"
)

type BrowserVersion struct {
	FullVersion  string
	MajorVersion int
}

type BrowserInfo struct {
	Path string
	Type BrowserType
}
