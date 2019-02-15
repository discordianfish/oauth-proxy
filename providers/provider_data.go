package providers

import (
	"net/url"
)

type ProviderData struct {
	ProviderName string
	ClientID     string
	ClientSecret string
	// LoginURL, RedeemURL are cached in runtime, only set/unset
	// them in cache-related methods
	LoginURL  *url.URL
	RedeemURL *url.URL
	// Config* attributes are attributes that are set in options and override
	// the cached attributes above
	ConfigLoginURL    *url.URL
	ConfigRedeemURL   *url.URL
	ValidateURL       *url.URL
	ProfileURL        *url.URL
	ProtectedResource *url.URL
	Scope             string
	ApprovalPrompt    string
}

func (p *ProviderData) Data() *ProviderData { return p }
