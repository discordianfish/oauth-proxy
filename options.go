package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/mbland/hmacauth"
	"github.com/openshift/oauth-proxy/providers"
	"github.com/openshift/oauth-proxy/providers/openshift"
)

// Configuration Options that can be set by Command Line Flag, or Config File
type Options struct {
	ProxyPrefix      string        `flag:"proxy-prefix" cfg:"proxy-prefix"`
	ProxyWebSockets  bool          `flag:"proxy-websockets" cfg:"proxy_websockets"`
	HttpAddress      string        `flag:"http-address" cfg:"http_address"`
	HttpsAddress     string        `flag:"https-address" cfg:"https_address"`
	DebugAddress     string        `flag:"debug-address" cfg:"debug_address"`
	UpstreamFlush    time.Duration `flag:"upstream-flush" cfg:"upstream_flush"`
	RedirectURL      string        `flag:"redirect-url" cfg:"redirect_url"`
	ClientID         string        `flag:"client-id" cfg:"client_id" env:"OAUTH2_PROXY_CLIENT_ID"`
	ClientSecret     string        `flag:"client-secret" cfg:"client_secret" env:"OAUTH2_PROXY_CLIENT_SECRET"`
	ClientSecretFile string        `flag:"client-secret-file" cfg:"client_secret_file" env:"OAUTH2_PROXY_CLIENT_SECRET_FILE"`
	TLSCertFile      string        `flag:"tls-cert" cfg:"tls_cert_file"`
	TLSKeyFile       string        `flag:"tls-key" cfg:"tls_key_file"`
	TLSClientCAFiles []string      `flag:"tls-client-ca" cfg:"tls_client_ca"`

	AuthenticatedEmailsFile string `flag:"authenticated-emails-file" cfg:"authenticated_em
ails_file"`
	EmailDomains        []string `flag:"email-domain" cfg:"email_domains"`
	HtpasswdFile        string   `flag:"htpasswd-file" cfg:"htpasswd_file"`
	DisplayHtpasswdForm bool     `flag:"display-htpasswd-form" cfg:"display_htpasswd_form"`
	CustomTemplatesDir  string   `flag:"custom-templates-dir" cfg:"custom_templates_dir"`
	Footer              string   `flag:"footer" cfg:"footer"`

	OpenShiftSAR            string   `flag:"openshift-sar" cfg:"openshift_sar"`
	OpenShiftSARByHost      string   `flag:"openshift-sar-by-host" cfg:"openshift_sar_by_host"`
	OpenShiftReviewURL      string   `flag:"openshift-review-url" cfg:"openshift_review_url"`
	OpenShiftCAs            []string `flag:"openshift-ca" cfg:"openshift_ca"`
	OpenShiftServiceAccount string   `flag:"openshift-service-account" cfg:"openshift_service_account"`
	OpenShiftDelegateURLs   string   `flag:"openshift-delegate-urls" cfg:"openshift_delegate_urls"`

	CookieName       string        `flag:"cookie-name" cfg:"cookie_name" env:"OAUTH2_PROXY_COOKIE_NAME"`
	CookieSecret     string        `flag:"cookie-secret" cfg:"cookie_secret" env:"OAUTH2_PROXY_COOKIE_SECRET"`
	CookieSecretFile string        `flag:"cookie-secret-file" cfg:"cookie_secret_file" env:"OAUTH2_PROXY_COOKIE_SECRET_FILE"`
	CookieDomain     string        `flag:"cookie-domain" cfg:"cookie_domain" env:"OAUTH2_PROXY_COOKIE_DOMAIN"`
	CookieExpire     time.Duration `flag:"cookie-expire" cfg:"cookie_expire" env:"OAUTH2_PROXY_COOKIE_EXPIRE"`
	CookieRefresh    time.Duration `flag:"cookie-refresh" cfg:"cookie_refresh" env:"OAUTH2_PROXY_COOKIE_REFRESH"`
	CookieSecure     bool          `flag:"cookie-secure" cfg:"cookie_secure"`
	CookieHttpOnly   bool          `flag:"cookie-httponly" cfg:"cookie_httponly"`

	AzureTenant              string   `flag:"azure-tenant" cfg:"azure_tenant"`
	GitHubOrg                string   `flag:"github-org" cfg:"github_org"`
	GitHubTeam               string   `flag:"github-team" cfg:"github_team"`
	GoogleGroups             []string `flag:"google-group" cfg:"google_group"`
	GoogleAdminEmail         string   `flag:"google-admin-email" cfg:"google_admin_email"`
	GoogleServiceAccountJSON string   `flag:"google-service-account-json" cfg:"google_service_account_json"`

	Upstreams             []string `flag:"upstream" cfg:"upstreams"`
	BypassAuthExceptRegex []string `flag:"bypass-auth-except-for" cfg:"bypass_auth_except_for"`
	BypassAuthRegex       []string `flag:"bypass-auth-for" cfg:"bypass_auth_for"`
	SkipAuthRegex         []string `flag:"skip-auth-regex" cfg:"skip_auth_regex"`
	PassBasicAuth         bool     `flag:"pass-basic-auth" cfg:"pass_basic_auth"`
	BasicAuthPassword     string   `flag:"basic-auth-password" cfg:"basic_auth_password"`
	PassAccessToken       bool     `flag:"pass-access-token" cfg:"pass_access_token"`
	PassUserBearerToken   bool     `flag:"pass-user-bearer-token" cfg:"pass_user_bearer_token"`
	PassHostHeader        bool     `flag:"pass-host-header" cfg:"pass_host_header"`
	SkipProviderButton    bool     `flag:"skip-provider-button" cfg:"skip_provider_button"`
	PassUserHeaders       bool     `flag:"pass-user-headers" cfg:"pass_user_headers"`
	SSLInsecureSkipVerify bool     `flag:"ssl-insecure-skip-verify" cfg:"ssl_insecure_skip_verify"`
	SetXAuthRequest       bool     `flag:"set-xauthrequest" cfg:"set_xauthrequest"`
	SkipAuthPreflight     bool     `flag:"skip-auth-preflight" cfg:"skip_auth_preflight"`

	// These options allow for other providers besides Google, with
	// potential overrides.
	ApprovalPrompt    string `flag:"approval-prompt" cfg:"approval_prompt"`
	Provider          string `flag:"provider" cfg:"provider"`
	OIDCIssuerURL     string `flag:"oidc-issuer-url" cfg:"oidc_issuer_url"`
	LoginURL          string `flag:"login-url" cfg:"login_url"`
	RedeemURL         string `flag:"redeem-url" cfg:"redeem_url"`
	ProfileURL        string `flag:"profile-url" cfg:"profile_url"`
	ProtectedResource string `flag:"resource" cfg:"resource"`
	ValidateURL       string `flag:"validate-url" cfg:"validate_url"`
	Scope             string `flag:"scope" cfg:"scope"`
	RequestLogging    bool   `flag:"request-logging" cfg:"request_logging"`

	UpstreamCAs  []string `flag:"upstream-ca" cfg:"upstream_ca"`
	SignatureKey string   `flag:"signature-key" cfg:"signature_key" env:"OAUTH2_PROXY_SIGNATURE_KEY"`

	// internal values that are set after config validation
	redirectURL       *url.URL
	proxyURLs         []*url.URL
	CompiledAuthRegex []*regexp.Regexp
	CompiledSkipRegex []*regexp.Regexp
	provider          providers.Provider
	signatureData     *SignatureData
	oidcVerifier      *oidc.IDTokenVerifier
}

type SignatureData struct {
	hash crypto.Hash
	key  string
}

func NewOptions() *Options {
	return &Options{
		ProxyPrefix:         "/oauth2",
		ProxyWebSockets:     true,
		HttpAddress:         "127.0.0.1:4180",
		HttpsAddress:        ":443",
		UpstreamFlush:       time.Duration(5) * time.Millisecond,
		DisplayHtpasswdForm: true,
		CookieName:          "_oauth2_proxy",
		CookieSecure:        true,
		CookieHttpOnly:      true,
		CookieExpire:        time.Duration(168) * time.Hour,
		CookieRefresh:       time.Duration(0),
		SetXAuthRequest:     false,
		SkipAuthPreflight:   false,
		PassBasicAuth:       true,
		PassUserHeaders:     true,
		PassAccessToken:     false,
		PassUserBearerToken: false,
		PassHostHeader:      true,
		ApprovalPrompt:      "force",
		RequestLogging:      true,
	}
}

func parseURL(to_parse string, urltype string, msgs []string) (*url.URL, []string) {
	parsed, err := url.Parse(to_parse)
	if err != nil {
		return nil, append(msgs, fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, to_parse, err))
	}
	return parsed, msgs
}

func (o *Options) Validate() error {
	msgs := make([]string, 0)
	// allow the provider to default some values

	if o.CookieSecretFile != "" {
		if contents, err := ioutil.ReadFile(o.CookieSecretFile); err != nil {
			msgs = append(msgs, fmt.Sprintf("cannot read cookie-secret-file: %v", err))
		} else {
			o.CookieSecret = string(contents)
		}
	}
	if o.ClientSecretFile != "" {
		if contents, err := ioutil.ReadFile(o.ClientSecretFile); err != nil {
			msgs = append(msgs, fmt.Sprintf("cannot read client-secret-file: %v", err))
		} else {
			o.ClientSecret = string(contents)
		}
	}

	if len(o.Upstreams) < 1 {
		msgs = append(msgs, "missing setting: upstream")
	}
	if o.CookieSecret == "" {
		msgs = append(msgs, "missing setting: cookie-secret")
	}
	if o.ClientID == "" {
		msgs = append(msgs, "missing setting: client-id")
	}
	if o.ClientSecret == "" {
		msgs = append(msgs, "missing setting: client-secret")
	}
	if o.AuthenticatedEmailsFile == "" && len(o.EmailDomains) == 0 && o.HtpasswdFile == "" {
		msgs = append(msgs, "missing setting for email validation: email-domain or authenticated-emails-file required.\n      use email-domain=* to authorize all email addresses")
	}
	o.redirectURL, msgs = parseURL(o.RedirectURL, "redirect", msgs)

	o.proxyURLs = nil
	for _, u := range o.Upstreams {
		upstreamURL, err := url.Parse(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error parsing upstream=%q %s",
				upstreamURL, err))
		}
		if upstreamURL.Path == "" {
			upstreamURL.Path = "/"
		}
		o.proxyURLs = append(o.proxyURLs, upstreamURL)
	}

	if len(o.BypassAuthRegex) != 0 {
		o.SkipAuthRegex = o.BypassAuthRegex
	}

	if len(o.BypassAuthExceptRegex) != 0 && len(o.SkipAuthRegex) != 0 {
		msgs = append(msgs, "error: cannot set -skip-auth-regex and -bypass-auth-except-for together")
	}

	for _, u := range o.BypassAuthExceptRegex {
		CompiledRegex, err := regexp.Compile(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error compiling regex=%q %s", u, err))
		}
		o.CompiledAuthRegex = append(o.CompiledAuthRegex, CompiledRegex)
	}

	// Ensure paths under ProxyPrefix are still protected when using -bypass-auth-except-for
	if len(o.CompiledAuthRegex) > 0 {
		proxyRegex, err := regexp.Compile(o.ProxyPrefix + "*")
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error compiling regex=%q %s", o.ProxyPrefix+"*", err))
		}
		o.CompiledAuthRegex = append(o.CompiledAuthRegex, proxyRegex)
	}

	for _, u := range o.SkipAuthRegex {
		CompiledRegex, err := regexp.Compile(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error compiling regex=%q %s", u, err))
		}
		o.CompiledSkipRegex = append(o.CompiledSkipRegex, CompiledRegex)
	}
	msgs = parseProviderInfo(o, msgs)

	if o.PassAccessToken || (o.CookieRefresh != time.Duration(0)) {
		valid_cookie_secret_size := false
		for _, i := range []int{16, 24, 32} {
			if len(secretBytes(o.CookieSecret)) == i {
				valid_cookie_secret_size = true
			}
		}
		var decoded bool
		if string(secretBytes(o.CookieSecret)) != o.CookieSecret {
			decoded = true
		}
		if valid_cookie_secret_size == false {
			var suffix string
			if decoded {
				suffix = fmt.Sprintf(" note: cookie secret was base64 decoded from %q", o.CookieSecret)
			}
			msgs = append(msgs, fmt.Sprintf(
				"cookie_secret must be 16, 24, or 32 bytes "+
					"to create an AES cipher when "+
					"pass_access_token == true or "+
					"cookie_refresh != 0, but is %d bytes.%s",
				len(secretBytes(o.CookieSecret)), suffix))
		}
	}

	if o.CookieRefresh >= o.CookieExpire {
		msgs = append(msgs, fmt.Sprintf(
			"cookie_refresh (%s) must be less than "+
				"cookie_expire (%s)",
			o.CookieRefresh.String(),
			o.CookieExpire.String()))
	}

	if len(o.TLSClientCAFiles) > 0 && len(o.TLSKeyFile) == 0 && len(o.TLSCertFile) == 0 {
		msgs = append(msgs, "tls-client-ca requires tls-key-file or tls-cert-file to be set to listen on tls")
	}

	msgs = parseSignatureKey(o, msgs)
	msgs = validateCookieName(o, msgs)

	if o.SSLInsecureSkipVerify {
		insecureTransport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		http.DefaultClient = &http.Client{Transport: insecureTransport}
	}
	if len(msgs) != 0 {
		return fmt.Errorf("Invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseProviderInfo(o *Options, msgs []string) []string {
	data := &providers.ProviderData{
		Scope:          o.Scope,
		ClientID:       o.ClientID,
		ClientSecret:   o.ClientSecret,
		ApprovalPrompt: o.ApprovalPrompt,
	}
	data.LoginURL, msgs = parseURL(o.LoginURL, "login", msgs)
	data.RedeemURL, msgs = parseURL(o.RedeemURL, "redeem", msgs)
	data.ProfileURL, msgs = parseURL(o.ProfileURL, "profile", msgs)
	data.ValidateURL, msgs = parseURL(o.ValidateURL, "validate", msgs)
	data.ProtectedResource, msgs = parseURL(o.ProtectedResource, "resource", msgs)

	o.provider = providers.New(o.Provider, data)
	switch p := o.provider.(type) {
	case *openshift.OpenShiftProvider:
		defaults, err := p.LoadDefaults(o.OpenShiftServiceAccount, o.OpenShiftCAs, o.OpenShiftSAR, o.OpenShiftSARByHost, o.OpenShiftDelegateURLs)
		if err != nil {
			msgs = append(msgs, "couldn't load openshift provider defaults: "+err.Error())
		}
		if len(o.ClientID) == 0 {
			o.ClientID = defaults.ClientID
		}
		if len(o.ClientSecret) == 0 {
			o.ClientSecret = defaults.ClientSecret
		}
		if len(o.Scope) == 0 {
			o.Scope = defaults.Scope
		}
		if len(o.LoginURL) == 0 && defaults.LoginURL != nil {
			o.LoginURL = defaults.LoginURL.String()
		}
		if len(o.RedeemURL) == 0 && defaults.RedeemURL != nil {
			o.RedeemURL = defaults.RedeemURL.String()
		}
		if len(o.ValidateURL) == 0 && defaults.ValidateURL != nil {
			o.ValidateURL = defaults.ValidateURL.String()
		}
		if len(o.EmailDomains) == 0 {
			o.EmailDomains = []string{"*"}
		}
		if len(o.RedirectURL) == 0 {
			o.RedirectURL = "https:///"
		}

	case *providers.AzureProvider:
		p.Configure(o.AzureTenant)
	case *providers.GitHubProvider:
		p.SetOrgTeam(o.GitHubOrg, o.GitHubTeam)
	case *providers.GoogleProvider:
		if len(o.GoogleGroups) > 0 || o.GoogleAdminEmail != "" || o.GoogleServiceAccountJSON != "" {
			if len(o.GoogleGroups) < 1 {
				msgs = append(msgs, "missing setting: google-group")
			}
			if o.GoogleAdminEmail == "" {
				msgs = append(msgs, "missing setting: google-admin-email")
			}
			if o.GoogleServiceAccountJSON == "" {
				msgs = append(msgs, "missing setting: google-service-account-json")
			}
		}
		if o.GoogleServiceAccountJSON != "" {
			file, err := os.Open(o.GoogleServiceAccountJSON)
			if err != nil {
				msgs = append(msgs, "invalid Google credentials file: "+o.GoogleServiceAccountJSON)
			} else {
				p.SetGroupRestriction(o.GoogleGroups, o.GoogleAdminEmail, file)
			}
		}
	case *providers.OIDCProvider:
		if o.OIDCIssuerURL != "" {
			// Configure discoverable provider data.
			provider, err := oidc.NewProvider(context.Background(), o.OIDCIssuerURL)
			if err != nil {
				msgs = append(msgs, err.Error())
			}
			o.oidcVerifier = provider.Verifier(&oidc.Config{
				ClientID: o.ClientID,
			})
			o.LoginURL = provider.Endpoint().AuthURL
			o.RedeemURL = provider.Endpoint().TokenURL
			if o.Scope == "" {
				o.Scope = "openid email profile"
			}
		}

		if o.oidcVerifier == nil {
			msgs = append(msgs, "oidc provider requires an oidc issuer URL")
		} else {
			p.Verifier = o.oidcVerifier
		}
	case *providers.ProviderData:
		p.Scope = data.Scope
		p.ClientID = data.ClientID
		p.ClientSecret = data.ClientSecret
		p.ApprovalPrompt = data.ApprovalPrompt
		p.LoginURL = data.LoginURL
		p.RedeemURL = data.RedeemURL
		p.ProfileURL = data.ProfileURL
		p.ValidateURL = data.ValidateURL
	}
	return msgs
}

func parseSignatureKey(o *Options, msgs []string) []string {
	if o.SignatureKey == "" {
		return msgs
	}

	components := strings.Split(o.SignatureKey, ":")
	if len(components) != 2 {
		return append(msgs, "invalid signature hash:key spec: "+
			o.SignatureKey)
	}

	algorithm, secretKey := components[0], components[1]
	if hash, err := hmacauth.DigestNameToCryptoHash(algorithm); err != nil {
		return append(msgs, "unsupported signature hash algorithm: "+
			o.SignatureKey)
	} else {
		o.signatureData = &SignatureData{hash, secretKey}
	}
	return msgs
}

func validateCookieName(o *Options, msgs []string) []string {
	cookie := &http.Cookie{Name: o.CookieName}
	if cookie.String() == "" {
		return append(msgs, fmt.Sprintf("invalid cookie name: %q", o.CookieName))
	}
	return msgs
}

func addPadding(secret string) string {
	padding := len(secret) % 4
	switch padding {
	case 1:
		return secret + "==="
	case 2:
		return secret + "=="
	case 3:
		return secret + "="
	default:
		return secret
	}
}

// secretBytes attempts to base64 decode the secret, if that fails it treats the secret as binary
func secretBytes(secret string) []byte {
	b, err := base64.URLEncoding.DecodeString(addPadding(secret))
	if err == nil {
		return []byte(addPadding(string(b)))
	}
	return []byte(secret)
}
