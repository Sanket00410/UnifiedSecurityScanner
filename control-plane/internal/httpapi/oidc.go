package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	sessionCookieName      = "uss_session"
	oidcStateCookieName    = "uss_oidc_state"
	oidcVerifierCookieName = "uss_oidc_verifier"
)

type oidcMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type oidcUserInfo struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
}

func (s *Server) oidcConfigured() bool {
	return strings.TrimSpace(s.cfg.OIDCIssuerURL) != "" &&
		strings.TrimSpace(s.cfg.OIDCClientID) != "" &&
		strings.TrimSpace(s.cfg.OIDCClientSecret) != "" &&
		strings.TrimSpace(s.cfg.OIDCRedirectURL) != ""
}

func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}
	if !s.oidcConfigured() {
		s.writeError(w, http.StatusServiceUnavailable, "oidc_not_configured", "oidc sso is not configured")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	metadata, err := s.fetchOIDCMetadata(ctx)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, "oidc_discovery_failed", "oidc discovery failed")
		return
	}

	state, err := randomHex(16)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "oidc_state_failed", "oidc state generation failed")
		return
	}
	verifier, err := randomHex(32)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "oidc_verifier_failed", "oidc verifier generation failed")
		return
	}

	query := url.Values{}
	query.Set("client_id", s.cfg.OIDCClientID)
	query.Set("response_type", "code")
	query.Set("redirect_uri", s.cfg.OIDCRedirectURL)
	query.Set("scope", "openid profile email")
	query.Set("state", state)
	query.Set("code_challenge", pkceChallenge(verifier))
	query.Set("code_challenge_method", "S256")

	redirectURL, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, "oidc_authorize_url_invalid", "oidc authorization endpoint is invalid")
		return
	}
	redirectURL.RawQuery = query.Encode()

	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    state,
		Path:     "/",
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     oidcVerifierCookieName,
		Value:    verifier,
		Path:     "/",
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})

	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}
	if !s.oidcConfigured() {
		s.writeError(w, http.StatusServiceUnavailable, "oidc_not_configured", "oidc sso is not configured")
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if code == "" || state == "" {
		s.writeError(w, http.StatusBadRequest, "oidc_callback_invalid", "oidc callback requires code and state")
		return
	}

	stateCookie, err := r.Cookie(oidcStateCookieName)
	if err != nil || strings.TrimSpace(stateCookie.Value) == "" || stateCookie.Value != state {
		s.writeError(w, http.StatusUnauthorized, "oidc_state_invalid", "oidc state validation failed")
		return
	}

	verifierCookie, err := r.Cookie(oidcVerifierCookieName)
	if err != nil || strings.TrimSpace(verifierCookie.Value) == "" {
		s.writeError(w, http.StatusUnauthorized, "oidc_verifier_missing", "oidc verifier cookie is missing")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	metadata, err := s.fetchOIDCMetadata(ctx)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, "oidc_discovery_failed", "oidc discovery failed")
		return
	}

	tokenResponse, err := s.exchangeOIDCCode(ctx, metadata, code, verifierCookie.Value)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, "oidc_token_exchange_failed", "oidc token exchange failed")
		return
	}

	userInfo, err := s.fetchOIDCUserInfo(ctx, metadata, tokenResponse.AccessToken)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, "oidc_userinfo_failed", "oidc user info lookup failed")
		return
	}
	if strings.TrimSpace(userInfo.Subject) == "" || strings.TrimSpace(userInfo.Email) == "" {
		s.writeError(w, http.StatusBadGateway, "oidc_userinfo_invalid", "oidc user info did not include required claims")
		return
	}

	session, err := s.store.CreateOIDCSession(ctx, strings.TrimSpace(s.cfg.OIDCIssuerURL), userInfo.Subject, userInfo.Email, firstNonEmpty(userInfo.Name, userInfo.PreferredUsername, userInfo.Email))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "oidc_session_failed", "oidc session could not be created")
		return
	}

	s.clearTemporaryOIDCCookies(w, r)

	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    session.PlaintextToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	}
	if session.Token.ExpiresAt != nil {
		cookie.Expires = *session.Token.ExpiresAt
		cookie.MaxAge = int(time.Until(*session.Token.ExpiresAt).Seconds())
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, s.primaryUIRedirectPath(), http.StatusTemporaryRedirect)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.clearSessionCookie(w, r)
		http.Redirect(w, r, s.primaryUIRedirectPath(), http.StatusTemporaryRedirect)
	case http.MethodPost:
		s.clearSessionCookie(w, r)
		w.WriteHeader(http.StatusNoContent)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) clearTemporaryOIDCCookies(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{oidcStateCookieName, oidcVerifierCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   r.TLS != nil,
		})
	}
}

func (s *Server) fetchOIDCMetadata(ctx context.Context) (oidcMetadata, error) {
	discoveryURL := strings.TrimRight(strings.TrimSpace(s.cfg.OIDCIssuerURL), "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return oidcMetadata{}, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oidcMetadata{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return oidcMetadata{}, fmt.Errorf("unexpected discovery status: %d", resp.StatusCode)
	}

	var metadata oidcMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return oidcMetadata{}, err
	}
	if strings.TrimSpace(metadata.AuthorizationEndpoint) == "" || strings.TrimSpace(metadata.TokenEndpoint) == "" || strings.TrimSpace(metadata.UserInfoEndpoint) == "" {
		return oidcMetadata{}, fmt.Errorf("oidc discovery metadata is incomplete")
	}

	return metadata, nil
}

func (s *Server) exchangeOIDCCode(ctx context.Context, metadata oidcMetadata, code string, verifier string) (oidcTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", s.cfg.OIDCClientID)
	form.Set("client_secret", s.cfg.OIDCClientSecret)
	form.Set("redirect_uri", s.cfg.OIDCRedirectURL)
	form.Set("code", code)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return oidcTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oidcTokenResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return oidcTokenResponse{}, fmt.Errorf("unexpected token status: %d", resp.StatusCode)
	}

	var tokenResponse oidcTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return oidcTokenResponse{}, err
	}
	if strings.TrimSpace(tokenResponse.AccessToken) == "" {
		return oidcTokenResponse{}, fmt.Errorf("missing access token")
	}

	return tokenResponse, nil
}

func (s *Server) fetchOIDCUserInfo(ctx context.Context, metadata oidcMetadata, accessToken string) (oidcUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadata.UserInfoEndpoint, nil)
	if err != nil {
		return oidcUserInfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oidcUserInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return oidcUserInfo{}, fmt.Errorf("unexpected userinfo status: %d", resp.StatusCode)
	}

	var userInfo oidcUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return oidcUserInfo{}, err
	}

	return userInfo, nil
}

func randomHex(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(verifier)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
