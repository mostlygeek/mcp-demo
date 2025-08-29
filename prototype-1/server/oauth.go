package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type OpenIDConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

type UserInfo struct {
	Sub      string `json:"sub"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Picture  string `json:"picture"`
	UserName string `json:"username"`
}

func (u *UserInfo) String() string {
	return fmt.Sprintf(`User Information:
    username: %s
    name: %s
    email: %s
    picture: %s
    sub: %s`,
		u.UserName, u.Name, u.Email, u.Picture, u.Sub)
}

type Validator struct {
	discoveryURL string
}

func NewOAuthValidator(discoveryURL string) *Validator {
	return &Validator{
		discoveryURL: discoveryURL,
	}
}

func (v *Validator) FetchOpenIDConfiguration() (*OpenIDConfiguration, error) {
	resp, err := http.Get(v.discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OpenID configuration: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenID configuration endpoint returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OpenID configuration response: %v", err)
	}

	var config OpenIDConfiguration
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("failed to parse OpenID configuration: %v", err)
	}

	return &config, nil
}

func (v *Validator) FetchUserInfoFromOauthServer(accessToken string) (*UserInfo, error) {
	config, err := v.FetchOpenIDConfiguration()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OpenID configuration: %v", err)
	}

	if config.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("userinfo endpoint not available")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", config.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch userinfo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read userinfo response: %v", err)
	}

	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo: %v", err)
	}

	return &userInfo, nil
}

func (v *Validator) ValidateAccessToken(accessToken string) (*UserInfo, error) {
	userInfo, err := v.FetchUserInfoFromOauthServer(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate access token: %v", err)
	}

	if userInfo.Sub == "" {
		return nil, fmt.Errorf("invalid user info: missing subject")
	}

	return userInfo, nil
}

func ExtractBearerToken(authHeader string) string {
	if authHeader == "" {
		return ""
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}
