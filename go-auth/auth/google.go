package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Devkrea8-Technologies/go-auth/config"
	"github.com/Devkrea8-Technologies/go-auth/types"
)

// GoogleService handles Google OAuth operations
type GoogleService struct {
	config *config.Config
}

// NewGoogleService creates a new Google OAuth service
func NewGoogleService(cfg *config.Config) *GoogleService {
	return &GoogleService{
		config: cfg,
	}
}

// GoogleTokenResponse represents Google OAuth token response
type GoogleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

// GoogleUserInfo represents Google user information
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

// GetAuthURL generates Google OAuth authorization URL
func (g *GoogleService) GetAuthURL(state string) string {
	if !g.config.Google.Enabled {
		return ""
	}

	params := url.Values{}
	params.Add("client_id", g.config.Google.ClientID)
	params.Add("redirect_uri", g.config.Google.RedirectURL)
	params.Add("scope", "openid email profile")
	params.Add("response_type", "code")
	params.Add("access_type", "offline")
	params.Add("prompt", "consent")
	if state != "" {
		params.Add("state", state)
	}

	return fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?%s", params.Encode())
}

// ExchangeCodeForToken exchanges authorization code for access token
func (g *GoogleService) ExchangeCodeForToken(ctx context.Context, code string) (*GoogleTokenResponse, error) {
	if !g.config.Google.Enabled {
		return nil, fmt.Errorf("Google OAuth is not enabled")
	}

	data := url.Values{}
	data.Set("client_id", g.config.Google.ClientID)
	data.Set("client_secret", g.config.Google.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", g.config.Google.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://oauth2.googleapis.com/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Google OAuth error: %s", resp.Status)
	}

	var tokenResp GoogleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// GetUserInfo retrieves user information from Google
func (g *GoogleService) GetUserInfo(ctx context.Context, accessToken string) (*GoogleUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: %s", resp.Status)
	}

	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &userInfo, nil
}

// AuthenticateWithGoogle authenticates a user with Google OAuth
func (g *GoogleService) AuthenticateWithGoogle(ctx context.Context, code string) (*types.User, error) {
	if !g.config.Google.Enabled {
		return nil, fmt.Errorf("Google OAuth is not enabled")
	}

	// Exchange code for token
	tokenResp, err := g.ExchangeCodeForToken(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user info
	userInfo, err := g.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Convert to our User type
	user := &types.User{
		GoogleID:        userInfo.ID,
		Email:           userInfo.Email,
		FirstName:       userInfo.GivenName,
		LastName:        userInfo.FamilyName,
		IsEmailVerified: userInfo.VerifiedEmail,
		IsActive:        true,
		GoogleProfile: &types.GoogleProfile{
			ID:            userInfo.ID,
			Email:         userInfo.Email,
			VerifiedEmail: userInfo.VerifiedEmail,
			Name:          userInfo.Name,
			GivenName:     userInfo.GivenName,
			FamilyName:    userInfo.FamilyName,
			Picture:       userInfo.Picture,
			Locale:        userInfo.Locale,
		},
	}

	return user, nil
}
