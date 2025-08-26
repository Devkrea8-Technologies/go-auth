package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Devkrea8-Technologies/go-auth/go-auth/config"
	"github.com/Devkrea8-Technologies/go-auth/go-auth/types"
)

// TikTokService handles TikTok OAuth operations
type TikTokService struct {
	config *config.Config
}

// NewTikTokService creates a new TikTok OAuth service
func NewTikTokService(cfg *config.Config) *TikTokService {
	return &TikTokService{
		config: cfg,
	}
}

// TikTokTokenResponse represents TikTok OAuth token response
type TikTokTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
	OpenID       string `json:"open_id"`
}

// TikTokUserInfo represents TikTok user information
type TikTokUserInfo struct {
	ID             string `json:"id"`
	Username       string `json:"username"`
	DisplayName    string `json:"display_name"`
	ProfilePicture string `json:"profile_picture"`
	Bio            string `json:"bio"`
	FollowerCount  int    `json:"follower_count"`
	FollowingCount int    `json:"following_count"`
	LikesCount     int    `json:"likes_count"`
	VideoCount     int    `json:"video_count"`
	IsVerified     bool   `json:"is_verified"`
	IsPrivate      bool   `json:"is_private"`
}

// GetAuthURL generates TikTok OAuth authorization URL
func (t *TikTokService) GetAuthURL(state string) string {
	if !t.config.TikTok.Enabled {
		return ""
	}

	params := url.Values{}
	params.Add("client_key", t.config.TikTok.ClientID)
	params.Add("redirect_uri", t.config.TikTok.RedirectURL)
	params.Add("scope", "user.info.basic,video.list")
	params.Add("response_type", "code")
	params.Add("state", state)

	return fmt.Sprintf("https://www.tiktok.com/v2/auth/authorize/?%s", params.Encode())
}

// ExchangeCodeForToken exchanges authorization code for access token
func (t *TikTokService) ExchangeCodeForToken(ctx context.Context, code string) (*TikTokTokenResponse, error) {
	if !t.config.TikTok.Enabled {
		return nil, fmt.Errorf("TikTok OAuth is not enabled")
	}

	data := url.Values{}
	data.Set("client_key", t.config.TikTok.ClientID)
	data.Set("client_secret", t.config.TikTok.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", t.config.TikTok.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://open.tiktokapis.com/v2/oauth/token/", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TikTok OAuth error: %s", resp.Status)
	}

	var tokenResp TikTokTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// GetUserInfo retrieves user information from TikTok
func (t *TikTokService) GetUserInfo(ctx context.Context, accessToken string) (*TikTokUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://open.tiktokapis.com/v2/user/info/", nil)
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

	var userInfo TikTokUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &userInfo, nil
}

// AuthenticateWithTikTok authenticates a user with TikTok OAuth
func (t *TikTokService) AuthenticateWithTikTok(ctx context.Context, code string) (*types.User, error) {
	if !t.config.TikTok.Enabled {
		return nil, fmt.Errorf("TikTok OAuth is not enabled")
	}

	// Exchange code for token
	tokenResp, err := t.ExchangeCodeForToken(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user info
	userInfo, err := t.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Convert to our User type
	user := &types.User{
		TikTokID:        userInfo.ID,
		FirstName:       userInfo.DisplayName,
		LastName:        "",    // TikTok doesn't provide separate first/last name
		IsEmailVerified: false, // TikTok doesn't provide email verification status
		IsActive:        true,
		TikTokProfile: &types.TikTokProfile{
			ID:             userInfo.ID,
			Username:       userInfo.Username,
			DisplayName:    userInfo.DisplayName,
			ProfilePicture: userInfo.ProfilePicture,
			Bio:            userInfo.Bio,
			FollowerCount:  userInfo.FollowerCount,
			FollowingCount: userInfo.FollowingCount,
			LikesCount:     userInfo.LikesCount,
			VideoCount:     userInfo.VideoCount,
			IsVerified:     userInfo.IsVerified,
			IsPrivate:      userInfo.IsPrivate,
		},
	}

	return user, nil
}
