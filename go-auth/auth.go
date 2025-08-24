package goauth

import (
	"context"
	"fmt"

	"github.com/Devkrea8-Technologies/go-auth/auth"
	"github.com/Devkrea8-Technologies/go-auth/config"
	"github.com/Devkrea8-Technologies/go-auth/types"
)

// Auth represents the main authentication library interface
type Auth struct {
	service *auth.Service
	config  *config.Config
}

// New creates a new authentication instance
func New(cfg *config.Config) (*Auth, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	service, err := auth.NewService(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auth service: %w", err)
	}

	return &Auth{
		service: service,
		config:  cfg,
	}, nil
}

// Register registers a new user
func (a *Auth) Register(ctx context.Context, req *types.UserRegistration, baseURL string) (*types.AuthResponse, error) {
	return a.service.Register(ctx, req, baseURL)
}

// Login authenticates a user
func (a *Auth) Login(ctx context.Context, req *types.UserLogin) (*types.AuthResponse, error) {
	return a.service.Login(ctx, req)
}

// VerifyEmail verifies a user's email
func (a *Auth) VerifyEmail(ctx context.Context, req *types.EmailVerificationRequest) error {
	return a.service.VerifyEmail(ctx, req)
}

// RequestPasswordReset requests a password reset
func (a *Auth) RequestPasswordReset(ctx context.Context, req *types.PasswordResetRequest, baseURL string) error {
	return a.service.RequestPasswordReset(ctx, req, baseURL)
}

// ResetPassword resets a user's password
func (a *Auth) ResetPassword(ctx context.Context, req *types.PasswordResetConfirm) error {
	return a.service.ResetPassword(ctx, req)
}

// RefreshToken refreshes an access token
func (a *Auth) RefreshToken(ctx context.Context, refreshToken string) (*types.AuthResponse, error) {
	return a.service.RefreshToken(ctx, refreshToken)
}

// GetUserByID gets a user by ID
func (a *Auth) GetUserByID(ctx context.Context, userID interface{}) (*types.User, error) {
	return a.service.GetUserByID(ctx, userID)
}

// GetUserByEmail gets a user by email
func (a *Auth) GetUserByEmail(ctx context.Context, email string) (*types.User, error) {
	return a.service.GetUserByEmail(ctx, email)
}

// ValidateToken validates a JWT token and returns user info
func (a *Auth) ValidateToken(ctx context.Context, tokenString string) (*types.User, error) {
	return a.service.ValidateToken(ctx, tokenString)
}

// Close closes the authentication service
func (a *Auth) Close(ctx context.Context) error {
	return a.service.Close(ctx)
}

// GetConfig returns the current configuration
func (a *Auth) GetConfig() *config.Config {
	return a.config
}

// UpdateUserCustomFields updates custom fields for a user
func (a *Auth) UpdateUserCustomFields(ctx context.Context, userID interface{}, customFields map[string]interface{}) error {
	user, err := a.service.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	user.SetCustomFields(customFields)
	return a.service.UpdateUser(ctx, user)
}

// SetUserCustomField sets a single custom field for a user
func (a *Auth) SetUserCustomField(ctx context.Context, userID interface{}, key string, value interface{}) error {
	user, err := a.service.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	user.SetCustomField(key, value)
	return a.service.UpdateUser(ctx, user)
}

// GetUserCustomField gets a single custom field for a user
func (a *Auth) GetUserCustomField(ctx context.Context, userID interface{}, key string) (interface{}, bool, error) {
	user, err := a.service.GetUserByID(ctx, userID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, false, fmt.Errorf("user not found")
	}

	value, exists := user.GetCustomField(key)
	return value, exists, nil
}

// RemoveUserCustomField removes a custom field for a user
func (a *Auth) RemoveUserCustomField(ctx context.Context, userID interface{}, key string) error {
	user, err := a.service.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	user.RemoveCustomField(key)
	return a.service.UpdateUser(ctx, user)
}

// GetGoogleAuthURL generates Google OAuth authorization URL
func (a *Auth) GetGoogleAuthURL(state string) string {
	return a.service.GetGoogleAuthURL(state)
}

// AuthenticateWithGoogle authenticates a user with Google OAuth
func (a *Auth) AuthenticateWithGoogle(ctx context.Context, code string) (*types.AuthResponse, error) {
	return a.service.AuthenticateWithGoogle(ctx, code)
}

// GetTikTokAuthURL generates TikTok OAuth authorization URL
func (a *Auth) GetTikTokAuthURL(state string) string {
	return a.service.GetTikTokAuthURL(state)
}

// AuthenticateWithTikTok authenticates a user with TikTok OAuth
func (a *Auth) AuthenticateWithTikTok(ctx context.Context, code string) (*types.AuthResponse, error) {
	return a.service.AuthenticateWithTikTok(ctx, code)
}

// GetAppleAuthURL generates Apple Sign-In authorization URL
func (a *Auth) GetAppleAuthURL(state string) string {
	return a.service.GetAppleAuthURL(state)
}

// AuthenticateWithApple authenticates a user with Apple Sign-In
func (a *Auth) AuthenticateWithApple(ctx context.Context, code string) (*types.AuthResponse, error) {
	return a.service.AuthenticateWithApple(ctx, code)
}

// Setup2FA sets up 2FA for a user
func (a *Auth) Setup2FA(ctx context.Context, req *types.TwoFactorSetupRequest) (*types.TwoFactorSetupResponse, error) {
	return a.service.Setup2FA(ctx, req)
}

// Enable2FA enables 2FA for a user
func (a *Auth) Enable2FA(ctx context.Context, req *types.TwoFactorVerifyRequest) error {
	return a.service.Enable2FA(ctx, req)
}

// Disable2FA disables 2FA for a user
func (a *Auth) Disable2FA(ctx context.Context, req *types.TwoFactorDisableRequest) error {
	return a.service.Disable2FA(ctx, req)
}

// Verify2FA verifies a 2FA code
func (a *Auth) Verify2FA(ctx context.Context, req *types.TwoFactorVerifyRequest) (bool, error) {
	return a.service.Verify2FA(ctx, req)
}
