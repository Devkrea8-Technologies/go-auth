package goauth

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/go-auth/auth"
	"github.com/go-auth/config"
	"github.com/go-auth/types"
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
func (a *Auth) GetUserByID(ctx context.Context, userID primitive.ObjectID) (*types.User, error) {
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
