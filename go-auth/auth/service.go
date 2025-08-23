package auth

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/go-auth/config"
	"github.com/go-auth/database"
	"github.com/go-auth/email"
	"github.com/go-auth/types"
	"github.com/go-auth/utils"
)

// Service represents the main authentication service
type Service struct {
	config        *config.Config
	db            database.Database
	jwtManager    *JWTManager
	emailService  *email.EmailService
	googleService *GoogleService
}

// NewService creates a new authentication service
func NewService(cfg *config.Config) (*Service, error) {
	// Initialize database based on configuration
	var db database.Database
	var err error

	switch cfg.Database.Type {
	case config.DatabaseTypeMongoDB:
		db, err = database.NewMongoDB(cfg)
	case config.DatabaseTypePostgreSQL:
		db, err = database.NewPostgreSQL(cfg)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Database.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize JWT manager
	jwtManager := NewJWTManager(cfg)

	// Initialize email service
	emailService := email.NewEmailService(cfg)

	// Initialize Google OAuth service
	googleService := NewGoogleService(cfg)

	return &Service{
		config:        cfg,
		db:            db,
		jwtManager:    jwtManager,
		emailService:  emailService,
		googleService: googleService,
	}, nil
}

// Register registers a new user
func (s *Service) Register(ctx context.Context, req *types.UserRegistration, baseURL string) (*types.AuthResponse, error) {
	// Validate that at least one authentication method is provided
	if s.config.Security.RequirePassword && req.Password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Check if user already exists
	existingUser, err := s.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}
	if existingUser != nil {
		return nil, fmt.Errorf("user with email %s already exists", req.Email)
	}

	var hashedPassword string
	if req.Password != "" {
		// Hash password
		hashedPassword, err = utils.HashPassword(req.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
	}

	// Create user
	user := &types.User{
		Email:           req.Email,
		Password:        hashedPassword,
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		IsEmailVerified: false,
		IsActive:        true,
		CustomFields:    req.CustomFields,
	}

	// Add email verification if password is provided
	if hashedPassword != "" {
		verificationToken, err := utils.GenerateToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate verification token: %w", err)
		}

		user.EmailVerification = &types.EmailVerification{
			Token:     verificationToken,
			ExpiresAt: utils.GenerateExpirationTime(s.config.Security.EmailVerificationTTL),
		}
	}

	// Save user to database
	if err := s.db.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Send verification email if email verification is enabled
	if user.EmailVerification != nil && s.config.Security.RequireEmailVerification {
		if err := s.emailService.SendEmailVerification(
			user.Email,
			user.FirstName,
			user.EmailVerification.Token,
			baseURL,
		); err != nil {
			// Log error but don't fail registration
			// TODO: Add proper logging
		}
	}

	// Generate tokens
	accessToken, err := s.jwtManager.GenerateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &types.AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL.Seconds()),
	}, nil
}

// Login authenticates a user
func (s *Service) Login(ctx context.Context, req *types.UserLogin) (*types.AuthResponse, error) {
	// Get user by email
	user, err := s.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("invalid email or password")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("account is deactivated")
	}

	// Check if user has password authentication
	if user.Password == "" {
		return nil, fmt.Errorf("password authentication not available for this user")
	}

	// Verify password
	if !utils.CheckPassword(req.Password, user.Password) {
		return nil, fmt.Errorf("invalid email or password")
	}

	// Check email verification requirement
	if s.config.Security.RequireEmailVerification && !user.IsEmailVerified {
		return nil, fmt.Errorf("email verification required")
	}

	// Update last login
	if err := s.db.UpdateLastLogin(ctx, user.ID); err != nil {
		// Log error but don't fail login
		// TODO: Add proper logging
	}

	// Generate tokens
	accessToken, err := s.jwtManager.GenerateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &types.AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL.Seconds()),
	}, nil
}

// VerifyEmail verifies a user's email
func (s *Service) VerifyEmail(ctx context.Context, req *types.EmailVerificationRequest) error {
	// Get user by verification token
	user, err := s.db.GetUserByEmailVerificationToken(ctx, req.Token)
	if err != nil {
		return fmt.Errorf("failed to get user by verification token: %w", err)
	}
	if user == nil {
		return fmt.Errorf("invalid verification token")
	}

	// Check if token is expired
	if utils.IsTokenExpired(user.EmailVerification.ExpiresAt) {
		return fmt.Errorf("verification token has expired")
	}

	// Check if already verified
	if user.IsEmailVerified {
		return fmt.Errorf("email already verified")
	}

	// Update email verification status
	if err := s.db.UpdateEmailVerification(ctx, user.ID, true); err != nil {
		return fmt.Errorf("failed to update email verification: %w", err)
	}

	return nil
}

// RequestPasswordReset requests a password reset
func (s *Service) RequestPasswordReset(ctx context.Context, req *types.PasswordResetRequest, baseURL string) error {
	// Get user by email
	user, err := s.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		// Don't reveal if user exists or not
		return nil
	}

	// Generate password reset token
	resetToken, err := utils.GenerateToken()
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Update user with reset token
	user.PasswordReset = &types.PasswordReset{
		Token:     resetToken,
		ExpiresAt: utils.GenerateExpirationTime(s.config.Security.PasswordResetTTL),
	}

	if err := s.db.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to update user with reset token: %w", err)
	}

	// Send password reset email
	if err := s.emailService.SendPasswordReset(
		user.Email,
		user.FirstName,
		resetToken,
		baseURL,
	); err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	return nil
}

// ResetPassword resets a user's password
func (s *Service) ResetPassword(ctx context.Context, req *types.PasswordResetConfirm) error {
	// Get user by reset token
	user, err := s.db.GetUserByPasswordResetToken(ctx, req.Token)
	if err != nil {
		return fmt.Errorf("failed to get user by reset token: %w", err)
	}
	if user == nil {
		return fmt.Errorf("invalid reset token")
	}

	// Check if token is expired
	if utils.IsTokenExpired(user.PasswordReset.ExpiresAt) {
		return fmt.Errorf("reset token has expired")
	}

	// Check if token already used
	if user.PasswordReset.UsedAt != nil {
		return fmt.Errorf("reset token already used")
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	if err := s.db.UpdateUserPassword(ctx, user.ID, hashedPassword); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// RefreshToken refreshes an access token
func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*types.AuthResponse, error) {
	// Validate refresh token
	claims, err := s.jwtManager.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Get user by ID
	user, err := s.db.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("account is deactivated")
	}

	// Generate new access token
	accessToken, err := s.jwtManager.GenerateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &types.AuthResponse{
		User:        user,
		AccessToken: accessToken,
		ExpiresIn:   int64(s.config.JWT.AccessTokenTTL.Seconds()),
	}, nil
}

// GetUserByID gets a user by ID
func (s *Service) GetUserByID(ctx context.Context, userID interface{}) (*types.User, error) {
	return s.db.GetUserByID(ctx, userID)
}

// GetUserByEmail gets a user by email
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*types.User, error) {
	return s.db.GetUserByEmail(ctx, email)
}

// ValidateToken validates a JWT token and returns user info
func (s *Service) ValidateToken(ctx context.Context, tokenString string) (*types.User, error) {
	claims, err := s.jwtManager.ValidateToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	userID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token: %w", err)
	}

	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	if !user.IsActive {
		return nil, fmt.Errorf("account is deactivated")
	}

	return user, nil
}

// Close closes the service and database connection
func (s *Service) Close(ctx context.Context) error {
	return s.db.Close(ctx)
}

// UpdateUser updates a user in the database
func (s *Service) UpdateUser(ctx context.Context, user *types.User) error {
	return s.db.UpdateUser(ctx, user)
}

// GetGoogleAuthURL generates Google OAuth authorization URL
func (s *Service) GetGoogleAuthURL(state string) string {
	return s.googleService.GetAuthURL(state)
}

// AuthenticateWithGoogle authenticates a user with Google OAuth
func (s *Service) AuthenticateWithGoogle(ctx context.Context, code string) (*types.AuthResponse, error) {
	// Authenticate with Google
	googleUser, err := s.googleService.AuthenticateWithGoogle(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with Google: %w", err)
	}

	// Check if user already exists
	existingUser, err := s.db.GetUserByEmail(ctx, googleUser.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	var user *types.User
	if existingUser != nil {
		// User exists, update Google information
		existingUser.GoogleID = googleUser.GoogleID
		existingUser.GoogleProfile = googleUser.GoogleProfile
		existingUser.IsEmailVerified = googleUser.IsEmailVerified
		existingUser.FirstName = googleUser.FirstName
		existingUser.LastName = googleUser.LastName

		if err := s.db.UpdateUser(ctx, existingUser); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
		user = existingUser
	} else {
		// Create new user
		user = googleUser
		if err := s.db.CreateUser(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	}

	// Update last login
	if err := s.db.UpdateLastLogin(ctx, user.ID); err != nil {
		return nil, fmt.Errorf("failed to update last login: %w", err)
	}

	// Generate tokens
	accessToken, err := s.jwtManager.GenerateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &types.AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.JWT.AccessTokenTTL.Seconds()),
	}, nil
}
