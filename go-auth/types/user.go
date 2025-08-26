package types

import (
	"time"
)

// CustomFields interface allows users to define custom fields
type CustomFields interface {
	// GetCustomFields returns a map of custom field names to values
	GetCustomFields() map[string]interface{}
	// SetCustomFields sets custom fields from a map
	SetCustomFields(fields map[string]interface{})
}

// User represents a user in the authentication system
type User struct {
	ID                interface{}        `bson:"_id,omitempty" json:"id,omitempty"`
	Email             string             `bson:"email" json:"email"`
	Password          string             `bson:"password" json:"-"`
	FirstName         string             `bson:"first_name" json:"first_name"`
	LastName          string             `bson:"last_name" json:"last_name"`
	IsEmailVerified   bool               `bson:"is_email_verified" json:"is_email_verified"`
	EmailVerification *EmailVerification `bson:"email_verification,omitempty" json:"email_verification,omitempty"`
	PasswordReset     *PasswordReset     `bson:"password_reset,omitempty" json:"password_reset,omitempty"`
	CreatedAt         time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt         time.Time          `bson:"updated_at" json:"updated_at"`
	LastLoginAt       *time.Time         `bson:"last_login_at,omitempty" json:"last_login_at,omitempty"`
	IsActive          bool               `bson:"is_active" json:"is_active"`

	// Google OAuth support
	GoogleID      string         `bson:"google_id,omitempty" json:"google_id,omitempty"`
	GoogleProfile *GoogleProfile `bson:"google_profile,omitempty" json:"google_profile,omitempty"`

	// TikTok OAuth support
	TikTokID      string         `bson:"tiktok_id,omitempty" json:"tiktok_id,omitempty"`
	TikTokProfile *TikTokProfile `bson:"tiktok_profile,omitempty" json:"tiktok_profile,omitempty"`

	// Apple Sign-In support
	AppleID      string        `bson:"apple_id,omitempty" json:"apple_id,omitempty"`
	AppleProfile *AppleProfile `bson:"apple_profile,omitempty" json:"apple_profile,omitempty"`

	// 2FA support
	TwoFactorEnabled     bool     `bson:"two_factor_enabled" json:"two_factor_enabled"`
	TwoFactorSecret      string   `bson:"two_factor_secret,omitempty" json:"two_factor_secret,omitempty"`
	TwoFactorBackupCodes []string `bson:"two_factor_backup_codes,omitempty" json:"two_factor_backup_codes,omitempty"`

	// Custom fields support
	CustomFields map[string]interface{} `bson:"custom_fields,omitempty" json:"custom_fields,omitempty"`
}

// GetCustomFields implements CustomFields interface
func (u *User) GetCustomFields() map[string]interface{} {
	if u.CustomFields == nil {
		u.CustomFields = make(map[string]interface{})
	}
	return u.CustomFields
}

// SetCustomFields implements CustomFields interface
func (u *User) SetCustomFields(fields map[string]interface{}) {
	u.CustomFields = fields
}

// SetCustomField sets a single custom field
func (u *User) SetCustomField(key string, value interface{}) {
	if u.CustomFields == nil {
		u.CustomFields = make(map[string]interface{})
	}
	u.CustomFields[key] = value
}

// GetCustomField gets a single custom field
func (u *User) GetCustomField(key string) (interface{}, bool) {
	if u.CustomFields == nil {
		return nil, false
	}
	value, exists := u.CustomFields[key]
	return value, exists
}

// RemoveCustomField removes a custom field
func (u *User) RemoveCustomField(key string) {
	if u.CustomFields != nil {
		delete(u.CustomFields, key)
	}
}

// EmailVerification represents email verification data
type EmailVerification struct {
	Token      string     `bson:"token" json:"token"`
	ExpiresAt  time.Time  `bson:"expires_at" json:"expires_at"`
	VerifiedAt *time.Time `bson:"verified_at,omitempty" json:"verified_at,omitempty"`
}

// PasswordReset represents password reset data
type PasswordReset struct {
	Token     string     `bson:"token" json:"token"`
	ExpiresAt time.Time  `bson:"expires_at" json:"expires_at"`
	UsedAt    *time.Time `bson:"used_at,omitempty" json:"used_at,omitempty"`
}

// UserRegistration represents user registration request
type UserRegistration struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`

	// Custom fields support
	CustomFields map[string]interface{} `json:"custom_fields,omitempty"`
}

// GetCustomFields implements CustomFields interface
func (ur *UserRegistration) GetCustomFields() map[string]interface{} {
	if ur.CustomFields == nil {
		ur.CustomFields = make(map[string]interface{})
	}
	return ur.CustomFields
}

// SetCustomFields implements CustomFields interface
func (ur *UserRegistration) SetCustomFields(fields map[string]interface{}) {
	ur.CustomFields = fields
}

// SetCustomField sets a single custom field
func (ur *UserRegistration) SetCustomField(key string, value interface{}) {
	if ur.CustomFields == nil {
		ur.CustomFields = make(map[string]interface{})
	}
	ur.CustomFields[key] = value
}

// UserLogin represents user login request
type UserLogin struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// PasswordResetRequest represents password reset request
type PasswordResetRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// PasswordResetConfirm represents password reset confirmation
type PasswordResetConfirm struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
}

// EmailVerificationRequest represents email verification request
type EmailVerificationRequest struct {
	Token string `json:"token" validate:"required"`
}

// GoogleAuthRequest represents Google OAuth authentication request
type GoogleAuthRequest struct {
	Code string `json:"code" validate:"required"`
}

// GoogleAuthResponse represents Google OAuth authentication response
type GoogleAuthResponse struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
}

// TikTokAuthRequest represents TikTok OAuth authentication request
type TikTokAuthRequest struct {
	Code string `json:"code" validate:"required"`
}

// TikTokAuthResponse represents TikTok OAuth authentication response
type TikTokAuthResponse struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
}

// AppleAuthRequest represents Apple Sign-In authentication request
type AppleAuthRequest struct {
	Code string `json:"code" validate:"required"`
}

// AppleAuthResponse represents Apple Sign-In authentication response
type AppleAuthResponse struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	User         *User  `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in"`
}

// GoogleProfile represents Google OAuth profile information
type GoogleProfile struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

// TikTokProfile represents TikTok OAuth profile information
type TikTokProfile struct {
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

// AppleProfile represents Apple Sign-In profile information
type AppleProfile struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	EmailVerified  string `json:"email_verified"`   // "true" or "false" as string
	IsPrivateEmail string `json:"is_private_email"` // "true" or "false" as string
	RealUserStatus int    `json:"real_user_status"` // 0: Unsupported, 1: Unknown, 2: LikelyReal
	FirstName      string `json:"first_name,omitempty"`
	LastName       string `json:"last_name,omitempty"`
}

// UserResponse represents user response (without sensitive data)
type UserResponse struct {
	ID              interface{} `json:"id"`
	Email           string      `json:"email"`
	FirstName       string      `json:"first_name"`
	LastName        string      `json:"last_name"`
	IsEmailVerified bool        `json:"is_email_verified"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
	LastLoginAt     *time.Time  `json:"last_login_at,omitempty"`
	IsActive        bool        `json:"is_active"`

	// Google OAuth support
	GoogleID      string         `json:"google_id,omitempty"`
	GoogleProfile *GoogleProfile `json:"google_profile,omitempty"`

	// TikTok OAuth support
	TikTokID      string         `json:"tiktok_id,omitempty"`
	TikTokProfile *TikTokProfile `json:"tiktok_profile,omitempty"`

	// Apple Sign-In support
	AppleID      string        `json:"apple_id,omitempty"`
	AppleProfile *AppleProfile `json:"apple_profile,omitempty"`

	// 2FA support
	TwoFactorEnabled     bool     `json:"two_factor_enabled"`
	TwoFactorBackupCodes []string `json:"two_factor_backup_codes,omitempty"`

	// Custom fields support
	CustomFields map[string]interface{} `json:"custom_fields,omitempty"`
}

// GetCustomFields implements CustomFields interface
func (ur *UserResponse) GetCustomFields() map[string]interface{} {
	if ur.CustomFields == nil {
		ur.CustomFields = make(map[string]interface{})
	}
	return ur.CustomFields
}

// SetCustomFields implements CustomFields interface
func (ur *UserResponse) SetCustomFields(fields map[string]interface{}) {
	ur.CustomFields = fields
}

// TwoFactorSetupRequest represents 2FA setup request
type TwoFactorSetupRequest struct {
	UserID interface{} `json:"user_id" validate:"required"`
}

// TwoFactorSetupResponse represents 2FA setup response
type TwoFactorSetupResponse struct {
	Secret      string   `json:"secret"`       // TOTP secret for QR code generation
	QRCodeURL   string   `json:"qr_code_url"`  // URL for QR code
	BackupCodes []string `json:"backup_codes"` // Backup codes for account recovery
}

// TwoFactorVerifyRequest represents 2FA verification request
type TwoFactorVerifyRequest struct {
	UserID interface{} `json:"user_id" validate:"required"`
	Code   string      `json:"code" validate:"required"` // TOTP code or backup code
}

// TwoFactorDisableRequest represents 2FA disable request
type TwoFactorDisableRequest struct {
	UserID interface{} `json:"user_id" validate:"required"`
	Code   string      `json:"code" validate:"required"` // TOTP code or backup code
}

// TwoFactorLoginRequest represents 2FA login request
type TwoFactorLoginRequest struct {
	UserID interface{} `json:"user_id" validate:"required"`
	Code   string      `json:"code" validate:"required"` // TOTP code or backup code
}
