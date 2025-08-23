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

// AuthResponse represents authentication response
type AuthResponse struct {
	User         *User  `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in"`
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
