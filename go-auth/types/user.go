package types

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents a user in the authentication system
type User struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
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
}

// EmailVerification represents email verification data
type EmailVerification struct {
	Token     string    `bson:"token" json:"token"`
	ExpiresAt time.Time `bson:"expires_at" json:"expires_at"`
	VerifiedAt *time.Time `bson:"verified_at,omitempty" json:"verified_at,omitempty"`
}

// PasswordReset represents password reset data
type PasswordReset struct {
	Token     string    `bson:"token" json:"token"`
	ExpiresAt time.Time `bson:"expires_at" json:"expires_at"`
	UsedAt    *time.Time `bson:"used_at,omitempty" json:"used_at,omitempty"`
}

// UserRegistration represents user registration request
type UserRegistration struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
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
	ID              primitive.ObjectID `json:"id"`
	Email           string             `json:"email"`
	FirstName       string             `json:"first_name"`
	LastName        string             `json:"last_name"`
	IsEmailVerified bool               `json:"is_email_verified"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
	LastLoginAt     *time.Time         `json:"last_login_at,omitempty"`
	IsActive        bool               `json:"is_active"`
}
