package config

import (
	"time"
)

// Config represents the main configuration for the authentication library
type Config struct {
	Database DatabaseConfig `json:"database"`
	JWT      JWTConfig      `json:"jwt"`
	Email    EmailConfig    `json:"email"`
	Security SecurityConfig `json:"security"`
}

// DatabaseConfig represents MongoDB configuration
type DatabaseConfig struct {
	URI        string `json:"uri" validate:"required"`
	Database   string `json:"database" validate:"required"`
	Collection string `json:"collection" default:"users"`
}

// JWTConfig represents JWT configuration
type JWTConfig struct {
	SecretKey        string        `json:"secret_key" validate:"required"`
	AccessTokenTTL   time.Duration `json:"access_token_ttl" default:"15m"`
	RefreshTokenTTL  time.Duration `json:"refresh_token_ttl" default:"7d"`
	Issuer           string        `json:"issuer" default:"go-auth"`
	Audience         string        `json:"audience" default:"go-auth-users"`
}

// EmailConfig represents email configuration
type EmailConfig struct {
	SMTPHost     string `json:"smtp_host" validate:"required"`
	SMTPPort     int    `json:"smtp_port" validate:"required"`
	SMTPUsername string `json:"smtp_username" validate:"required"`
	SMTPPassword string `json:"smtp_password" validate:"required"`
	FromEmail    string `json:"from_email" validate:"required,email"`
	FromName     string `json:"from_name" validate:"required"`
	
	// Email templates
	EmailVerificationTemplate EmailTemplate `json:"email_verification_template"`
	PasswordResetTemplate     EmailTemplate `json:"password_reset_template"`
}

// EmailTemplate represents email template configuration
type EmailTemplate struct {
	Subject string `json:"subject" validate:"required"`
	Body    string `json:"body" validate:"required"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	PasswordMinLength     int           `json:"password_min_length" default:"8"`
	PasswordMaxLength     int           `json:"password_max_length" default:"128"`
	EmailVerificationTTL  time.Duration `json:"email_verification_ttl" default:"24h"`
	PasswordResetTTL      time.Duration `json:"password_reset_ttl" default:"1h"`
	MaxLoginAttempts      int           `json:"max_login_attempts" default:"5"`
	LockoutDuration       time.Duration `json:"lockout_duration" default:"15m"`
	RequireEmailVerification bool       `json:"require_email_verification" default:"true"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Database: DatabaseConfig{
			Collection: "users",
		},
		JWT: JWTConfig{
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
			Issuer:          "go-auth",
			Audience:        "go-auth-users",
		},
		Security: SecurityConfig{
			PasswordMinLength:        8,
			PasswordMaxLength:        128,
			EmailVerificationTTL:     24 * time.Hour,
			PasswordResetTTL:         1 * time.Hour,
			MaxLoginAttempts:         5,
			LockoutDuration:          15 * time.Minute,
			RequireEmailVerification: true,
		},
	}
}
