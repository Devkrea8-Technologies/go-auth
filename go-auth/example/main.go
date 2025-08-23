package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-auth"
	"github.com/go-auth/config"
	"github.com/go-auth/types"
)

func main() {
	// Create configuration
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			URI:        "mongodb://localhost:27017",
			Database:   "auth_example",
			Collection: "users",
		},
		JWT: config.JWTConfig{
			SecretKey:       "your-super-secret-key-here-make-it-long-and-secure",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
			Issuer:          "auth-example",
			Audience:        "auth-example-users",
		},
		Email: config.EmailConfig{
			SMTPHost:     "smtp.gmail.com",
			SMTPPort:     587,
			SMTPUsername: "your-email@gmail.com",
			SMTPPassword: "your-app-password",
			FromEmail:    "noreply@example.com",
			FromName:     "Auth Example",
			EmailVerificationTemplate: config.EmailTemplate{
				Subject: "Verify your email address",
				Body: `
					<h2>Welcome to Auth Example!</h2>
					<p>Hi {{.UserName}},</p>
					<p>Please verify your email address by clicking the link below:</p>
					<a href="{{.BaseURL}}/verify?token={{.Token}}">Verify Email</a>
					<p>This link will expire in 24 hours.</p>
				`,
			},
			PasswordResetTemplate: config.EmailTemplate{
				Subject: "Reset your password",
				Body: `
					<h2>Password Reset Request</h2>
					<p>Hi {{.UserName}},</p>
					<p>You requested a password reset. Click the link below to reset your password:</p>
					<a href="{{.BaseURL}}/reset?token={{.Token}}">Reset Password</a>
					<p>This link will expire in 1 hour.</p>
					<p>If you didn't request this, please ignore this email.</p>
				`,
			},
		},
		Security: config.SecurityConfig{
			PasswordMinLength:         8,
			PasswordMaxLength:         128,
			EmailVerificationTTL:      24 * time.Hour,
			PasswordResetTTL:          1 * time.Hour,
			MaxLoginAttempts:          5,
			LockoutDuration:           15 * time.Minute,
			RequireEmailVerification:  true,
		},
	}

	// Initialize auth service
	auth, err := goauth.New(cfg)
	if err != nil {
		log.Fatal("Failed to initialize auth service:", err)
	}
	defer auth.Close(context.Background())

	fmt.Println("=== Go Auth Library Example ===\n")

	// Example 1: User Registration
	fmt.Println("1. User Registration")
	user := &types.UserRegistration{
		Email:     "john.doe@example.com",
		Password:  "securepassword123",
		FirstName: "John",
		LastName:  "Doe",
	}

	response, err := auth.Register(context.Background(), user, "https://example.com")
	if err != nil {
		log.Printf("Registration failed: %v", err)
	} else {
		fmt.Printf("✓ User registered successfully: %s\n", response.User.Email)
		fmt.Printf("  User ID: %s\n", response.User.ID.Hex())
		fmt.Printf("  Email verified: %t\n", response.User.IsEmailVerified)
		fmt.Printf("  Access token: %s...\n", response.AccessToken[:20])
	}

	fmt.Println()

	// Example 2: User Login (will fail if email verification is required)
	fmt.Println("2. User Login")
	login := &types.UserLogin{
		Email:    "john.doe@example.com",
		Password: "securepassword123",
	}

	loginResponse, err := auth.Login(context.Background(), login)
	if err != nil {
		fmt.Printf("✗ Login failed: %v\n", err)
		fmt.Println("  (This is expected if email verification is required)")
	} else {
		fmt.Printf("✓ Login successful: %s\n", loginResponse.User.Email)
		fmt.Printf("  Access token: %s...\n", loginResponse.AccessToken[:20])
	}

	fmt.Println()

	// Example 3: Get User by Email
	fmt.Println("3. Get User by Email")
	retrievedUser, err := auth.GetUserByEmail(context.Background(), "john.doe@example.com")
	if err != nil {
		fmt.Printf("✗ Failed to get user: %v\n", err)
	} else {
		fmt.Printf("✓ User retrieved: %s %s\n", retrievedUser.FirstName, retrievedUser.LastName)
		fmt.Printf("  Created at: %s\n", retrievedUser.CreatedAt.Format(time.RFC3339))
	}

	fmt.Println()

	// Example 4: Request Password Reset
	fmt.Println("4. Request Password Reset")
	resetRequest := &types.PasswordResetRequest{
		Email: "john.doe@example.com",
	}

	err = auth.RequestPasswordReset(context.Background(), resetRequest, "https://example.com")
	if err != nil {
		fmt.Printf("✗ Password reset request failed: %v\n", err)
	} else {
		fmt.Println("✓ Password reset email sent")
	}

	fmt.Println()

	// Example 5: Token Validation (simulated)
	fmt.Println("5. Token Validation")
	if loginResponse != nil {
		validatedUser, err := auth.ValidateToken(context.Background(), loginResponse.AccessToken)
		if err != nil {
			fmt.Printf("✗ Token validation failed: %v\n", err)
		} else {
			fmt.Printf("✓ Token validated successfully\n")
			fmt.Printf("  Authenticated user: %s\n", validatedUser.Email)
		}
	} else {
		fmt.Println("  (Skipped - no valid token available)")
	}

	fmt.Println("\n=== Example completed ===")
	fmt.Println("\nNote: This example requires:")
	fmt.Println("- MongoDB running on localhost:27017")
	fmt.Println("- Valid SMTP configuration for email functionality")
	fmt.Println("- Email verification may be required depending on configuration")
}
