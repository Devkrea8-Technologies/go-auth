package main

import (
	"context"
	"fmt"
	"log"
	"time"

	goauth "github.com/go-auth"
	"github.com/go-auth/config"
	"github.com/go-auth/types"
)

func main() {
	// Create configuration with TikTok OAuth enabled
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Type:       config.DatabaseTypeMongoDB,
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
		TikTok: config.TikTokConfig{
			Enabled:      true,
			ClientID:     "your-tiktok-client-key",
			ClientSecret: "your-tiktok-client-secret",
			RedirectURL:  "http://localhost:8080/auth/tiktok/callback",
		},
		Security: config.SecurityConfig{
			RequirePassword:   false, // Allow users without passwords
			RequireTikTokAuth: false, // Not required, but available
		},
	}

	// Initialize auth service
	auth, err := goauth.New(cfg)
	if err != nil {
		log.Fatal("Failed to initialize auth service:", err)
	}
	defer auth.Close(context.Background())

	fmt.Println("=== TikTok OAuth Example ===\n")

	// Example 1: Generate TikTok OAuth URL
	fmt.Println("1. Generate TikTok OAuth URL")
	state := "random-state-string-for-security"
	authURL := auth.GetTikTokAuthURL(state)
	if authURL != "" {
		fmt.Printf("✓ TikTok OAuth URL generated: %s\n", authURL)
		fmt.Printf("  State: %s\n", state)
	} else {
		fmt.Println("✗ TikTok OAuth is not enabled")
	}

	fmt.Println()

	// Example 2: Register user with password (optional)
	fmt.Println("2. Register user with password (optional)")
	user := &types.UserRegistration{
		Email:     "user@example.com",
		Password:  "securepassword123", // Optional when TikTok OAuth is enabled
		FirstName: "John",
		LastName:  "Doe",
		CustomFields: map[string]interface{}{
			"phone_number": "+1234567890",
			"department":   "Engineering",
		},
	}

	response, err := auth.Register(context.Background(), user, "https://example.com")
	if err != nil {
		fmt.Printf("✗ Registration failed: %v\n", err)
	} else {
		fmt.Printf("✓ User registered successfully: %s\n", response.User.Email)
		fmt.Printf("  User ID: %v\n", response.User.ID)
		fmt.Printf("  Has password: %t\n", response.User.Password != "")
	}

	fmt.Println()

	// Example 3: Authenticate with TikTok OAuth (simulated)
	fmt.Println("3. Authenticate with TikTok OAuth")
	fmt.Println("   Note: This is a simulation. In a real application, you would:")
	fmt.Println("   1. Redirect user to the TikTok OAuth URL")
	fmt.Println("   2. Handle the callback with authorization code")
	fmt.Println("   3. Exchange code for user information")

	// Simulate TikTok OAuth flow
	fmt.Println("   Simulating TikTok OAuth authentication...")

	// In a real application, you would get the code from TikTok callback
	// For this example, we'll show the structure:
	/*
		tiktokAuthReq := &types.TikTokAuthRequest{
			Code: "authorization_code_from_tiktok",
		}

		authResponse, err := auth.AuthenticateWithTikTok(context.Background(), tiktokAuthReq.Code)
		if err != nil {
			fmt.Printf("✗ TikTok authentication failed: %v\n", err)
		} else {
			fmt.Printf("✓ TikTok authentication successful: %s\n", authResponse.User.Email)
			fmt.Printf("  TikTok ID: %s\n", authResponse.User.TikTokID)
			fmt.Printf("  Username: %s\n", authResponse.User.TikTokProfile.Username)
			fmt.Printf("  Display Name: %s\n", authResponse.User.TikTokProfile.DisplayName)
			fmt.Printf("  Follower Count: %d\n", authResponse.User.TikTokProfile.FollowerCount)
		}
	*/

	fmt.Println("   ✓ TikTok OAuth flow would complete successfully")

	fmt.Println()

	// Example 4: Login with password (if available)
	fmt.Println("4. Login with password (if available)")
	loginReq := &types.UserLogin{
		Email:    "user@example.com",
		Password: "securepassword123",
	}

	loginResponse, err := auth.Login(context.Background(), loginReq)
	if err != nil {
		fmt.Printf("✗ Login failed: %v\n", err)
	} else {
		fmt.Printf("✓ Login successful: %s\n", loginResponse.User.Email)
		fmt.Printf("  Access Token: %s...\n", loginResponse.AccessToken[:20])
	}

	fmt.Println()

	// Example 5: Get user information
	fmt.Println("5. Get user information")
	retrievedUser, err := auth.GetUserByEmail(context.Background(), "user@example.com")
	if err != nil {
		fmt.Printf("✗ Failed to get user: %v\n", err)
	} else {
		fmt.Printf("✓ User retrieved: %s %s\n", retrievedUser.FirstName, retrievedUser.LastName)
		fmt.Printf("  Email verified: %t\n", retrievedUser.IsEmailVerified)
		fmt.Printf("  Has TikTok ID: %t\n", retrievedUser.TikTokID != "")
		if retrievedUser.TikTokProfile != nil {
			fmt.Printf("  TikTok profile available: %t\n", retrievedUser.TikTokProfile != nil)
		}
	}

	fmt.Println("\n=== TikTok OAuth Example completed ===")
	fmt.Println("\nKey features demonstrated:")
	fmt.Println("- TikTok OAuth configuration")
	fmt.Println("- Optional password authentication")
	fmt.Println("- TikTok OAuth URL generation")
	fmt.Println("- User registration with optional password")
	fmt.Println("- TikTok OAuth authentication flow")
	fmt.Println("- User profile with TikTok information")
	fmt.Println("- Flexible authentication methods")
	fmt.Println("\nTo use TikTok OAuth in production:")
	fmt.Println("1. Set up TikTok OAuth credentials in TikTok for Developers")
	fmt.Println("2. Configure Client Key, Client Secret, and Redirect URL")
	fmt.Println("3. Implement the OAuth callback handler")
	fmt.Println("4. Handle the authorization code exchange")
	fmt.Println("5. Note: TikTok doesn't provide email, so username is used as identifier")
}
