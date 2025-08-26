package main

import (
	"context"
	"fmt"
	"log"
	"time"

	goauth "github.com/Devkrea8-Technologies/go-auth/go-auth"
	"github.com/Devkrea8-Technologies/go-auth/go-auth/config"
	"github.com/Devkrea8-Technologies/go-auth/go-auth/types"
)

func main() {
	// Create configuration with Google OAuth enabled
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
		Google: config.GoogleConfig{
			Enabled:      true,
			ClientID:     "your-google-client-id.apps.googleusercontent.com",
			ClientSecret: "your-google-client-secret",
			RedirectURL:  "http://localhost:8080/auth/google/callback",
		},
		Security: config.SecurityConfig{
			RequirePassword:   false, // Allow users without passwords
			RequireGoogleAuth: false, // Not required, but available
		},
	}

	// Initialize auth service
	auth, err := goauth.New(cfg)
	if err != nil {
		log.Fatal("Failed to initialize auth service:", err)
	}
	defer auth.Close(context.Background())

	fmt.Println("=== Google OAuth Example ===")

	// Example 1: Generate Google OAuth URL
	fmt.Println("1. Generate Google OAuth URL")
	state := "random-state-string-for-security"
	authURL := auth.GetGoogleAuthURL(state)
	if authURL != "" {
		fmt.Printf("✓ Google OAuth URL generated: %s\n", authURL)
		fmt.Printf("  State: %s\n", state)
	} else {
		fmt.Println("✗ Google OAuth is not enabled")
	}

	fmt.Println()

	// Example 2: Register user with password (optional)
	fmt.Println("2. Register user with password (optional)")
	user := &types.UserRegistration{
		Email:     "user@example.com",
		Password:  "securepassword123", // Optional when Google OAuth is enabled
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

	// Example 3: Authenticate with Google OAuth (simulated)
	fmt.Println("3. Authenticate with Google OAuth")
	fmt.Println("   Note: This is a simulation. In a real application, you would:")
	fmt.Println("   1. Redirect user to the Google OAuth URL")
	fmt.Println("   2. Handle the callback with authorization code")
	fmt.Println("   3. Exchange code for user information")

	// Simulate Google OAuth flow
	fmt.Println("   Simulating Google OAuth authentication...")

	// In a real application, you would get the code from Google callback
	// For this example, we'll show the structure:
	/*
		googleAuthReq := &types.GoogleAuthRequest{
			Code: "authorization_code_from_google",
		}

		authResponse, err := auth.AuthenticateWithGoogle(context.Background(), googleAuthReq.Code)
		if err != nil {
			fmt.Printf("✗ Google authentication failed: %v\n", err)
		} else {
			fmt.Printf("✓ Google authentication successful: %s\n", authResponse.User.Email)
			fmt.Printf("  Google ID: %s\n", authResponse.User.GoogleID)
			fmt.Printf("  Profile picture: %s\n", authResponse.User.GoogleProfile.Picture)
		}
	*/

	fmt.Println("   ✓ Google OAuth flow would complete successfully")

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
		fmt.Printf("  Has Google ID: %t\n", retrievedUser.GoogleID != "")
		if retrievedUser.GoogleProfile != nil {
			fmt.Printf("  Google profile available: %t\n", retrievedUser.GoogleProfile != nil)
		}
	}

	fmt.Println("\n=== Google OAuth Example completed ===")
	fmt.Println("\nKey features demonstrated:")
	fmt.Println("- Google OAuth configuration")
	fmt.Println("- Optional password authentication")
	fmt.Println("- Google OAuth URL generation")
	fmt.Println("- User registration with optional password")
	fmt.Println("- Google OAuth authentication flow")
	fmt.Println("- User profile with Google information")
	fmt.Println("- Flexible authentication methods")
	fmt.Println("\nTo use Google OAuth in production:")
	fmt.Println("1. Set up Google OAuth credentials in Google Cloud Console")
	fmt.Println("2. Configure Client ID, Client Secret, and Redirect URL")
	fmt.Println("3. Implement the OAuth callback handler")
	fmt.Println("4. Handle the authorization code exchange")
}
