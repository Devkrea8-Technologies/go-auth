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
	// Create configuration for PostgreSQL
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Type:            config.DatabaseTypePostgreSQL,
			Host:            "localhost",
			Port:            5432,
			Username:        "postgres",
			Password:        "password",
			Database:        "auth_example",
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
		},
		JWT: config.JWTConfig{
			SecretKey:       "your-super-secret-key-here-make-it-long-and-secure",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
			Issuer:          "auth-example",
			Audience:        "auth-example-users",
		},
	}

	// Initialize auth service
	auth, err := goauth.New(cfg)
	if err != nil {
		log.Fatal("Failed to initialize auth service:", err)
	}
	defer auth.Close(context.Background())

	fmt.Println("=== PostgreSQL Authentication Example ===")

	// Example 1: Register user
	fmt.Println("1. Register user")
	user := &types.UserRegistration{
		Email:     "jane.doe@example.com",
		Password:  "securepassword123",
		FirstName: "Jane",
		LastName:  "Doe",
		CustomFields: map[string]interface{}{
			"phone_number": "+1234567890",
			"department":   "Engineering",
			"employee_id":  "EMP002",
		},
	}

	response, err := auth.Register(context.Background(), user, "https://example.com")
	if err != nil {
		log.Printf("Registration failed: %v", err)
	} else {
		fmt.Printf("✓ User registered successfully: %s\n", response.User.Email)
		fmt.Printf("  User ID: %v\n", response.User.ID)
		fmt.Printf("  Custom fields: %+v\n", response.User.CustomFields)
	}

	fmt.Println()

	// Example 2: Login
	fmt.Println("2. Login")
	loginReq := &types.UserLogin{
		Email:    "jane.doe@example.com",
		Password: "securepassword123",
	}

	loginResponse, err := auth.Login(context.Background(), loginReq)
	if err != nil {
		fmt.Printf("✗ Login failed: %v\n", err)
	} else {
		fmt.Printf("✓ Login successful: %s\n", loginResponse.User.Email)
		fmt.Printf("  Access Token: %s...\n", loginResponse.AccessToken[:20])
		fmt.Printf("  User ID: %v\n", loginResponse.User.ID)
	}

	fmt.Println()

	// Example 3: Get user by email
	fmt.Println("3. Get user by email")
	retrievedUser, err := auth.GetUserByEmail(context.Background(), "jane.doe@example.com")
	if err != nil {
		fmt.Printf("✗ Failed to get user: %v\n", err)
	} else {
		fmt.Printf("✓ User retrieved: %s %s\n", retrievedUser.FirstName, retrievedUser.LastName)
		fmt.Printf("  User ID: %v\n", retrievedUser.ID)
		fmt.Printf("  Email verified: %t\n", retrievedUser.IsEmailVerified)
	}

	fmt.Println()

	// Example 4: Update custom fields
	fmt.Println("4. Update custom fields")
	if retrievedUser != nil {
		// Set a new custom field
		err = auth.SetUserCustomField(context.Background(), retrievedUser.ID, "salary", 75000)
		if err != nil {
			fmt.Printf("✗ Failed to set custom field: %v\n", err)
		} else {
			fmt.Println("✓ Added salary field")
		}

		// Get the custom field
		if value, exists, err := auth.GetUserCustomField(context.Background(), retrievedUser.ID, "salary"); err == nil && exists {
			fmt.Printf("  Salary: $%v\n", value)
		}
	}

	fmt.Println()

	// Example 5: Validate token
	fmt.Println("5. Validate token")
	if loginResponse != nil {
		user, err := auth.ValidateToken(context.Background(), loginResponse.AccessToken)
		if err != nil {
			fmt.Printf("✗ Token validation failed: %v\n", err)
		} else {
			fmt.Printf("✓ Token is valid\n")
			fmt.Printf("  User ID: %v\n", user.ID)
			fmt.Printf("  Email: %s\n", user.Email)
		}
	}

	fmt.Println()

	// Example 6: Request password reset
	fmt.Println("6. Request password reset")
	resetReq := &types.PasswordResetRequest{
		Email: "jane.doe@example.com",
	}
	err = auth.RequestPasswordReset(context.Background(), resetReq, "https://example.com")
	if err != nil {
		fmt.Printf("✗ Password reset request failed: %v\n", err)
	} else {
		fmt.Println("✓ Password reset email sent")
	}

	fmt.Println("\n=== PostgreSQL Example completed ===")
	fmt.Println("\nKey features demonstrated:")
	fmt.Println("- PostgreSQL database connection")
	fmt.Println("- User registration with custom fields")
	fmt.Println("- User login and authentication")
	fmt.Println("- Token validation")
	fmt.Println("- Custom fields management")
	fmt.Println("- Password reset functionality")
	fmt.Println("- Integer-based user IDs (PostgreSQL)")
}
