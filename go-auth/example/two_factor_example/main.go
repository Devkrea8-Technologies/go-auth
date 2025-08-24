package main

import (
	"context"
	"fmt"
	"log"
	"time"

	goauth "github.com/Devkrea8-Technologies/go-auth"
	"github.com/Devkrea8-Technologies/go-auth/config"
	"github.com/Devkrea8-Technologies/go-auth/types"
)

func main() {
	fmt.Println("=== Two-Factor Authentication (2FA) Example ===")

	// Create configuration with 2FA enabled
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Type:       config.DatabaseTypeMongoDB,
			URI:        "mongodb://localhost:27017",
			Database:   "myapp",
			Collection: "users",
		},
		JWT: config.JWTConfig{
			SecretKey:       "your-secret-key-here",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
			Issuer:          "MyApp",
		},
		Security: config.SecurityConfig{
			Enable2FA:  true,  // Enable 2FA functionality
			Require2FA: false, // Make 2FA optional (not required for all users)
		},
	}

	// Initialize auth service
	auth, err := goauth.New(cfg)
	if err != nil {
		log.Fatal("Failed to initialize auth service:", err)
	}
	defer auth.Close(context.Background())

	// Example 1: Register a user
	fmt.Println("\n1. Registering a new user...")
	user := &types.UserRegistration{
		Email:     "user@example.com",
		Password:  "securepassword123",
		FirstName: "John",
		LastName:  "Doe",
	}

	response, err := auth.Register(context.Background(), user, "https://example.com")
	if err != nil {
		log.Printf("Registration failed: %v", err)
		return
	}
	fmt.Printf("✅ User registered successfully: %s\n", response.User.Email)

	// Example 2: Setup 2FA
	fmt.Println("\n2. Setting up 2FA...")
	setupReq := &types.TwoFactorSetupRequest{
		UserID: response.User.ID,
	}

	setupResponse, err := auth.Setup2FA(context.Background(), setupReq)
	if err != nil {
		log.Printf("2FA setup failed: %v", err)
		return
	}

	fmt.Println("✅ 2FA setup successful!")
	fmt.Printf("📱 Secret: %s\n", setupResponse.Secret)
	fmt.Printf("🔗 QR Code URL: %s\n", setupResponse.QRCodeURL)
	fmt.Printf("🔑 Backup Codes: %v\n", setupResponse.BackupCodes)

	// Example 3: Enable 2FA
	fmt.Println("\n3. Enabling 2FA...")
	fmt.Println("   Note: In a real application, the user would:")
	fmt.Println("   1. Scan the QR code with their authenticator app")
	fmt.Println("   2. Enter the 6-digit code from their app")
	fmt.Println("   3. Submit the code to enable 2FA")

	enableReq := &types.TwoFactorVerifyRequest{
		UserID: response.User.ID,
		Code:   "123456", // This would be the actual code from the user's app
	}

	err = auth.Enable2FA(context.Background(), enableReq)
	if err != nil {
		fmt.Printf("❌ 2FA enable failed: %v\n", err)
		fmt.Println("   (This is expected in this demo since we're using a fake code)")
	} else {
		fmt.Println("✅ 2FA enabled successfully!")
	}

	// Example 4: Verify 2FA code
	fmt.Println("\n4. Verifying 2FA code...")
	verifyReq := &types.TwoFactorVerifyRequest{
		UserID: response.User.ID,
		Code:   "123456", // This would be the actual code from the user's app
	}

	isValid, err := auth.Verify2FA(context.Background(), verifyReq)
	if err != nil {
		fmt.Printf("❌ 2FA verification failed: %v\n", err)
	} else if isValid {
		fmt.Println("✅ 2FA code verified successfully!")
	} else {
		fmt.Println("❌ Invalid 2FA code")
	}

	// Example 5: Using backup codes
	fmt.Println("\n5. Using backup codes...")
	if len(setupResponse.BackupCodes) > 0 {
		backupReq := &types.TwoFactorVerifyRequest{
			UserID: response.User.ID,
			Code:   setupResponse.BackupCodes[0], // Use the first backup code
		}

		isValid, err := auth.Verify2FA(context.Background(), backupReq)
		if err != nil {
			fmt.Printf("❌ Backup code verification failed: %v\n", err)
		} else if isValid {
			fmt.Println("✅ Backup code verified successfully!")
		} else {
			fmt.Println("❌ Invalid backup code")
		}
	}

	// Example 6: Disable 2FA
	fmt.Println("\n6. Disabling 2FA...")
	disableReq := &types.TwoFactorDisableRequest{
		UserID: response.User.ID,
		Code:   "123456", // This would be the actual code from the user's app
	}

	err = auth.Disable2FA(context.Background(), disableReq)
	if err != nil {
		fmt.Printf("❌ 2FA disable failed: %v\n", err)
		fmt.Println("   (This is expected in this demo since we're using a fake code)")
	} else {
		fmt.Println("✅ 2FA disabled successfully!")
	}

	fmt.Println("\n=== 2FA Example Completed ===")
	fmt.Println("\nKey Features Demonstrated:")
	fmt.Println("✅ 2FA setup with QR code generation")
	fmt.Println("✅ TOTP code verification")
	fmt.Println("✅ Backup codes for account recovery")
	fmt.Println("✅ 2FA enable/disable functionality")
	fmt.Println("✅ Secure storage of 2FA secrets")
}
