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
	}

	// Initialize auth service
	auth, err := goauth.New(cfg)
	if err != nil {
		log.Fatal("Failed to initialize auth service:", err)
	}
	defer auth.Close(context.Background())

	fmt.Println("=== Custom Fields Example ===")

	// Example 1: Register user with custom fields
	fmt.Println("1. Register user with custom fields")
	user := &types.UserRegistration{
		Email:     "john.doe@example.com",
		Password:  "securepassword123",
		FirstName: "John",
		LastName:  "Doe",
		CustomFields: map[string]interface{}{
			"phone_number": "+1234567890",
			"age":          30,
			"preferences": map[string]interface{}{
				"theme":    "dark",
				"language": "en",
				"timezone": "UTC",
			},
			"subscription_tier": "premium",
			"last_payment_date": time.Now().AddDate(0, -1, 0),
		},
	}

	response, err := auth.Register(context.Background(), user, "https://example.com")
	if err != nil {
		log.Printf("Registration failed: %v", err)
	} else {
		fmt.Printf("✓ User registered successfully: %s\n", response.User.Email)
		fmt.Printf("  Custom fields: %+v\n", response.User.CustomFields)
	}

	fmt.Println()

	// Example 2: Get user and access custom fields
	fmt.Println("2. Get user and access custom fields")
	retrievedUser, err := auth.GetUserByEmail(context.Background(), "john.doe@example.com")
	if err != nil {
		fmt.Printf("✗ Failed to get user: %v\n", err)
	} else {
		fmt.Printf("✓ User retrieved: %s %s\n", retrievedUser.FirstName, retrievedUser.LastName)

		// Access custom fields
		if phone, exists := retrievedUser.GetCustomField("phone_number"); exists {
			fmt.Printf("  Phone: %s\n", phone)
		}

		if age, exists := retrievedUser.GetCustomField("age"); exists {
			fmt.Printf("  Age: %v\n", age)
		}

		if prefs, exists := retrievedUser.GetCustomField("preferences"); exists {
			if prefsMap, ok := prefs.(map[string]interface{}); ok {
				fmt.Printf("  Theme: %s\n", prefsMap["theme"])
				fmt.Printf("  Language: %s\n", prefsMap["language"])
			}
		}
	}

	fmt.Println()

	// Example 3: Update custom fields
	fmt.Println("3. Update custom fields")
	if retrievedUser != nil {
		// Set a new custom field
		err = auth.SetUserCustomField(context.Background(), retrievedUser.ID, "company", "Tech Corp")
		if err != nil {
			fmt.Printf("✗ Failed to set custom field: %v\n", err)
		} else {
			fmt.Println("✓ Added company field")
		}

		// Update existing custom field
		err = auth.SetUserCustomField(context.Background(), retrievedUser.ID, "age", 31)
		if err != nil {
			fmt.Printf("✗ Failed to update custom field: %v\n", err)
		} else {
			fmt.Println("✓ Updated age field")
		}

		// Get the updated field
		if age, exists, err := auth.GetUserCustomField(context.Background(), retrievedUser.ID, "age"); err == nil && exists {
			fmt.Printf("  Updated age: %v\n", age)
		}
	}

	fmt.Println()

	// Example 4: Remove custom field
	fmt.Println("4. Remove custom field")
	if retrievedUser != nil {
		err = auth.RemoveUserCustomField(context.Background(), retrievedUser.ID, "subscription_tier")
		if err != nil {
			fmt.Printf("✗ Failed to remove custom field: %v\n", err)
		} else {
			fmt.Println("✓ Removed subscription_tier field")
		}

		// Verify it's removed
		if _, exists, err := auth.GetUserCustomField(context.Background(), retrievedUser.ID, "subscription_tier"); err == nil && !exists {
			fmt.Println("  ✓ Field successfully removed")
		}
	}

	fmt.Println()

	// Example 5: Bulk update custom fields
	fmt.Println("5. Bulk update custom fields")
	if retrievedUser != nil {
		newCustomFields := map[string]interface{}{
			"department":  "Engineering",
			"employee_id": "EMP001",
			"hire_date":   time.Now().AddDate(0, -6, 0),
			"skills":      []string{"Go", "MongoDB", "JWT"},
			"is_manager":  true,
			"team_size":   5,
		}

		err = auth.UpdateUserCustomFields(context.Background(), retrievedUser.ID, newCustomFields)
		if err != nil {
			fmt.Printf("✗ Failed to update custom fields: %v\n", err)
		} else {
			fmt.Println("✓ Bulk updated custom fields")

			// Verify the update
			updatedUser, err := auth.GetUserByID(context.Background(), retrievedUser.ID)
			if err == nil {
				fmt.Printf("  Department: %s\n", updatedUser.CustomFields["department"])
				fmt.Printf("  Employee ID: %s\n", updatedUser.CustomFields["employee_id"])
				fmt.Printf("  Skills: %v\n", updatedUser.CustomFields["skills"])
			}
		}
	}

	fmt.Println("\n=== Custom Fields Example completed ===")
	fmt.Println("\nKey features demonstrated:")
	fmt.Println("- Adding custom fields during registration")
	fmt.Println("- Retrieving and accessing custom fields")
	fmt.Println("- Setting individual custom fields")
	fmt.Println("- Updating existing custom fields")
	fmt.Println("- Removing custom fields")
	fmt.Println("- Bulk updating custom fields")
	fmt.Println("- Support for various data types (strings, numbers, maps, arrays, booleans, dates)")
}
