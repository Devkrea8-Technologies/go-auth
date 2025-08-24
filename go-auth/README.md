# Go Auth Library

A comprehensive authentication library for Go applications with MongoDB and PostgreSQL support, email verification, password reset functionality, and multiple OAuth integrations.

## Features

- **Flexible Authentication**: Email/password, Google OAuth, TikTok OAuth, and Apple Sign-In authentication
- **Multiple Database Support**: MongoDB and PostgreSQL with automatic schema management
- **User Registration & Login**: Secure user registration and authentication
- **Email Verification**: Email verification with customizable templates
- **Password Reset**: Secure password reset functionality
- **Google OAuth**: Complete OAuth 2.0 integration with Google
- **TikTok OAuth**: Complete OAuth 2.0 integration with TikTok
- **Apple Sign-In**: Production-ready Apple Sign-In with JWT client authentication
- **JWT Tokens**: Access and refresh token management
- **Custom Fields**: Extensible user data with custom fields
- **Configurable**: Highly configurable security settings and email templates
- **Extensible**: Easy to extend with additional authentication methods

## Quick Start

### Installation

```bash
go get github.com/go-auth
```

### Basic Usage

```go
package main

import (
    "context"
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
            Type:       config.DatabaseTypeMongoDB,
            URI:        "mongodb://localhost:27017",
            Database:   "myapp",
            Collection: "users",
        },
        JWT: config.JWTConfig{
            SecretKey:       "your-secret-key",
            AccessTokenTTL:  15 * time.Minute,
            RefreshTokenTTL: 7 * 24 * time.Hour,
        },
        Email: config.EmailConfig{
            SMTPHost:     "smtp.gmail.com",
            SMTPPort:     587,
            SMTPUsername: "your-email@gmail.com",
            SMTPPassword: "your-app-password",
            FromEmail:    "noreply@yourapp.com",
            FromName:     "Your App",
            EmailVerificationTemplate: config.EmailTemplate{
                Subject: "Verify your email",
                Body:    "Click here to verify: {{.BaseURL}}/verify?token={{.Token}}",
            },
            PasswordResetTemplate: config.EmailTemplate{
                Subject: "Reset your password",
                Body:    "Click here to reset: {{.BaseURL}}/reset?token={{.Token}}",
            },
        },
        Google: config.GoogleConfig{
            Enabled:      true,
            ClientID:     "your-google-client-id.apps.googleusercontent.com",
            ClientSecret: "your-google-client-secret",
            RedirectURL:  "http://localhost:8080/auth/google/callback",
        },
        TikTok: config.TikTokConfig{
            Enabled:      true,
            ClientID:     "your-tiktok-client-key",
            ClientSecret: "your-tiktok-client-secret",
            RedirectURL:  "http://localhost:8080/auth/tiktok/callback",
        },
        Apple: config.AppleConfig{
            Enabled:     true,
            ClientID:    "com.yourcompany.yourapp", // Your Services ID
            TeamID:      "ABC123DEF4",              // Your Apple Developer Team ID
            KeyID:       "KEY123456",               // Your Private Key ID
            PrivateKey:  "-----BEGIN PRIVATE KEY-----\n...", // Your actual private key
            RedirectURL: "http://localhost:8080/auth/apple/callback",
        },
        Security: config.SecurityConfig{
            RequirePassword:   true,  // Require password authentication
            RequireGoogleAuth: false, // Google OAuth is optional
            RequireTikTokAuth: false, // TikTok OAuth is optional
            RequireAppleAuth:  false, // Apple Sign-In is optional
        },
    }

    // Initialize auth service
    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close(context.Background())

    // Register a new user
    user := &types.UserRegistration{
        Email:     "user@example.com",
        Password:  "securepassword123",
        FirstName: "John",
        LastName:  "Doe",
        CustomFields: map[string]interface{}{
            "phone_number": "+1234567890",
            "department":   "Engineering",
        },
    }

    response, err := auth.Register(context.Background(), user, "https://yourapp.com")
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("User registered: %s", response.User.Email)

    // Google OAuth authentication
    authURL := auth.GetGoogleAuthURL("state-string")
    log.Printf("Google OAuth URL: %s", authURL)

    // TikTok OAuth authentication
    tiktokAuthURL := auth.GetTikTokAuthURL("state-string")
    log.Printf("TikTok OAuth URL: %s", tiktokAuthURL)

    // Apple Sign-In authentication
    appleAuthURL := auth.GetAppleAuthURL("state-string")
    log.Printf("Apple Sign-In URL: %s", appleAuthURL)
}
```

## Documentation

- [Configuration](docs/configuration.md) - Detailed configuration options
- [Database Setup](docs/database.md) - MongoDB setup and configuration
- [Email Templates](docs/email-templates.md) - Email template configuration
- [API Reference](docs/api-reference.md) - Complete API documentation
- [Security](docs/security.md) - Security considerations and best practices
- [Examples](docs/examples.md) - Usage examples and patterns

## Architecture

The library is organized into several packages:

- `config/` - Configuration structures and defaults
- `types/` - Data structures and request/response types
- `database/` - MongoDB operations and connection management
- `auth/` - Core authentication logic and JWT management
- `email/` - Email service for verification and password reset
- `utils/` - Utility functions for password hashing and token generation

## Requirements

- Go 1.21 or higher
- MongoDB 4.0 or higher
- SMTP server for email functionality

## Contributing

This library is designed to be easily extensible. To add new features:

1. Add new types in the `types/` package
2. Implement database operations in `database/`
3. Add business logic in `auth/`
4. Update configuration in `config/` if needed
5. Add documentation and examples

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.