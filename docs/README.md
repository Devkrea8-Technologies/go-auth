# Go Auth Library

A comprehensive authentication library for Go applications with MongoDB support, email verification, and password reset functionality.

## Features

- **User Registration & Login**: Secure user registration and authentication
- **Email Verification**: Email verification with customizable templates
- **Password Reset**: Secure password reset functionality
- **JWT Tokens**: Access and refresh token management
- **MongoDB Support**: Built-in MongoDB integration with proper indexing
- **Configurable**: Highly configurable security settings and email templates
- **Extensible**: Easy to extend with additional authentication methods

## Quick Start

### Installation

```bash
go get github.com/Devkrea8-Technologies/go-auth/go-auth
```

### Basic Usage

```go
package main

import (
    "context"
    "log"
    
    "github.com/Devkrea8-Technologies/go-auth/go-auth"
    "github.com/Devkrea8-Technologies/go-auth/go-auth/config"
    "github.com/Devkrea8-Technologies/go-auth/go-auth/types"
)

func main() {
    // Create configuration
    cfg := &config.Config{
        Database: config.DatabaseConfig{
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
    }

    response, err := auth.Register(context.Background(), user, "https://yourapp.com")
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("User registered: %s", response.User.Email)
}
```

## Documentation

- [Configuration](configuration.md) - Detailed configuration options
- [Database Setup](database.md) - MongoDB setup and configuration
- [Email Templates](email-templates.md) - Email template configuration
- [API Reference](api-reference.md) - Complete API documentation
- [Security](security.md) - Security considerations and best practices
- [Examples](examples.md) - Usage examples and patterns

## Architecture

The library is organized into several packages:

- `config/` - Configuration structures and defaults
- `types/` - Data structures and request/response types
- `database/` - MongoDB operations and connection management
- `auth/` - Core authentication logic and JWT management
- `email/` - Email service for verification and password reset
- `utils/` - Utility functions for password hashing and token generation

## Contributing

This library is designed to be easily extensible. To add new features:

1. Add new types in the `types/` package
2. Implement database operations in `database/`
3. Add business logic in `auth/`
4. Update configuration in `config/` if needed
5. Add documentation and examples

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.
