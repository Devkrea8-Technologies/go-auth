# Getting Started

This guide will help you get the Go Auth library up and running quickly.

## Prerequisites

- Go 1.21 or higher
- MongoDB 4.0 or higher
- SMTP server (for email functionality)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd go-auth
   ```

2. **Install dependencies**
   ```bash
   cd go-auth
   go mod tidy
   ```

3. **Set up MongoDB**
   ```bash
   # Install MongoDB (Ubuntu/Debian)
   sudo apt-get install mongodb
   
   # Install MongoDB (macOS with Homebrew)
   brew install mongodb-community
   
   # Start MongoDB service
   sudo systemctl start mongodb  # Linux
   brew services start mongodb-community  # macOS
   ```

## Quick Start

### 1. Basic Configuration

Create a simple configuration file or define it in your code:

```go
package main

import (
    "context"
    "log"
    "time"
    
    "github.com/Devkrea8-Technologies/go-auth"
    "github.com/Devkrea8-Technologies/go-auth/config"
    "github.com/Devkrea8-Technologies/go-auth/types"
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
            SecretKey:       "your-super-secret-key-here",
            AccessTokenTTL:  15 * time.Minute,
            RefreshTokenTTL: 7 * 24 * time.Hour,
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

    response, err := auth.Register(context.Background(), user, "https://myapp.com")
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("User registered: %s", response.User.Email)
}
```

### 2. With Email Verification

For email verification functionality, add email configuration:

```go
cfg := &config.Config{
    Database: config.DatabaseConfig{
        URI:        "mongodb://localhost:27017",
        Database:   "myapp",
        Collection: "users",
    },
    JWT: config.JWTConfig{
        SecretKey:       "your-super-secret-key-here",
        AccessTokenTTL:  15 * time.Minute,
        RefreshTokenTTL: 7 * 24 * time.Hour,
    },
    Email: config.EmailConfig{
        SMTPHost:     "smtp.gmail.com",
        SMTPPort:     587,
        SMTPUsername: "your-email@gmail.com",
        SMTPPassword: "your-app-password",
        FromEmail:    "noreply@myapp.com",
        FromName:     "My App",
        EmailVerificationTemplate: config.EmailTemplate{
            Subject: "Verify your email address",
            Body:    "Click here to verify: {{.BaseURL}}/verify?token={{.Token}}",
        },
        PasswordResetTemplate: config.EmailTemplate{
            Subject: "Reset your password",
            Body:    "Click here to reset: {{.BaseURL}}/reset?token={{.Token}}",
        },
    },
    Security: config.SecurityConfig{
        RequireEmailVerification: true,
    },
}
```

### 3. Run the Example

```bash
cd go-auth/example
go run main.go
```

## Environment Variables

For production deployments, use environment variables:

```go
import "os"

cfg := &config.Config{
    Database: config.DatabaseConfig{
        URI:        os.Getenv("MONGODB_URI"),
        Database:   os.Getenv("MONGODB_DATABASE"),
        Collection: "users",
    },
    JWT: config.JWTConfig{
        SecretKey: os.Getenv("JWT_SECRET_KEY"),
        // ... other JWT settings
    },
    Email: config.EmailConfig{
        SMTPHost:     os.Getenv("SMTP_HOST"),
        SMTPPort:     port, // convert from string
        SMTPUsername: os.Getenv("SMTP_USERNAME"),
        SMTPPassword: os.Getenv("SMTP_PASSWORD"),
        // ... other email settings
    },
}
```

## Troubleshooting

### Common Issues

1. **MongoDB Connection Failed**
   - Ensure MongoDB is running
   - Check connection string format
   - Verify network access

2. **Email Not Sending**
   - Check SMTP credentials
   - Verify email templates
   - Check firewall settings

3. **JWT Token Issues**
   - Ensure secret key is set
   - Check token expiration settings
   - Verify issuer and audience

### Debug Mode

Enable debug logging:

```go
// Add logging to your application
log.SetLevel(log.DebugLevel)
```

## Next Steps

1. **Read the Documentation**
   - [Configuration](configuration.md)
   - [API Reference](api-reference.md)
   - [Security](security.md)

2. **Explore Examples**
   - [Basic Examples](examples.md)
   - [Web Framework Integration](examples.md)

3. **Customize for Your Needs**
   - Extend user types
   - Add custom validation
   - Implement role-based access

## Support

If you encounter issues:

1. Check the troubleshooting section
2. Review the documentation
3. Look at the examples
4. Check the GitHub issues

## Contributing

We welcome contributions! Please see the contributing guidelines for more information.
