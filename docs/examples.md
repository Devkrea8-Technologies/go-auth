# Examples

This document provides examples of how to use the Go Auth library in different scenarios.

## Basic Usage

### Simple Registration and Login

```go
package main

import (
    "context"
    "fmt"
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
            SecretKey:       "your-secret-key-here",
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
        Password:  "password123",
        FirstName: "John",
        LastName:  "Doe",
    }

    response, err := auth.Register(context.Background(), user, "https://myapp.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("User registered: %s\n", response.User.Email)

    // Login the user
    login := &types.UserLogin{
        Email:    "user@example.com",
        Password: "password123",
    }

    loginResponse, err := auth.Login(context.Background(), login)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("User logged in: %s\n", loginResponse.User.Email)
    fmt.Printf("Access token: %s\n", loginResponse.AccessToken)
}
```

## Google OAuth Integration

### Basic Google OAuth Setup

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    
    "github.com/Devkrea8-Technologies/go-auth"
    "github.com/Devkrea8-Technologies/go-auth/config"
    "github.com/Devkrea8-Technologies/go-auth/types"
)

func main() {
    // Create configuration with Google OAuth enabled
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
        },
        Google: config.GoogleConfig{
            Enabled:      true,
            ClientID:     "your-google-client-id.apps.googleusercontent.com",
            ClientSecret: "your-google-client-secret",
            RedirectURL:  "http://localhost:8080/auth/google/callback",
        },
        Security: config.SecurityConfig{
            RequirePassword:   false, // Allow users without passwords
            RequireGoogleAuth: false, // Google OAuth is optional
        },
    }

    // Initialize auth service
    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close(context.Background())

    // Generate Google OAuth URL
    state := "random-state-string-for-security"
    authURL := auth.GetGoogleAuthURL(state)
    fmt.Printf("Google OAuth URL: %s\n", authURL)

    // In a real application, redirect user to authURL
    // Then handle the callback with the authorization code
}
```

### Google OAuth Callback Handler

```go
func handleGoogleCallback(auth *goauth.Auth, code string) {
    // Authenticate with Google OAuth
    authResponse, err := auth.AuthenticateWithGoogle(context.Background(), code)
    if err != nil {
        log.Printf("Google authentication failed: %v", err)
        return
    }

    fmt.Printf("Google authentication successful: %s\n", authResponse.User.Email)
    fmt.Printf("Google ID: %s\n", authResponse.User.GoogleID)
    fmt.Printf("Profile picture: %s\n", authResponse.User.GoogleProfile.Picture)
    fmt.Printf("Access token: %s\n", authResponse.AccessToken)
}
```

### Flexible Authentication (Password + Google OAuth)

```go
func main() {
    // Configuration allowing both password and Google OAuth
    cfg := &config.Config{
        // ... other config
        Security: config.SecurityConfig{
            RequirePassword:   true,  // Require password authentication
            RequireGoogleAuth: false, // Google OAuth is optional
        },
    }

    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close(context.Background())

    // Register user with password (Google OAuth can be added later)
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

    response, err := auth.Register(context.Background(), user, "https://myapp.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("User registered: %s\n", response.User.Email)

    // Later, user can authenticate with Google OAuth
    // The system will link the Google account to the existing user
}
```

## Web Framework Integration

### Gin Framework

```go
package main

import (
    "context"
    "net/http"
    "time"
    
    "github.com/gin-gonic/gin"
    "github.com/Devkrea8-Technologies/go-auth"
    "github.com/Devkrea8-Technologies/go-auth/config"
    "github.com/Devkrea8-Technologies/go-auth/types"
)

type AuthHandler struct {
    auth *goauth.Auth
}

func NewAuthHandler(auth *goauth.Auth) *AuthHandler {
    return &AuthHandler{auth: auth}
}

func (h *AuthHandler) Register(c *gin.Context) {
    var req types.UserRegistration
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    response, err := h.auth.Register(c.Request.Context(), &req, "https://myapp.com")
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusCreated, response)
}

func (h *AuthHandler) Login(c *gin.Context) {
    var req types.UserLogin
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    response, err := h.auth.Login(c.Request.Context(), &req)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, response)
}

// JWT middleware
func (h *AuthHandler) AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        if token == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
            c.Abort()
            return
        }

        if len(token) > 7 && token[:7] == "Bearer " {
            token = token[7:]
        }

        user, err := h.auth.ValidateToken(c.Request.Context(), token)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        c.Set("user", user)
        c.Next()
    }
}

func main() {
    cfg := &config.Config{
        Database: config.DatabaseConfig{
            URI:        "mongodb://localhost:27017",
            Database:   "myapp",
            Collection: "users",
        },
        JWT: config.JWTConfig{
            SecretKey:       "your-secret-key-here",
            AccessTokenTTL:  15 * time.Minute,
            RefreshTokenTTL: 7 * 24 * time.Hour,
        },
    }

    auth, err := goauth.New(cfg)
    if err != nil {
        panic(err)
    }
    defer auth.Close(context.Background())

    authHandler := NewAuthHandler(auth)

    r := gin.Default()

    // Public routes
    r.POST("/auth/register", authHandler.Register)
    r.POST("/auth/login", authHandler.Login)

    // Protected routes
    protected := r.Group("/api")
    protected.Use(authHandler.AuthMiddleware())
    {
        protected.GET("/profile", func(c *gin.Context) {
            user := c.MustGet("user").(*types.User)
            c.JSON(http.StatusOK, gin.H{
                "id":    user.ID,
                "email": user.Email,
                "name":  user.FirstName + " " + user.LastName,
            })
        })
    }

    r.Run(":8080")
}
```

## Error Handling

```go
func handleAuthError(err error) string {
    if err == nil {
        return ""
    }

    errMsg := err.Error()
    
    switch {
    case strings.Contains(errMsg, "already exists"):
        return "A user with this email already exists"
    case strings.Contains(errMsg, "invalid email or password"):
        return "Invalid email or password"
    case strings.Contains(errMsg, "email verification required"):
        return "Please verify your email address before logging in"
    case strings.Contains(errMsg, "invalid verification token"):
        return "Invalid or expired verification token"
    case strings.Contains(errMsg, "account is deactivated"):
        return "Your account has been deactivated"
    default:
        return "An error occurred. Please try again"
    }
}
```

## Testing

```go
func TestUserRegistration(t *testing.T) {
    cfg := &config.Config{
        Database: config.DatabaseConfig{
            URI:        "mongodb://localhost:27017",
            Database:   "test_db",
            Collection: "users",
        },
        JWT: config.JWTConfig{
            SecretKey:       "test-secret-key",
            AccessTokenTTL:  15 * time.Minute,
            RefreshTokenTTL: 7 * 24 * time.Hour,
        },
    }

    auth, err := goauth.New(cfg)
    require.NoError(t, err)
    defer auth.Close(context.Background())

    user := &types.UserRegistration{
        Email:     "test@example.com",
        Password:  "password123",
        FirstName: "Test",
        LastName:  "User",
    }

    response, err := auth.Register(context.Background(), user, "https://test.com")
    require.NoError(t, err)
    assert.NotNil(t, response)
    assert.Equal(t, user.Email, response.User.Email)
    assert.NotEmpty(t, response.AccessToken)
}
```

## Complete Example with Email

```go
func main() {
    cfg := &config.Config{
        Database: config.DatabaseConfig{
            URI:        "mongodb://localhost:27017",
            Database:   "myapp",
            Collection: "users",
        },
        JWT: config.JWTConfig{
            SecretKey:       "your-secret-key-here",
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

    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close(context.Background())

    // Register user (will send verification email)
    user := &types.UserRegistration{
        Email:     "user@example.com",
        Password:  "password123",
        FirstName: "John",
        LastName:  "Doe",
    }

    response, err := auth.Register(context.Background(), user, "https://myapp.com")
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("User registered: %s", response.User.Email)
    log.Printf("Email verification required: %t", !response.User.IsEmailVerified)
}
```

## Apple Sign-In Integration

### Basic Apple Sign-In Setup

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    
    "github.com/Devkrea8-Technologies/go-auth"
    "github.com/Devkrea8-Technologies/go-auth/config"
    "github.com/Devkrea8-Technologies/go-auth/types"
)

func main() {
    // Create configuration with Apple Sign-In enabled
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
        },
        Apple: config.AppleConfig{
            Enabled:     true,
            ClientID:    "com.yourcompany.yourapp", // Your Services ID
            TeamID:      "ABC123DEF4",              // Your Apple Developer Team ID
            KeyID:       "KEY123456",               // Your Private Key ID
            PrivateKey: `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg+s07iAcV4u1uV1Jg
YjqUqC9N9d3qJVmQZ/3FzJ6SfGigCgYIKoZIzj0DAQehRANCAASdX41vxjHdFyTz
h0E1bJmQtHj7FfTb/J3L0K8eM0NzBgt1769Oua3HkKmSBlkQf1IO2h06d1cGFyC+
-----END PRIVATE KEY-----`,
            RedirectURL: "http://localhost:8080/auth/apple/callback",
        },
        Security: config.SecurityConfig{
            RequirePassword:  false, // Allow users without passwords
            RequireAppleAuth: false, // Apple Sign-In is optional
        },
    }

    // Initialize auth service
    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close(context.Background())

    // Generate Apple Sign-In URL
    state := "random-state-string-for-security"
    authURL := auth.GetAppleAuthURL(state)
    fmt.Printf("Apple Sign-In URL: %s\n", authURL)

    // In a real application, redirect user to authURL
    // Then handle the callback with the authorization code
}
```

### Apple Sign-In Callback Handler

```go
func handleAppleCallback(auth *goauth.Auth, code string) {
    // Authenticate with Apple Sign-In
    authResponse, err := auth.AuthenticateWithApple(context.Background(), code)
    if err != nil {
        log.Printf("Apple Sign-In failed: %v", err)
        return
    }

    fmt.Printf("Apple Sign-In successful: %s\n", authResponse.User.Email)
    fmt.Printf("Apple ID: %s\n", authResponse.User.AppleID)
    fmt.Printf("Email Verified: %s\n", authResponse.User.AppleProfile.EmailVerified)
    fmt.Printf("Real User Status: %d\n", authResponse.User.AppleProfile.RealUserStatus)
    fmt.Printf("Is Private Email: %s\n", authResponse.User.AppleProfile.IsPrivateEmail)
    fmt.Printf("First Name: %s\n", authResponse.User.AppleProfile.FirstName)
    fmt.Printf("Last Name: %s\n", authResponse.User.AppleProfile.LastName)
}
```

### Multi-Provider Authentication (Password + Google + TikTok + Apple)

```go
func main() {
    // Configuration allowing all authentication methods
    cfg := &config.Config{
        // ... other config
        Security: config.SecurityConfig{
            RequirePassword:   true,  // Require password authentication
            RequireGoogleAuth: false, // Google OAuth is optional
            RequireTikTokAuth: false, // TikTok OAuth is optional
            RequireAppleAuth:  false, // Apple Sign-In is optional
        },
    }

    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal(err)
    }

    // Users can authenticate with any combination:
    // - Email/password only
    // - Google OAuth only
    // - TikTok OAuth only
    // - Apple Sign-In only
    // - Any combination of the above

    // The library automatically handles:
    // - User account linking
    // - Profile data merging
    // - Authentication method preferences
    // - Security validation
}
```

## Two-Factor Authentication (2FA) Integration

### Basic 2FA Setup

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    
    "github.com/Devkrea8-Technologies/go-auth"
    "github.com/Devkrea8-Technologies/go-auth/config"
    "github.com/Devkrea8-Technologies/go-auth/types"
)

func main() {
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
            Require2FA: false, // Make 2FA optional
        },
    }

    // Initialize auth service
    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close(context.Background())

    // Register a user first
    user := &types.UserRegistration{
        Email:     "user@example.com",
        Password:  "securepassword123",
        FirstName: "John",
        LastName:  "Doe",
    }

    response, err := auth.Register(context.Background(), user, "https://example.com")
    if err != nil {
        log.Fatal(err)
    }

    // Setup 2FA
    setupReq := &types.TwoFactorSetupRequest{
        UserID: response.User.ID,
    }

    setupResponse, err := auth.Setup2FA(context.Background(), setupReq)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("2FA Setup successful!\n")
    fmt.Printf("Secret: %s\n", setupResponse.Secret)
    fmt.Printf("QR Code URL: %s\n", setupResponse.QRCodeURL)
    fmt.Printf("Backup Codes: %v\n", setupResponse.BackupCodes)
}
```

### 2FA Verification Flow

```go
func handle2FAVerification(auth *goauth.Auth, userID interface{}, code string) {
    // Verify 2FA code
    verifyReq := &types.TwoFactorVerifyRequest{
        UserID: userID,
        Code:   code, // TOTP code or backup code
    }

    isValid, err := auth.Verify2FA(context.Background(), verifyReq)
    if err != nil {
        log.Printf("2FA verification failed: %v", err)
        return
    }

    if isValid {
        fmt.Println("2FA code verified successfully!")
        // Proceed with authentication
    } else {
        fmt.Println("Invalid 2FA code")
    }
}
```

### Enable 2FA

```go
func enable2FA(auth *goauth.Auth, userID interface{}, totpCode string) error {
    // User scans QR code and enters the code from their authenticator app
    enableReq := &types.TwoFactorVerifyRequest{
        UserID: userID,
        Code:   totpCode, // Code from authenticator app
    }

    err := auth.Enable2FA(context.Background(), enableReq)
    if err != nil {
        return fmt.Errorf("failed to enable 2FA: %w", err)
    }

    fmt.Println("2FA enabled successfully!")
    return nil
}
```

### Disable 2FA

```go
func disable2FA(auth *goauth.Auth, userID interface{}, code string) error {
    // User must provide a valid 2FA code to disable
    disableReq := &types.TwoFactorDisableRequest{
        UserID: userID,
        Code:   code, // TOTP code or backup code
    }

    err := auth.Disable2FA(context.Background(), disableReq)
    if err != nil {
        return fmt.Errorf("failed to disable 2FA: %w", err)
    }

    fmt.Println("2FA disabled successfully!")
    return nil
}
```

### Using Backup Codes

```go
func useBackupCode(auth *goauth.Auth, userID interface{}, backupCode string) {
    // Use backup code for account recovery
    backupReq := &types.TwoFactorVerifyRequest{
        UserID: userID,
        Code:   backupCode, // Backup code
    }

    isValid, err := auth.Verify2FA(context.Background(), backupReq)
    if err != nil {
        log.Printf("Backup code verification failed: %v", err)
        return
    }

    if isValid {
        fmt.Println("Backup code verified successfully!")
        fmt.Println("Note: This backup code has been consumed and cannot be used again.")
    } else {
        fmt.Println("Invalid backup code")
    }
}
```

### Multi-Provider Authentication with 2FA

```go
func main() {
    // Configuration allowing all authentication methods including 2FA
    cfg := &config.Config{
        // ... other config
        Security: config.SecurityConfig{
            RequirePassword:   true,  // Require password authentication
            RequireGoogleAuth: false, // Google OAuth is optional
            RequireTikTokAuth: false, // TikTok OAuth is optional
            RequireAppleAuth:  false, // Apple Sign-In is optional
            Enable2FA:         true,  // Enable 2FA functionality
            Require2FA:        false, // 2FA is optional
        },
    }

    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal(err)
    }

    // Users can authenticate with any combination:
    // - Email/password only
    // - Google OAuth only
    // - TikTok OAuth only
    // - Apple Sign-In only
    // - Any combination of the above
    // - Plus optional 2FA for any authentication method

    // The library automatically handles:
    // - User account linking
    // - Profile data merging
    // - Authentication method preferences
    // - Security validation
    // - 2FA setup and verification
}
```

These examples show the most common usage patterns. For more advanced scenarios, refer to the API documentation.

## TikTok OAuth Integration

### Basic TikTok OAuth Setup

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    
    "github.com/Devkrea8-Technologies/go-auth"
    "github.com/Devkrea8-Technologies/go-auth/config"
    "github.com/Devkrea8-Technologies/go-auth/types"
)

func main() {
    // Create configuration with TikTok OAuth enabled
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
        },
        TikTok: config.TikTokConfig{
            Enabled:      true,
            ClientID:     "your-tiktok-client-key",
            ClientSecret: "your-tiktok-client-secret",
            RedirectURL:  "http://localhost:8080/auth/tiktok/callback",
        },
        Security: config.SecurityConfig{
            RequirePassword:   false, // Allow users without passwords
            RequireTikTokAuth: false, // TikTok OAuth is optional
        },
    }

    // Initialize auth service
    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close(context.Background())

    // Generate TikTok OAuth URL
    state := "random-state-string-for-security"
    authURL := auth.GetTikTokAuthURL(state)
    fmt.Printf("TikTok OAuth URL: %s\n", authURL)

    // In a real application, redirect user to authURL
    // Then handle the callback with the authorization code
}
```

### TikTok OAuth Callback Handler

```go
func handleTikTokCallback(auth *goauth.Auth, code string) {
    // Authenticate with TikTok OAuth
    authResponse, err := auth.AuthenticateWithTikTok(context.Background(), code)
    if err != nil {
        log.Printf("TikTok authentication failed: %v", err)
        return
    }

    fmt.Printf("TikTok authentication successful: %s\n", authResponse.User.Email)
    fmt.Printf("TikTok ID: %s\n", authResponse.User.TikTokID)
    fmt.Printf("Username: %s\n", authResponse.User.TikTokProfile.Username)
    fmt.Printf("Display Name: %s\n", authResponse.User.TikTokProfile.DisplayName)
    fmt.Printf("Follower Count: %d\n", authResponse.User.TikTokProfile.FollowerCount)
}
```

### Multi-Provider Authentication (Password + Google + TikTok)

```go
func main() {
    // Configuration allowing all authentication methods
    cfg := &config.Config{
        // ... other config
        Security: config.SecurityConfig{
            RequirePassword:   true,  // Require password authentication
            RequireGoogleAuth: false, // Google OAuth is optional
            RequireTikTokAuth: false, // TikTok OAuth is optional
            RequireAppleAuth:  false, // Apple Sign-In is optional
        },
    }

    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close(context.Background())

    // Register user with password
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

    response, err := auth.Register(context.Background(), user, "https://myapp.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("User registered: %s\n", response.User.Email)

    // Later, user can authenticate with Google OAuth
    // The system will link the Google account to the existing user

    // Later, user can authenticate with TikTok OAuth
    // The system will link the TikTok account to the existing user

    // User can now login with any of the three methods:
    // 1. Email/password
    // 2. Google OAuth
    // 3. TikTok OAuth
}
```
