# API Reference

This document provides a complete reference for the Go Auth library API.

## Main Library Interface

### New

Creates a new authentication instance.

```go
func New(cfg *config.Config) (*Auth, error)
```

**Parameters:**
- `cfg` - Configuration object (can be nil to use defaults)

**Returns:**
- `*Auth` - Authentication instance
- `error` - Error if initialization fails

**Example:**
```go
auth, err := goauth.New(cfg)
if err != nil {
    log.Fatal(err)
}
defer auth.Close(context.Background())
```

## Authentication Methods

### Register

Registers a new user with email verification.

```go
func (a *Auth) Register(ctx context.Context, req *types.UserRegistration, baseURL string) (*types.AuthResponse, error)
```

**Parameters:**
- `ctx` - Context for the operation
- `req` - User registration request
- `baseURL` - Base URL for email verification links

**Returns:**
- `*types.AuthResponse` - Authentication response with tokens
- `error` - Error if registration fails

**Example:**
```go
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

fmt.Printf("User registered: %s\n", response.User.Email)
fmt.Printf("Access token: %s\n", response.AccessToken)
```

### Login

Authenticates a user and returns access tokens.

```go
func (a *Auth) Login(ctx context.Context, req *types.UserLogin) (*types.AuthResponse, error)
```

**Parameters:**
- `ctx` - Context for the operation
- `req` - User login request

**Returns:**
- `*types.AuthResponse` - Authentication response with tokens
- `error` - Error if login fails

**Example:**
```go
login := &types.UserLogin{
    Email:    "user@example.com",
    Password: "securepassword123",
}

response, err := auth.Login(context.Background(), login)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("User logged in: %s\n", response.User.Email)
fmt.Printf("Access token: %s\n", response.AccessToken)
```

### VerifyEmail

Verifies a user's email address using a verification token.

```go
func (a *Auth) VerifyEmail(ctx context.Context, req *types.EmailVerificationRequest) error
```

**Parameters:**
- `ctx` - Context for the operation
- `req` - Email verification request

**Returns:**
- `error` - Error if verification fails

**Example:**
```go
verification := &types.EmailVerificationRequest{
    Token: "abc123...",
}

err := auth.VerifyEmail(context.Background(), verification)
if err != nil {
    log.Fatal(err)
}

fmt.Println("Email verified successfully")
```

### RequestPasswordReset

Sends a password reset email to the user.

```go
func (a *Auth) RequestPasswordReset(ctx context.Context, req *types.PasswordResetRequest, baseURL string) error
```

**Parameters:**
- `ctx` - Context for the operation
- `req` - Password reset request
- `baseURL` - Base URL for password reset links

**Returns:**
- `error` - Error if request fails

**Example:**
```go
reset := &types.PasswordResetRequest{
    Email: "user@example.com",
}

err := auth.RequestPasswordReset(context.Background(), reset, "https://yourapp.com")
if err != nil {
    log.Fatal(err)
}

fmt.Println("Password reset email sent")
```

### ResetPassword

Resets a user's password using a reset token.

```go
func (a *Auth) ResetPassword(ctx context.Context, req *types.PasswordResetConfirm) error
```

**Parameters:**
- `ctx` - Context for the operation
- `req` - Password reset confirmation

**Returns:**
- `error` - Error if reset fails

**Example:**
```go
reset := &types.PasswordResetConfirm{
    Token:    "abc123...",
    Password: "newpassword123",
}

err := auth.ResetPassword(context.Background(), reset)
if err != nil {
    log.Fatal(err)
}

fmt.Println("Password reset successfully")
```

### RefreshToken

Refreshes an access token using a refresh token.

```go
func (a *Auth) RefreshToken(ctx context.Context, refreshToken string) (*types.AuthResponse, error)
```

**Parameters:**
- `ctx` - Context for the operation
- `refreshToken` - Refresh token string

**Returns:**
- `*types.AuthResponse` - New authentication response
- `error` - Error if refresh fails

**Example:**
```go
response, err := auth.RefreshToken(context.Background(), "refresh_token_here")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("New access token: %s\n", response.AccessToken)
```

## User Management Methods

### GetUserByID

Retrieves a user by their ID.

```go
func (a *Auth) GetUserByID(ctx context.Context, userID primitive.ObjectID) (*types.User, error)
```

**Parameters:**
- `ctx` - Context for the operation
- `userID` - User's ObjectID

**Returns:**
- `*types.User` - User object
- `error` - Error if user not found or operation fails

**Example:**
```go
userID, _ := primitive.ObjectIDFromHex("507f1f77bcf86cd799439011")
user, err := auth.GetUserByID(context.Background(), userID)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("User: %s %s\n", user.FirstName, user.LastName)
```

### GetUserByEmail

Retrieves a user by their email address.

```go
func (a *Auth) GetUserByEmail(ctx context.Context, email string) (*types.User, error)
```

**Parameters:**
- `ctx` - Context for the operation
- `email` - User's email address

**Returns:**
- `*types.User` - User object
- `error` - Error if user not found or operation fails

**Example:**
```go
user, err := auth.GetUserByEmail(context.Background(), "user@example.com")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("User: %s %s\n", user.FirstName, user.LastName)
```

### ValidateToken

Validates a JWT token and returns the associated user.

```go
func (a *Auth) ValidateToken(ctx context.Context, tokenString string) (*types.User, error)
```

**Parameters:**
- `ctx` - Context for the operation
- `tokenString` - JWT token string

**Returns:**
- `*types.User` - User object from token
- `error` - Error if token is invalid or user not found

**Example:**
```go
user, err := auth.ValidateToken(context.Background(), "jwt_token_here")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Authenticated user: %s\n", user.Email)
```

## Google OAuth Methods

### GetGoogleAuthURL

Generates Google OAuth authorization URL.

```go
func (a *Auth) GetGoogleAuthURL(state string) string
```

**Parameters:**
- `state` - State parameter for CSRF protection

**Returns:**
- `string` - Google OAuth authorization URL (empty if not enabled)

**Example:**
```go
state := "random-state-string"
authURL := auth.GetGoogleAuthURL(state)
if authURL != "" {
    fmt.Printf("Google OAuth URL: %s\n", authURL)
} else {
    fmt.Println("Google OAuth is not enabled")
}
```

### AuthenticateWithGoogle

Authenticates a user with Google OAuth.

```go
func (a *Auth) AuthenticateWithGoogle(ctx context.Context, code string) (*types.AuthResponse, error)
```

**Parameters:**
- `ctx` - Context for the operation
- `code` - Authorization code from Google OAuth callback

**Returns:**
- `*types.AuthResponse` - Authentication response with tokens
- `error` - Error if authentication fails

**Example:**
```go
// Handle Google OAuth callback
authResponse, err := auth.AuthenticateWithGoogle(context.Background(), code)
if err != nil {
    log.Printf("Google authentication failed: %v", err)
} else {
    fmt.Printf("Google authentication successful: %s\n", authResponse.User.Email)
    fmt.Printf("Google ID: %s\n", authResponse.User.GoogleID)
    	fmt.Printf("Access token: %s\n", authResponse.AccessToken)
}
```

## TikTok OAuth Methods

### GetTikTokAuthURL

Generates TikTok OAuth authorization URL.

```go
func (a *Auth) GetTikTokAuthURL(state string) string
```

**Parameters:**
- `state` - State parameter for CSRF protection

**Returns:**
- `string` - TikTok OAuth authorization URL (empty if not enabled)

**Example:**
```go
state := "random-state-string"
authURL := auth.GetTikTokAuthURL(state)
if authURL != "" {
    fmt.Printf("TikTok OAuth URL: %s\n", authURL)
} else {
    fmt.Println("TikTok OAuth is not enabled")
}
```

### AuthenticateWithTikTok

Authenticates a user with TikTok OAuth.

```go
func (a *Auth) AuthenticateWithTikTok(ctx context.Context, code string) (*types.AuthResponse, error)
```

**Parameters:**
- `ctx` - Context for the operation
- `code` - Authorization code from TikTok OAuth callback

**Returns:**
- `*types.AuthResponse` - Authentication response with tokens
- `error` - Error if authentication fails

**Example:**
```go
// Handle TikTok OAuth callback
authResponse, err := auth.AuthenticateWithTikTok(context.Background(), code)
if err != nil {
    log.Printf("TikTok authentication failed: %v", err)
} else {
    fmt.Printf("TikTok authentication successful: %s\n", authResponse.User.Email)
    fmt.Printf("TikTok ID: %s\n", authResponse.User.TikTokID)
    fmt.Printf("Username: %s\n", authResponse.User.TikTokProfile.Username)
    fmt.Printf("Access token: %s\n", authResponse.AccessToken)
}
```

## Apple Sign-In Methods

### GetAppleAuthURL

Generates Apple Sign-In authorization URL.

```go
func (a *Auth) GetAppleAuthURL(state string) string
```

**Parameters:**
- `state` - State parameter for CSRF protection

**Returns:**
- `string` - Apple Sign-In authorization URL (empty if not enabled)

**Example:**
```go
state := "random-state-string"
authURL := auth.GetAppleAuthURL(state)
if authURL != "" {
    fmt.Printf("Apple Sign-In URL: %s\n", authURL)
} else {
    fmt.Println("Apple Sign-In is not enabled")
}
```

### AuthenticateWithApple

Authenticates a user with Apple Sign-In.

```go
func (a *Auth) AuthenticateWithApple(ctx context.Context, code string) (*types.AuthResponse, error)
```

**Parameters:**
- `ctx` - Context for the operation
- `code` - Authorization code from Apple Sign-In callback

**Returns:**
- `*types.AuthResponse` - Authentication response with tokens
- `error` - Error if authentication fails

**Example:**
```go
// Handle Apple Sign-In callback
authResponse, err := auth.AuthenticateWithApple(context.Background(), code)
if err != nil {
    log.Printf("Apple Sign-In failed: %v", err)
} else {
    fmt.Printf("Apple Sign-In successful: %s\n", authResponse.User.Email)
    fmt.Printf("Apple ID: %s\n", authResponse.User.AppleID)
    fmt.Printf("Email Verified: %t\n", authResponse.User.AppleProfile.EmailVerified == "true")
    fmt.Printf("Real User Status: %d\n", authResponse.User.AppleProfile.RealUserStatus)
    fmt.Printf("Access token: %s\n", authResponse.AccessToken)
}
```

## Two-Factor Authentication (2FA) Methods

### Setup2FA

Sets up 2FA for a user by generating a TOTP secret and backup codes.

**Signature:**
```go
func (a *Auth) Setup2FA(ctx context.Context, req *types.TwoFactorSetupRequest) (*types.TwoFactorSetupResponse, error)
```

**Parameters:**
- `ctx` (context.Context): Context for the operation
- `req` (*types.TwoFactorSetupRequest): Setup request containing user ID

**Returns:**
- `*types.TwoFactorSetupResponse`: Setup response with secret, QR code URL, and backup codes
- `error`: Error if setup fails

**Example:**
```go
setupReq := &types.TwoFactorSetupRequest{
    UserID: user.ID,
}

setupResponse, err := auth.Setup2FA(context.Background(), setupReq)
if err != nil {
    // Handle error
}

// Generate QR code for authenticator apps
qrCodeURL := setupResponse.QRCodeURL
// Store backup codes securely
backupCodes := setupResponse.BackupCodes
```

### Enable2FA

Enables 2FA for a user after they verify the setup code.

**Signature:**
```go
func (a *Auth) Enable2FA(ctx context.Context, req *types.TwoFactorVerifyRequest) error
```

**Parameters:**
- `ctx` (context.Context): Context for the operation
- `req` (*types.TwoFactorVerifyRequest): Verification request with user ID and TOTP code

**Returns:**
- `error`: Error if enabling fails

**Example:**
```go
enableReq := &types.TwoFactorVerifyRequest{
    UserID: user.ID,
    Code:   "123456", // Code from authenticator app
}

err := auth.Enable2FA(context.Background(), enableReq)
if err != nil {
    // Handle error
}
```

### Verify2FA

Verifies a 2FA code (TOTP or backup code).

**Signature:**
```go
func (a *Auth) Verify2FA(ctx context.Context, req *types.TwoFactorVerifyRequest) (bool, error)
```

**Parameters:**
- `ctx` (context.Context): Context for the operation
- `req` (*types.TwoFactorVerifyRequest): Verification request with user ID and code

**Returns:**
- `bool`: True if code is valid, false otherwise
- `error`: Error if verification fails

**Example:**
```go
verifyReq := &types.TwoFactorVerifyRequest{
    UserID: user.ID,
    Code:   "123456", // TOTP code or backup code
}

isValid, err := auth.Verify2FA(context.Background(), verifyReq)
if err != nil {
    // Handle error
}
if isValid {
    // Code is valid, proceed with authentication
}
```

### Disable2FA

Disables 2FA for a user after they provide a valid code.

**Signature:**
```go
func (a *Auth) Disable2FA(ctx context.Context, req *types.TwoFactorDisableRequest) error
```

**Parameters:**
- `ctx` (context.Context): Context for the operation
- `req` (*types.TwoFactorDisableRequest): Disable request with user ID and verification code

**Returns:**
- `error`: Error if disabling fails

**Example:**
```go
disableReq := &types.TwoFactorDisableRequest{
    UserID: user.ID,
    Code:   "123456", // TOTP code or backup code
}

err := auth.Disable2FA(context.Background(), disableReq)
if err != nil {
    // Handle error
}
```

## Utility Methods

### Close

Closes the authentication service and database connection.

```go
func (a *Auth) Close(ctx context.Context) error
```

**Parameters:**
- `ctx` - Context for the operation

**Returns:**
- `error` - Error if close fails

**Example:**
```go
err := auth.Close(context.Background())
if err != nil {
    log.Printf("Error closing auth service: %v", err)
}
```

### GetConfig

Returns the current configuration.

```go
func (a *Auth) GetConfig() *config.Config
```

**Returns:**
- `*config.Config` - Current configuration

**Example:**
```go
cfg := auth.GetConfig()
fmt.Printf("Database: %s\n", cfg.Database.Database)
```

## Custom Fields Methods

### UpdateUserCustomFields

Updates all custom fields for a user.

```go
func (a *Auth) UpdateUserCustomFields(ctx context.Context, userID primitive.ObjectID, customFields map[string]interface{}) error
```

**Parameters:**
- `ctx` - Context for the operation
- `userID` - User's ObjectID
- `customFields` - Map of custom field names to values

**Returns:**
- `error` - Error if operation fails

**Example:**
```go
customFields := map[string]interface{}{
    "phone_number": "+1234567890",
    "age":          30,
    "department":   "Engineering",
}

err := auth.UpdateUserCustomFields(context.Background(), userID, customFields)
if err != nil {
    log.Printf("Failed to update custom fields: %v", err)
}
```

### SetUserCustomField

Sets a single custom field for a user.

```go
func (a *Auth) SetUserCustomField(ctx context.Context, userID primitive.ObjectID, key string, value interface{}) error
```

**Parameters:**
- `ctx` - Context for the operation
- `userID` - User's ObjectID
- `key` - Custom field name
- `value` - Custom field value

**Returns:**
- `error` - Error if operation fails

**Example:**
```go
err := auth.SetUserCustomField(context.Background(), userID, "phone_number", "+1234567890")
if err != nil {
    log.Printf("Failed to set custom field: %v", err)
}
```

### GetUserCustomField

Gets a single custom field for a user.

```go
func (a *Auth) GetUserCustomField(ctx context.Context, userID primitive.ObjectID, key string) (interface{}, bool, error)
```

**Parameters:**
- `ctx` - Context for the operation
- `userID` - User's ObjectID
- `key` - Custom field name

**Returns:**
- `interface{}` - Custom field value
- `bool` - Whether the field exists
- `error` - Error if operation fails

**Example:**
```go
value, exists, err := auth.GetUserCustomField(context.Background(), userID, "phone_number")
if err != nil {
    log.Printf("Failed to get custom field: %v", err)
} else if exists {
    fmt.Printf("Phone number: %v\n", value)
}
```

### RemoveUserCustomField

Removes a custom field for a user.

```go
func (a *Auth) RemoveUserCustomField(ctx context.Context, userID primitive.ObjectID, key string) error
```

**Parameters:**
- `ctx` - Context for the operation
- `userID` - User's ObjectID
- `key` - Custom field name to remove

**Returns:**
- `error` - Error if operation fails

**Example:**
```go
err := auth.RemoveUserCustomField(context.Background(), userID, "phone_number")
if err != nil {
    log.Printf("Failed to remove custom field: %v", err)
}
```

## Data Types

### UserRegistration

```go
type UserRegistration struct {
    Email     string `json:"email" validate:"required,email"`
    Password  string `json:"password" validate:"required,min=8"` // Optional when Google OAuth is enabled
    FirstName string `json:"first_name" validate:"required"`
    LastName  string `json:"last_name" validate:"required"`
    
    // Custom fields support
    CustomFields map[string]interface{} `json:"custom_fields,omitempty"`
}
```

### UserLogin

```go
type UserLogin struct {
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required"`
}
```

### EmailVerificationRequest

```go
type EmailVerificationRequest struct {
    Token string `json:"token" validate:"required"`
}
```

### PasswordResetRequest

```go
type PasswordResetRequest struct {
    Email string `json:"email" validate:"required,email"`
}
```

### PasswordResetConfirm

```go
type PasswordResetConfirm struct {
    Token    string `json:"token" validate:"required"`
    Password string `json:"password" validate:"required,min=8"`
}
```

### AuthResponse

```go
type AuthResponse struct {
    User         *User  `json:"user"`
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token,omitempty"`
    ExpiresIn    int64  `json:"expires_in"`
}
```

### User

```go
type User struct {
    ID                interface{}        `bson:"_id,omitempty" json:"id,omitempty"`
    Email             string             `bson:"email" json:"email"`
    Password          string             `bson:"password" json:"-"`
    FirstName         string             `bson:"first_name" json:"first_name"`
    LastName          string             `bson:"last_name" json:"last_name"`
    IsEmailVerified   bool               `bson:"is_email_verified" json:"is_email_verified"`
    EmailVerification *EmailVerification `bson:"email_verification,omitempty" json:"email_verification,omitempty"`
    PasswordReset     *PasswordReset     `bson:"password_reset,omitempty" json:"password_reset,omitempty"`
    CreatedAt         time.Time          `bson:"created_at" json:"created_at"`
    UpdatedAt         time.Time          `bson:"updated_at" json:"updated_at"`
    LastLoginAt       *time.Time         `bson:"last_login_at,omitempty" json:"last_login_at,omitempty"`
    IsActive          bool               `bson:"is_active" json:"is_active"`
    
    // Google OAuth support
    GoogleID          string             `bson:"google_id,omitempty" json:"google_id,omitempty"`
    GoogleProfile     *GoogleProfile     `bson:"google_profile,omitempty" json:"google_profile,omitempty"`

    // TikTok OAuth support
    TikTokID          string             `bson:"tiktok_id,omitempty" json:"tiktok_id,omitempty"`
    TikTokProfile     *TikTokProfile     `bson:"tiktok_profile,omitempty" json:"tiktok_profile,omitempty"`

    // Apple Sign-In support
    AppleID           string             `bson:"apple_id,omitempty" json:"apple_id,omitempty"`
    AppleProfile      *AppleProfile      `bson:"apple_profile,omitempty" json:"apple_profile,omitempty"`

    // 2FA support
    TwoFactorEnabled     bool     `bson:"two_factor_enabled" json:"two_factor_enabled"`
    TwoFactorSecret      string   `bson:"two_factor_secret,omitempty" json:"two_factor_secret,omitempty"`
    TwoFactorBackupCodes []string `bson:"two_factor_backup_codes,omitempty" json:"two_factor_backup_codes,omitempty"`

    // Custom fields support
    CustomFields      map[string]interface{} `bson:"custom_fields,omitempty" json:"custom_fields,omitempty"`
}
```

### GoogleProfile

```go
type GoogleProfile struct {
    ID            string `json:"id"`
    Email         string `json:"email"`
    VerifiedEmail bool   `json:"verified_email"`
    Name          string `json:"name"`
    GivenName     string `json:"given_name"`
    FamilyName    string `json:"family_name"`
    Picture       string `json:"picture"`
    Locale        string `json:"locale"`
}
```

### TikTokProfile

```go
type TikTokProfile struct {
    ID             string `json:"id"`
    Username       string `json:"username"`
    DisplayName    string `json:"display_name"`
    ProfilePicture string `json:"profile_picture"`
    Bio            string `json:"bio"`
    FollowerCount  int    `json:"follower_count"`
    FollowingCount int    `json:"following_count"`
    LikesCount     int    `json:"likes_count"`
    VideoCount     int    `json:"video_count"`
    IsVerified     bool   `json:"is_verified"`
    IsPrivate      bool   `json:"is_private"`
}
```

### AppleProfile

```go
type AppleProfile struct {
    ID             string `json:"id"`
    Email          string `json:"email"`
    EmailVerified  string `json:"email_verified"`  // "true" or "false" as string
    IsPrivateEmail string `json:"is_private_email"` // "true" or "false" as string
    RealUserStatus int    `json:"real_user_status"` // 0: Unsupported, 1: Unknown, 2: LikelyReal
    FirstName      string `json:"first_name,omitempty"`
    LastName       string `json:"last_name,omitempty"`
}
```

### GoogleAuthRequest

```go
type GoogleAuthRequest struct {
    Code string `json:"code" validate:"required"`
}
```

### GoogleAuthResponse

```go
type GoogleAuthResponse struct {
    AuthURL string `json:"auth_url"`
    State   string `json:"state"`
}
```

### TikTokAuthRequest

```go
type TikTokAuthRequest struct {
    Code string `json:"code" validate:"required"`
}
```

### TikTokAuthResponse

```go
type TikTokAuthResponse struct {
    AuthURL string `json:"auth_url"`
    State   string `json:"state"`
}
```

### AppleAuthRequest

```go
type AppleAuthRequest struct {
    Code string `json:"code" validate:"required"`
}
```

### AppleAuthResponse

```go
type AppleAuthResponse struct {
    AuthURL string `json:"auth_url"`
    State   string `json:"state"`
}
```

### TwoFactorSetupRequest

```go
type TwoFactorSetupRequest struct {
    UserID interface{} `json:"user_id" validate:"required"`
}
```

### TwoFactorSetupResponse

```go
type TwoFactorSetupResponse struct {
    Secret      string   `json:"secret"`       // TOTP secret for QR code generation
    QRCodeURL   string   `json:"qr_code_url"`  // URL for QR code
    BackupCodes []string `json:"backup_codes"` // Backup codes for account recovery
}
```

### TwoFactorVerifyRequest

```go
type TwoFactorVerifyRequest struct {
    UserID interface{} `json:"user_id" validate:"required"`
    Code   string      `json:"code" validate:"required"` // TOTP code or backup code
}
```

### TwoFactorDisableRequest

```go
type TwoFactorDisableRequest struct {
    UserID interface{} `json:"user_id" validate:"required"`
    Code   string      `json:"code" validate:"required"` // TOTP code or backup code
}
```

**Custom Fields Methods:**
```go
// GetCustomFields returns all custom fields
func (u *User) GetCustomFields() map[string]interface{}

// SetCustomFields sets all custom fields
func (u *User) SetCustomFields(fields map[string]interface{})

// SetCustomField sets a single custom field
func (u *User) SetCustomField(key string, value interface{})

// GetCustomField gets a single custom field
func (u *User) GetCustomField(key string) (interface{}, bool)

// RemoveCustomField removes a custom field
func (u *User) RemoveCustomField(key string)
```

## Error Handling

The library returns descriptive errors for various scenarios:

### Common Errors

- `"user with email %s already exists"` - Email already registered
- `"invalid email or password"` - Login credentials incorrect
- `"email verification required"` - Email not verified (when required)
- `"invalid verification token"` - Email verification token invalid
- `"verification token has expired"` - Email verification token expired
- `"email already verified"` - Email already verified
- `"invalid reset token"` - Password reset token invalid
- `"reset token has expired"` - Password reset token expired
- `"reset token already used"` - Password reset token already used
- `"invalid refresh token"` - Refresh token invalid
- `"user not found"` - User not found in database
- `"account is deactivated"` - User account is inactive

### Error Handling Example

```go
response, err := auth.Login(context.Background(), login)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "invalid email or password"):
        // Handle invalid credentials
        fmt.Println("Invalid email or password")
    case strings.Contains(err.Error(), "email verification required"):
        // Handle unverified email
        fmt.Println("Please verify your email first")
    case strings.Contains(err.Error(), "account is deactivated"):
        // Handle deactivated account
        fmt.Println("Account is deactivated")
    default:
        // Handle other errors
        log.Printf("Login error: %v", err)
    }
    return
}
```

## Context Usage

All methods accept a context.Context parameter for:

- Request cancellation
- Timeout handling
- Request tracing
- Cancellation propagation

**Example with timeout:**
```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

response, err := auth.Login(ctx, login)
if err != nil {
    if ctx.Err() == context.DeadlineExceeded {
        fmt.Println("Request timed out")
    } else {
        log.Printf("Login error: %v", err)
    }
    return
}
```

## Thread Safety

The Auth instance is safe for concurrent use. Multiple goroutines can safely call methods on the same Auth instance.

**Example:**
```go
var wg sync.WaitGroup

for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()
        
        user := &types.UserRegistration{
            Email:     fmt.Sprintf("user%d@example.com", id),
            Password:  "password123",
            FirstName: "User",
            LastName:  fmt.Sprintf("%d", id),
        }
        
        _, err := auth.Register(context.Background(), user, "https://yourapp.com")
        if err != nil {
            log.Printf("Registration failed: %v", err)
        }
    }(i)
}

wg.Wait()
```
