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
