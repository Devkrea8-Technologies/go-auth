# Configuration

The Go Auth library is highly configurable to meet different application requirements. This document covers all configuration options and their defaults.

## Configuration Structure

The main configuration is defined in the `config.Config` struct:

```go
type Config struct {
    Database DatabaseConfig `json:"database"`
    JWT      JWTConfig      `json:"jwt"`
    Email    EmailConfig    `json:"email"`
    Security SecurityConfig `json:"security"`
    Google   GoogleConfig   `json:"google"`
    TikTok   TikTokConfig   `json:"tiktok"`
}
```

## Database Configuration

Database connection and collection settings. Supports both MongoDB and PostgreSQL:

```go
type DatabaseConfig struct {
    Type      DatabaseType `json:"type" validate:"required" default:"mongodb"`
    URI       string       `json:"uri" validate:"required"`
    Database  string       `json:"database" validate:"required"`
    Collection string      `json:"collection" default:"users"`
    
    // PostgreSQL specific fields
    Host     string `json:"host"`
    Port     int    `json:"port"`
    Username string `json:"username"`
    Password string `json:"password"`
    SSLMode  string `json:"ssl_mode" default:"disable"`
    
    // Connection pool settings
    MaxOpenConns    int           `json:"max_open_conns" default:"25"`
    MaxIdleConns    int           `json:"max_idle_conns" default:"5"`
    ConnMaxLifetime time.Duration `json:"conn_max_lifetime" default:"5m"`
}
```

### Options

- **URI**: MongoDB connection string (required)
  - Example: `"mongodb://localhost:27017"`
  - Example with auth: `"mongodb://username:password@localhost:27017"`
  - Example with options: `"mongodb://localhost:27017/?maxPoolSize=10&retryWrites=true"`

- **Database**: Database name (required)
  - Example: `"myapp"`

- **Collection**: Collection name for users (optional, default: "users")
  - Example: `"users"`

### Example

```go
Database: config.DatabaseConfig{
    URI:        "mongodb://localhost:27017",
    Database:   "myapp",
    Collection: "users",
},
```

## JWT Configuration

JWT token settings and security:

```go
type JWTConfig struct {
    SecretKey        string        `json:"secret_key" validate:"required"`
    AccessTokenTTL   time.Duration `json:"access_token_ttl" default:"15m"`
    RefreshTokenTTL  time.Duration `json:"refresh_token_ttl" default:"7d"`
    Issuer           string        `json:"issuer" default:"go-auth"`
    Audience         string        `json:"audience" default:"go-auth-users"`
}
```

### Options

- **SecretKey**: JWT signing secret (required)
  - Should be at least 32 characters long
  - Keep this secret and secure
  - Example: `"your-super-secret-key-here"`

- **AccessTokenTTL**: Access token expiration time (default: 15 minutes)
  - Example: `15 * time.Minute`
  - Example: `1 * time.Hour`

- **RefreshTokenTTL**: Refresh token expiration time (default: 7 days)
  - Example: `7 * 24 * time.Hour`
  - Example: `30 * 24 * time.Hour`

- **Issuer**: JWT issuer claim (default: "go-auth")
  - Example: `"myapp.com"`

- **Audience**: JWT audience claim (default: "go-auth-users")
  - Example: `"myapp-users"`

### Example

```go
JWT: config.JWTConfig{
    SecretKey:       "your-super-secret-key-here",
    AccessTokenTTL:  15 * time.Minute,
    RefreshTokenTTL: 7 * 24 * time.Hour,
    Issuer:          "myapp.com",
    Audience:        "myapp-users",
},
```

## Email Configuration

SMTP settings and email templates:

```go
type EmailConfig struct {
    SMTPHost     string `json:"smtp_host" validate:"required"`
    SMTPPort     int    `json:"smtp_port" validate:"required"`
    SMTPUsername string `json:"smtp_username" validate:"required"`
    SMTPPassword string `json:"smtp_password" validate:"required"`
    FromEmail    string `json:"from_email" validate:"required,email"`
    FromName     string `json:"from_name" validate:"required"`
    
    EmailVerificationTemplate EmailTemplate `json:"email_verification_template"`
    PasswordResetTemplate     EmailTemplate `json:"password_reset_template"`
}
```

### SMTP Options

- **SMTPHost**: SMTP server hostname (required)
  - Gmail: `"smtp.gmail.com"`
  - Outlook: `"smtp-mail.outlook.com"`
  - Custom: `"mail.yourdomain.com"`

- **SMTPPort**: SMTP server port (required)
  - TLS: `587` or `465`
  - Non-TLS: `25`

- **SMTPUsername**: SMTP username (required)
  - Usually your email address

- **SMTPPassword**: SMTP password (required)
  - For Gmail, use an App Password
  - For other providers, use your email password

- **FromEmail**: Sender email address (required)
  - Example: `"noreply@yourapp.com"`

- **FromName**: Sender name (required)
  - Example: `"Your App"`

### Email Templates

Email templates use Go's template syntax and support the following variables:

- `{{.UserEmail}}` - User's email address
- `{{.UserName}}` - User's first name
- `{{.Token}}` - Verification or reset token
- `{{.BaseURL}}` - Your application's base URL

```go
type EmailTemplate struct {
    Subject string `json:"subject" validate:"required"`
    Body    string `json:"body" validate:"required"`
}
```

### Example

```go
Email: config.EmailConfig{
    SMTPHost:     "smtp.gmail.com",
    SMTPPort:     587,
    SMTPUsername: "your-email@gmail.com",
    SMTPPassword: "your-app-password",
    FromEmail:    "noreply@yourapp.com",
    FromName:     "Your App",
    EmailVerificationTemplate: config.EmailTemplate{
        Subject: "Verify your email address",
        Body: `
            <h2>Welcome to Your App!</h2>
            <p>Hi {{.UserName}},</p>
            <p>Please verify your email address by clicking the link below:</p>
            <a href="{{.BaseURL}}/verify?token={{.Token}}">Verify Email</a>
            <p>This link will expire in 24 hours.</p>
        `,
    },
    PasswordResetTemplate: config.EmailTemplate{
        Subject: "Reset your password",
        Body: `
            <h2>Password Reset Request</h2>
            <p>Hi {{.UserName}},</p>
            <p>You requested a password reset. Click the link below to reset your password:</p>
            <a href="{{.BaseURL}}/reset?token={{.Token}}">Reset Password</a>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, please ignore this email.</p>
        `,
    },
},
```

## Google OAuth Configuration

Google OAuth 2.0 settings for social authentication:

```go
type GoogleConfig struct {
    ClientID     string `json:"client_id"`
    ClientSecret string `json:"client_secret"`
    RedirectURL  string `json:"redirect_url"`
    Enabled      bool   `json:"enabled" default:"false"`
}
```

### Options

- **ClientID**: Google OAuth client ID (required if enabled)
  - Get this from Google Cloud Console
  - Example: `"123456789-abc123.apps.googleusercontent.com"`

- **ClientSecret**: Google OAuth client secret (required if enabled)
  - Get this from Google Cloud Console
  - Keep this secret and secure

- **RedirectURL**: OAuth callback URL (required if enabled)
  - Must match the URL configured in Google Cloud Console
  - Example: `"http://localhost:8080/auth/google/callback"`

- **Enabled**: Enable Google OAuth (default: false)
  - Set to `true` to enable Google authentication

### Example

```go
Google: config.GoogleConfig{
    Enabled:      true,
    ClientID:     "your-google-client-id.apps.googleusercontent.com",
    ClientSecret: "your-google-client-secret",
    RedirectURL:  "http://localhost:8080/auth/google/callback",
},
```

## TikTok OAuth Configuration

TikTok OAuth 2.0 settings for social authentication:

```go
type TikTokConfig struct {
    ClientID     string `json:"client_id"`
    ClientSecret string `json:"client_secret"`
    RedirectURL  string `json:"redirect_url"`
    Enabled      bool   `json:"enabled" default:"false"`
}
```

### Options

- **ClientID**: TikTok OAuth client key (required if enabled)
  - Get this from TikTok for Developers
  - Example: `"your-tiktok-client-key"`

- **ClientSecret**: TikTok OAuth client secret (required if enabled)
  - Get this from TikTok for Developers
  - Keep this secret and secure

- **RedirectURL**: OAuth callback URL (required if enabled)
  - Must match the URL configured in TikTok for Developers
  - Example: `"http://localhost:8080/auth/tiktok/callback"`

- **Enabled**: Enable TikTok OAuth (default: false)
  - Set to `true` to enable TikTok authentication

### Example

```go
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
        PrivateKey: `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg+s07iAcV4u1uV1Jg
YjqUqC9N9d3qJVmQZ/3FzJ6SfGigCgYIKoZIzj0DAQehRANCAASdX41vxjHdFyTz
h0E1bJmQtHj7FfTb/J3L0K8eM0NzBgt1769Oua3HkKmSBlkQf1IO2h06d1cGFyC+
-----END PRIVATE KEY-----`,
        RedirectURL: "http://localhost:8080/auth/apple/callback",
    },
```

## Apple Sign-In Configuration

Apple Sign-In settings for social authentication:

```go
type AppleConfig struct {
    ClientID    string `json:"client_id"`    // Services ID (e.g., com.yourcompany.yourapp)
    TeamID      string `json:"team_id"`      // Apple Developer Team ID
    KeyID       string `json:"key_id"`       // Private Key ID
    PrivateKey  string `json:"private_key"`  // Private Key content (PEM format)
    RedirectURL string `json:"redirect_url"` // OAuth redirect URL
    Enabled     bool   `json:"enabled" default:"false"`
}
```

### Options

- **ClientID**: Your Services ID (required if enabled)
  - This is your app's bundle identifier (e.g., `com.yourcompany.yourapp`)
  - Get this from Apple Developer Console
  - Example: `"com.yourcompany.yourapp"`

- **TeamID**: Your Apple Developer Team ID (required if enabled)
  - Found in Apple Developer Console
  - Example: `"ABC123DEF4"`

- **KeyID**: The ID of your private key (required if enabled)
  - Found in Apple Developer Console when you create a private key
  - Example: `"KEY123456"`

- **PrivateKey**: Your private key content in PEM format (required if enabled)
  - Download from Apple Developer Console
  - Must be in PEM format
  - Example: `"-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg+s07iAcV4u1uV1Jg\nYjqUqC9N9d3qJVmQZ/3FzJ6SfGigCgYIKoZIzj0DAQehRANCAASdX41vxjHdFyTz\nh0E1bJmQtHj7FfTb/J3L0K8eM0NzBgt1769Oua3HkKmSBlkQf1IO2h06d1cGFyC+\n-----END PRIVATE KEY-----"`

- **RedirectURL**: OAuth callback URL (required if enabled)
  - Must match the URL configured in Apple Developer Console
  - Example: `"http://localhost:8080/auth/apple/callback"`

- **Enabled**: Enable Apple Sign-In (default: false)
  - Set to `true` to enable Apple Sign-In authentication

### Example

```go
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
```

### Apple Developer Setup

To use Apple Sign-In, you need to set up your Apple Developer account:

1. **Create a Services ID** in Apple Developer Console
   - Go to Certificates, Identifiers & Profiles
   - Click "Identifiers" and then "+"
   - Select "Services IDs" and click "Continue"
   - Enter a description and identifier (e.g., `com.yourcompany.yourapp`)
   - Enable "Sign In with Apple" and click "Continue"

2. **Generate a Private Key** for client authentication
   - Go to Certificates, Identifiers & Profiles
   - Click "Keys" and then "+"
   - Enter a name and enable "Sign In with Apple"
   - Click "Continue" and then "Register"
   - Download the private key file (`.p8` format)
   - Note the Key ID

3. **Configure Sign in with Apple** for your Services ID
   - Go back to your Services ID
   - Click "Edit" next to "Sign In with Apple"
   - Add your domain and redirect URLs
   - Click "Save"

4. **Note your credentials** for configuration
   - Team ID: Found in the top-right corner of Apple Developer Console
   - Services ID: The identifier you created (e.g., `com.yourcompany.yourapp`)
   - Key ID: The ID of the private key you created
   - Private Key: The content of the downloaded `.p8` file (convert to PEM format)
```

## Security Configuration

Security settings and policies:

```go
type SecurityConfig struct {
    PasswordMinLength     int           `json:"password_min_length" default:"8"`
    PasswordMaxLength     int           `json:"password_max_length" default:"128"`
    EmailVerificationTTL  time.Duration `json:"email_verification_ttl" default:"24h"`
    PasswordResetTTL      time.Duration `json:"password_reset_ttl" default:"1h"`
    MaxLoginAttempts      int           `json:"max_login_attempts" default:"5"`
    LockoutDuration       time.Duration `json:"lockout_duration" default:"15m"`
    RequireEmailVerification bool       `json:"require_email_verification" default:"true"`
    RequirePassword       bool          `json:"require_password" default:"true"`
    RequireGoogleAuth     bool          `json:"require_google_auth" default:"false"`
    RequireTikTokAuth     bool          `json:"require_tiktok_auth" default:"false"`
    RequireAppleAuth      bool          `json:"require_apple_auth" default:"false"`
    Enable2FA             bool          `json:"enable_2fa" default:"false"`
    Require2FA            bool          `json:"require_2fa" default:"false"`
}
```

### Options

- **PasswordMinLength**: Minimum password length (default: 8)
  - Example: `8`

- **PasswordMaxLength**: Maximum password length (default: 128)
  - Example: `128`

- **EmailVerificationTTL**: Email verification token expiration (default: 24 hours)
  - Example: `24 * time.Hour`

- **PasswordResetTTL**: Password reset token expiration (default: 1 hour)
  - Example: `1 * time.Hour`

- **MaxLoginAttempts**: Maximum failed login attempts (default: 5)
  - Example: `5`

- **LockoutDuration**: Account lockout duration after max attempts (default: 15 minutes)
  - Example: `15 * time.Minute`

- **RequireEmailVerification**: Require email verification for login (default: true)
  - Example: `true`

- **Enable2FA**: Enable Two-Factor Authentication functionality (default: false)
  - Example: `true`

- **Require2FA**: Require 2FA for all users (default: false)
  - Example: `false`

### Example

```go
Security: config.SecurityConfig{
    PasswordMinLength:         8,
    PasswordMaxLength:         128,
    EmailVerificationTTL:      24 * time.Hour,
    PasswordResetTTL:          1 * time.Hour,
    MaxLoginAttempts:          5,
    LockoutDuration:           15 * time.Minute,
    RequireEmailVerification:  true,
},
```

## Complete Configuration Example

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
        Issuer:          "myapp.com",
        Audience:        "myapp-users",
    },
    Email: config.EmailConfig{
        SMTPHost:     "smtp.gmail.com",
        SMTPPort:     587,
        SMTPUsername: "your-email@gmail.com",
        SMTPPassword: "your-app-password",
        FromEmail:    "noreply@myapp.com",
        FromName:     "My App",
        EmailVerificationTemplate: config.EmailTemplate{
            Subject: "Verify your email",
            Body:    "Click here to verify: {{.BaseURL}}/verify?token={{.Token}}",
        },
        PasswordResetTemplate: config.EmailTemplate{
            Subject: "Reset your password",
            Body:    "Click here to reset: {{.BaseURL}}/reset?token={{.Token}}",
        },
    },
    Security: config.SecurityConfig{
        PasswordMinLength:         8,
        PasswordMaxLength:         128,
        EmailVerificationTTL:      24 * time.Hour,
        PasswordResetTTL:          1 * time.Hour,
        MaxLoginAttempts:          5,
        LockoutDuration:           15 * time.Minute,
        RequireEmailVerification:  true,
        Enable2FA:                 true,
        Require2FA:                false,
    },
}
```

## Using Default Configuration

You can use the default configuration and override only the required fields:

```go
cfg := config.DefaultConfig()
cfg.Database.URI = "mongodb://localhost:27017"
cfg.Database.Database = "myapp"
cfg.JWT.SecretKey = "your-secret-key"
cfg.Email.SMTPHost = "smtp.gmail.com"
// ... set other required fields
```

## Environment Variables

For production deployments, consider loading configuration from environment variables:

```go
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
