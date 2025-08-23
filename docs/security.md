# Security

This document covers security considerations, best practices, and recommendations for using the Go Auth library securely.

## Security Features

The Go Auth library includes several built-in security features:

### Password Security

- **Bcrypt Hashing**: Passwords are hashed using bcrypt with a cost factor of 10
- **Salt Generation**: Each password is automatically salted
- **Minimum Length**: Configurable minimum password length (default: 8 characters)
- **Maximum Length**: Configurable maximum password length (default: 128 characters)

### Token Security

- **JWT Tokens**: Secure JWT tokens with configurable expiration
- **Refresh Tokens**: Separate refresh tokens for token renewal
- **Token Expiration**: Configurable token expiration times
- **Secure Signing**: HMAC-SHA256 signing algorithm

### Email Security

- **Verification Tokens**: Secure random tokens for email verification
- **Reset Tokens**: Secure random tokens for password reset
- **Token Expiration**: Configurable token expiration times
- **One-time Use**: Password reset tokens are single-use

## Configuration Security

### JWT Configuration

```go
JWT: config.JWTConfig{
    SecretKey:       "your-super-secret-key-here", // Use strong secret
    AccessTokenTTL:  15 * time.Minute,             // Short expiration
    RefreshTokenTTL: 7 * 24 * time.Hour,           // Longer expiration
    Issuer:          "your-app.com",               // Set your domain
    Audience:        "your-app-users",             // Set your audience
}
```

**Security Recommendations:**
- Use a strong, random secret key (at least 32 characters)
- Keep access token expiration short (15-30 minutes)
- Use longer expiration for refresh tokens (7-30 days)
- Set proper issuer and audience claims

### Database Security

```go
Database: config.DatabaseConfig{
    URI:        "mongodb://username:password@localhost:27017",
    Database:   "myapp",
    Collection: "users",
}
```

**Security Recommendations:**
- Use authentication for MongoDB connections
- Use TLS/SSL connections in production
- Restrict network access to MongoDB
- Use dedicated database users with minimal permissions

### Email Security

```go
Email: config.EmailConfig{
    SMTPHost:     "smtp.gmail.com",
    SMTPPort:     587, // Use TLS port
    SMTPUsername: "your-email@gmail.com",
    SMTPPassword: "your-app-password", // Use app-specific password
    FromEmail:    "noreply@yourapp.com",
    FromName:     "Your App",
}
```

**Security Recommendations:**
- Use TLS/SSL for SMTP connections
- Use app-specific passwords for email providers
- Use dedicated email addresses for sending
- Implement SPF, DKIM, and DMARC records

## Best Practices

### 1. Strong Passwords

Enforce strong password policies:

```go
Security: config.SecurityConfig{
    PasswordMinLength: 12,        // Require longer passwords
    PasswordMaxLength: 128,
    // ... other settings
}
```

**Additional Recommendations:**
- Implement password complexity requirements
- Check against common password lists
- Prevent password reuse
- Implement password history

### 2. Rate Limiting

Implement rate limiting for authentication endpoints:

```go
// Example rate limiting middleware
func RateLimitMiddleware(limiter *rate.Limiter) gin.HandlerFunc {
    return func(c *gin.Context) {
        if !limiter.Allow() {
            c.JSON(429, gin.H{"error": "Too many requests"})
            c.Abort()
            return
        }
        c.Next()
    }
}
```

### 3. HTTPS Only

Always use HTTPS in production:

```go
// Redirect HTTP to HTTPS
func HTTPSRedirect() gin.HandlerFunc {
    return func(c *gin.Context) {
        if c.Request.TLS == nil {
            url := "https://" + c.Request.Host + c.Request.URL.String()
            c.Redirect(301, url)
            c.Abort()
            return
        }
        c.Next()
    }
}
```

### 4. Secure Headers

Set security headers:

```go
// Security headers middleware
func SecurityHeaders() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        c.Header("Content-Security-Policy", "default-src 'self'")
        c.Next()
    }
}
```

### 5. Input Validation

Validate all inputs:

```go
// Example validation middleware
func ValidateRegistration(c *gin.Context) {
    var req types.UserRegistration
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "Invalid input"})
        c.Abort()
        return
    }
    
    // Additional validation
    if !isValidEmail(req.Email) {
        c.JSON(400, gin.H{"error": "Invalid email format"})
        c.Abort()
        return
    }
    
    c.Next()
}
```

### 6. Logging and Monitoring

Implement comprehensive logging:

```go
// Security event logging
func LogSecurityEvent(event string, userID string, details map[string]interface{}) {
    log.Printf("SECURITY: %s | User: %s | Details: %+v", event, userID, details)
}

// Usage examples
LogSecurityEvent("login_failed", "", map[string]interface{}{
    "email": "user@example.com",
    "ip":    "192.168.1.1",
})

LogSecurityEvent("password_reset_requested", userID, map[string]interface{}{
    "ip": "192.168.1.1",
})
```

## Common Security Vulnerabilities

### 1. SQL Injection

**Risk**: Low (using MongoDB driver with proper parameterization)
**Mitigation**: The library uses parameterized queries automatically

### 2. XSS (Cross-Site Scripting)

**Risk**: Medium (depends on how you handle user input)
**Mitigation**:
```go
// Sanitize user input
func SanitizeInput(input string) string {
    return html.EscapeString(input)
}
```

### 3. CSRF (Cross-Site Request Forgery)

**Risk**: Medium (depends on your application)
**Mitigation**:
```go
// Implement CSRF protection
func CSRFProtection() gin.HandlerFunc {
    return func(c *gin.Context) {
        if c.Request.Method == "POST" {
            token := c.GetHeader("X-CSRF-Token")
            if !validateCSRFToken(token) {
                c.JSON(403, gin.H{"error": "Invalid CSRF token"})
                c.Abort()
                return
            }
        }
        c.Next()
    }
}
```

### 4. Session Hijacking

**Risk**: Medium (mitigated by JWT tokens)
**Mitigation**:
- Use HTTPS only
- Set secure and httpOnly flags for cookies
- Implement token rotation
- Monitor for suspicious activity

### 5. Brute Force Attacks

**Risk**: High
**Mitigation**:
```go
// Implement account lockout
type LoginAttempt struct {
    Email     string    `json:"email"`
    Attempts  int       `json:"attempts"`
    LockedAt  time.Time `json:"locked_at"`
}

func CheckLoginAttempts(email string) error {
    attempts := getLoginAttempts(email)
    if attempts.Attempts >= 5 && time.Since(attempts.LockedAt) < 15*time.Minute {
        return fmt.Errorf("account temporarily locked")
    }
    return nil
}
```

## Production Security Checklist

### Before Deployment

- [ ] Use strong, unique JWT secret keys
- [ ] Enable HTTPS/TLS for all connections
- [ ] Configure proper CORS settings
- [ ] Set up rate limiting
- [ ] Implement input validation
- [ ] Configure secure headers
- [ ] Set up logging and monitoring
- [ ] Test security measures

### Ongoing Security

- [ ] Regularly rotate JWT secrets
- [ ] Monitor for suspicious activity
- [ ] Keep dependencies updated
- [ ] Review and update security policies
- [ ] Conduct security audits
- [ ] Train developers on security

### Incident Response

- [ ] Have a security incident response plan
- [ ] Monitor for data breaches
- [ ] Implement account recovery procedures
- [ ] Have communication plans ready
- [ ] Document security incidents

## Security Testing

### Automated Testing

```go
func TestPasswordSecurity(t *testing.T) {
    password := "testpassword123"
    hash, err := utils.HashPassword(password)
    require.NoError(t, err)
    
    // Test password verification
    assert.True(t, utils.CheckPassword(password, hash))
    assert.False(t, utils.CheckPassword("wrongpassword", hash))
}

func TestTokenSecurity(t *testing.T) {
    cfg := &config.Config{
        JWT: config.JWTConfig{
            SecretKey: "test-secret-key",
        },
    }
    
    jwtManager := auth.NewJWTManager(cfg)
    user := &types.User{
        ID:    primitive.NewObjectID(),
        Email: "test@example.com",
    }
    
    token, err := jwtManager.GenerateAccessToken(user)
    require.NoError(t, err)
    
    claims, err := jwtManager.ValidateToken(token)
    require.NoError(t, err)
    assert.Equal(t, user.Email, claims.Email)
}
```

### Penetration Testing

Consider conducting penetration testing to identify vulnerabilities:

1. **Authentication Testing**
   - Test brute force protection
   - Test account lockout mechanisms
   - Test password reset functionality

2. **Authorization Testing**
   - Test token validation
   - Test access control
   - Test privilege escalation

3. **Input Validation Testing**
   - Test SQL injection attempts
   - Test XSS payloads
   - Test CSRF attacks

## Compliance

### GDPR Compliance

- Implement data minimization
- Provide data portability
- Implement right to be forgotten
- Maintain data processing records

### SOC 2 Compliance

- Implement access controls
- Maintain audit logs
- Conduct regular security assessments
- Document security policies

### PCI DSS Compliance

- Encrypt sensitive data
- Implement access controls
- Maintain audit trails
- Regular security testing

## Security Resources

### Documentation

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Go Security Best Practices](https://golang.org/doc/security)
- [JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)

### Tools

- [GoSec](https://github.com/securecodewarrior/gosec) - Static analysis
- [GolangCI-Lint](https://golangci-lint.run/) - Linting with security rules
- [Snyk](https://snyk.io/) - Dependency vulnerability scanning

### Monitoring

- [Prometheus](https://prometheus.io/) - Metrics collection
- [Grafana](https://grafana.com/) - Monitoring dashboards
- [ELK Stack](https://www.elastic.co/elk-stack) - Log analysis
