# Email Templates

The Go Auth library supports customizable email templates for email verification and password reset functionality. This document covers template configuration, variables, and best practices.

## Template Configuration

Email templates are configured in the `EmailConfig` section of your configuration:

```go
Email: config.EmailConfig{
    // SMTP settings...
    EmailVerificationTemplate: config.EmailTemplate{
        Subject: "Verify your email address",
        Body:    "Click here to verify: {{.BaseURL}}/verify?token={{.Token}}",
    },
    PasswordResetTemplate: config.EmailTemplate{
        Subject: "Reset your password",
        Body:    "Click here to reset: {{.BaseURL}}/reset?token={{.Token}}",
    },
}
```

## Available Variables

Both email verification and password reset templates support the following variables:

### Template Variables

- `{{.UserEmail}}` - User's email address
- `{{.UserName}}` - User's first name
- `{{.Token}}` - Verification or reset token
- `{{.BaseURL}}` - Your application's base URL

### Variable Usage Examples

```go
// Email verification template
EmailVerificationTemplate: config.EmailTemplate{
    Subject: "Welcome to {{.BaseURL}} - Verify your email",
    Body: `
        <h2>Welcome to Our App!</h2>
        <p>Hi {{.UserName}},</p>
        <p>Thank you for registering with {{.BaseURL}}.</p>
        <p>Please verify your email address by clicking the link below:</p>
        <a href="{{.BaseURL}}/verify?token={{.Token}}">Verify Email Address</a>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't create an account, please ignore this email.</p>
    `,
}

// Password reset template
PasswordResetTemplate: config.EmailTemplate{
    Subject: "Password Reset Request - {{.BaseURL}}",
    Body: `
        <h2>Password Reset Request</h2>
        <p>Hi {{.UserName}},</p>
        <p>You requested a password reset for your account at {{.BaseURL}}.</p>
        <p>Click the link below to reset your password:</p>
        <a href="{{.BaseURL}}/reset?token={{.Token}}">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this password reset, please ignore this email.</p>
        <p>Your password will remain unchanged.</p>
    `,
}
```

## HTML Email Templates

For better user experience, you can create rich HTML email templates:

```go
EmailVerificationTemplate: config.EmailTemplate{
    Subject: "Verify your email address",
    Body: `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Email Verification</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #007bff; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background: #f8f9fa; }
                .button { display: inline-block; padding: 12px 24px; background: #007bff; 
                         color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome to Our App!</h1>
                </div>
                <div class="content">
                    <h2>Hi {{.UserName}},</h2>
                    <p>Thank you for registering with us. To complete your registration, 
                       please verify your email address by clicking the button below:</p>
                    
                    <a href="{{.BaseURL}}/verify?token={{.Token}}" class="button">
                        Verify Email Address
                    </a>
                    
                    <p>This verification link will expire in 24 hours.</p>
                    <p>If you didn't create an account with us, please ignore this email.</p>
                </div>
                <div class="footer">
                    <p>This email was sent to {{.UserEmail}}</p>
                    <p>&copy; 2024 Our App. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
    `,
}
```

## Plain Text Templates

For better compatibility, you can also provide plain text versions:

```go
EmailVerificationTemplate: config.EmailTemplate{
    Subject: "Verify your email address",
    Body: `
        Welcome to Our App!
        
        Hi {{.UserName}},
        
        Thank you for registering with us. To complete your registration, 
        please verify your email address by visiting the following link:
        
        {{.BaseURL}}/verify?token={{.Token}}
        
        This verification link will expire in 24 hours.
        
        If you didn't create an account with us, please ignore this email.
        
        Best regards,
        The Our App Team
    `,
}
```

## Template Validation

The library validates email templates to ensure they are properly formatted:

```go
// Validate email template
err := emailService.ValidateEmailTemplate(template)
if err != nil {
    log.Printf("Invalid email template: %v", err)
}
```

## Best Practices

### 1. Clear Subject Lines

Use descriptive and clear subject lines:

```go
// Good
Subject: "Verify your email address - Our App"

// Avoid
Subject: "Action required"
```

### 2. Include Your Brand

Make sure your emails are clearly branded:

```go
Body: `
    <h1>Welcome to {{.BaseURL}}</h1>
    <p>Hi {{.UserName}},</p>
    <p>Thank you for joining Our App!</p>
    // ... rest of template
`
```

### 3. Clear Call-to-Action

Make the action button or link prominent:

```go
Body: `
    <p>Please verify your email address:</p>
    <a href="{{.BaseURL}}/verify?token={{.Token}}" 
       style="background: #007bff; color: white; padding: 12px 24px; 
              text-decoration: none; border-radius: 5px;">
        Verify Email Address
    </a>
`
```

### 4. Include Expiration Information

Always inform users about token expiration:

```go
Body: `
    <p>This verification link will expire in 24 hours.</p>
    <p>If the link expires, you can request a new one from your account settings.</p>
`
```

### 5. Security Information

Include security-related information:

```go
Body: `
    <p>If you didn't request this email, please ignore it.</p>
    <p>Your account security is important to us.</p>
`
```

### 6. Responsive Design

Use responsive CSS for mobile compatibility:

```go
Body: `
    <style>
        @media only screen and (max-width: 600px) {
            .container { width: 100% !important; }
            .button { display: block !important; width: 100% !important; }
        }
    </style>
`
```

## Template Examples

### Complete Email Verification Template

```go
EmailVerificationTemplate: config.EmailTemplate{
    Subject: "Welcome to Our App - Verify your email address",
    Body: `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Email Verification</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
                .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                         color: white; padding: 30px; text-align: center; }
                .content { padding: 30px; }
                .button { display: inline-block; padding: 15px 30px; background: #667eea; 
                         color: white; text-decoration: none; border-radius: 8px; 
                         font-weight: bold; margin: 20px 0; }
                .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; 
                         background: #f8f9fa; }
                .warning { background: #fff3cd; border: 1px solid #ffeaa7; 
                          padding: 15px; border-radius: 5px; margin: 20px 0; }
                @media only screen and (max-width: 600px) {
                    .container { width: 100% !important; }
                    .button { display: block !important; width: 100% !important; text-align: center; }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome to Our App!</h1>
                    <p>Complete your registration</p>
                </div>
                <div class="content">
                    <h2>Hi {{.UserName}},</h2>
                    <p>Thank you for registering with Our App! We're excited to have you on board.</p>
                    <p>To complete your registration and start using our services, please verify your email address:</p>
                    
                    <div style="text-align: center;">
                        <a href="{{.BaseURL}}/verify?token={{.Token}}" class="button">
                            Verify Email Address
                        </a>
                    </div>
                    
                    <div class="warning">
                        <strong>Important:</strong> This verification link will expire in 24 hours.
                        If you don't verify your email within this time, you'll need to request a new verification link.
                    </div>
                    
                    <p>If the button above doesn't work, you can copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; color: #667eea;">
                        {{.BaseURL}}/verify?token={{.Token}}
                    </p>
                    
                    <p>If you didn't create an account with Our App, please ignore this email.</p>
                </div>
                <div class="footer">
                    <p>This email was sent to {{.UserEmail}}</p>
                    <p>Our App | 123 Main St, City, State 12345</p>
                    <p>&copy; 2024 Our App. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
    `,
}
```

### Complete Password Reset Template

```go
PasswordResetTemplate: config.EmailTemplate{
    Subject: "Password Reset Request - Our App",
    Body: `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Reset</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
                .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
                .header { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); 
                         color: white; padding: 30px; text-align: center; }
                .content { padding: 30px; }
                .button { display: inline-block; padding: 15px 30px; background: #ff6b6b; 
                         color: white; text-decoration: none; border-radius: 8px; 
                         font-weight: bold; margin: 20px 0; }
                .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; 
                         background: #f8f9fa; }
                .warning { background: #fff3cd; border: 1px solid #ffeaa7; 
                          padding: 15px; border-radius: 5px; margin: 20px 0; }
                .security { background: #d1ecf1; border: 1px solid #bee5eb; 
                           padding: 15px; border-radius: 5px; margin: 20px 0; }
                @media only screen and (max-width: 600px) {
                    .container { width: 100% !important; }
                    .button { display: block !important; width: 100% !important; text-align: center; }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Password Reset Request</h1>
                    <p>Secure your account</p>
                </div>
                <div class="content">
                    <h2>Hi {{.UserName}},</h2>
                    <p>We received a request to reset the password for your Our App account.</p>
                    <p>Click the button below to reset your password:</p>
                    
                    <div style="text-align: center;">
                        <a href="{{.BaseURL}}/reset?token={{.Token}}" class="button">
                            Reset Password
                        </a>
                    </div>
                    
                    <div class="warning">
                        <strong>Important:</strong> This password reset link will expire in 1 hour.
                        If you don't reset your password within this time, you'll need to request a new reset link.
                    </div>
                    
                    <p>If the button above doesn't work, you can copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; color: #ff6b6b;">
                        {{.BaseURL}}/reset?token={{.Token}}
                    </p>
                    
                    <div class="security">
                        <strong>Security Notice:</strong> If you didn't request this password reset, 
                        please ignore this email. Your password will remain unchanged, and no action is required.
                    </div>
                </div>
                <div class="footer">
                    <p>This email was sent to {{.UserEmail}}</p>
                    <p>Our App | 123 Main St, City, State 12345</p>
                    <p>&copy; 2024 Our App. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
    `,
}
```

## Testing Templates

You can test your email templates before using them in production:

```go
// Test template rendering
testData := email.EmailData{
    UserEmail: "test@example.com",
    UserName:  "Test User",
    Token:     "test-token-123",
    BaseURL:   "https://yourapp.com",
}

subject, body, err := emailService.renderEmailTemplate(template, testData)
if err != nil {
    log.Printf("Template rendering failed: %v", err)
} else {
    fmt.Printf("Subject: %s\n", subject)
    fmt.Printf("Body: %s\n", body)
}
```

## Internationalization

For multi-language support, you can create different templates for different languages:

```go
// English template
EmailVerificationTemplateEN: config.EmailTemplate{
    Subject: "Verify your email address",
    Body:    "Hi {{.UserName}}, please verify your email...",
}

// Spanish template
EmailVerificationTemplateES: config.EmailTemplate{
    Subject: "Verifica tu dirección de correo electrónico",
    Body:    "Hola {{.UserName}}, por favor verifica tu correo...",
}
```

## Troubleshooting

### Common Issues

1. **Template Variables Not Replaced**
   - Ensure variable names match exactly (case-sensitive)
   - Check for extra spaces in variable names

2. **HTML Not Rendering**
   - Some email clients strip CSS
   - Use inline styles for better compatibility
   - Test with multiple email clients

3. **Links Not Working**
   - Ensure `{{.BaseURL}}` is properly set
   - Check that the token is being passed correctly
   - Verify URL encoding

### Debug Mode

Enable debug logging to troubleshoot template issues:

```go
// Add logging to see template rendering
log.Printf("Rendering template with data: %+v", data)
subject, body, err := emailService.renderEmailTemplate(template, data)
if err != nil {
    log.Printf("Template rendering error: %v", err)
}
```
