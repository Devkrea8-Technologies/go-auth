package email

import (
	"bytes"
	"fmt"
	"strings"
	"html/template"

	"gopkg.in/gomail.v2"

	"github.com/go-auth/config"
)

// EmailService handles email operations
type EmailService struct {
	config *config.Config
	dialer *gomail.Dialer
}

// NewEmailService creates a new email service
func NewEmailService(cfg *config.Config) *EmailService {
	dialer := gomail.NewDialer(
		cfg.Email.SMTPHost,
		cfg.Email.SMTPPort,
		cfg.Email.SMTPUsername,
		cfg.Email.SMTPPassword,
	)

	return &EmailService{
		config: cfg,
		dialer: dialer,
	}
}

// EmailData represents data for email templates
type EmailData struct {
	UserEmail string
	UserName  string
	Token     string
	BaseURL   string
}

// SendEmailVerification sends an email verification email
func (e *EmailService) SendEmailVerification(userEmail, userName, token, baseURL string) error {
	data := EmailData{
		UserEmail: userEmail,
		UserName:  userName,
		Token:     token,
		BaseURL:   baseURL,
	}

	subject, body, err := e.renderEmailTemplate(e.config.Email.EmailVerificationTemplate, data)
	if err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}

	return e.sendEmail(userEmail, subject, body)
}

// SendPasswordReset sends a password reset email
func (e *EmailService) SendPasswordReset(userEmail, userName, token, baseURL string) error {
	data := EmailData{
		UserEmail: userEmail,
		UserName:  userName,
		Token:     token,
		BaseURL:   baseURL,
	}

	subject, body, err := e.renderEmailTemplate(e.config.Email.PasswordResetTemplate, data)
	if err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}

	return e.sendEmail(userEmail, subject, body)
}

// renderEmailTemplate renders an email template with data
func (e *EmailService) renderEmailTemplate(emailTemplate config.EmailTemplate, data EmailData) (string, string, error) {
	// Render subject template
	subjectTmpl, err := template.New("subject").Parse(emailTemplate.Subject)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse subject template: %w", err)
	}

	var subjectBuf bytes.Buffer
	if err := subjectTmpl.Execute(&subjectBuf, data); err != nil {
		return "", "", fmt.Errorf("failed to execute subject template: %w", err)
	}

	// Render body template
	bodyTmpl, err := template.New("body").Parse(emailTemplate.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse body template: %w", err)
	}

	var bodyBuf bytes.Buffer
	if err := bodyTmpl.Execute(&bodyBuf, data); err != nil {
		return "", "", fmt.Errorf("failed to execute body template: %w", err)
	}

	return subjectBuf.String(), bodyBuf.String(), nil
}

// sendEmail sends an email using the configured SMTP settings
func (e *EmailService) sendEmail(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", fmt.Sprintf("%s <%s>", e.config.Email.FromName, e.config.Email.FromEmail))
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	if err := e.dialer.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// ValidateEmailTemplate validates an email template
func (e *EmailService) ValidateEmailTemplate(template config.EmailTemplate) error {
	if strings.TrimSpace(template.Subject) == "" {
		return fmt.Errorf("email template subject cannot be empty")
	}

	if strings.TrimSpace(template.Body) == "" {
		return fmt.Errorf("email template body cannot be empty")
	}

	// Test template parsing
	testData := EmailData{
		UserEmail: "test@example.com",
		UserName:  "Test User",
		Token:     "test-token",
		BaseURL:   "https://example.com",
	}

	_, _, err := e.renderEmailTemplate(template, testData)
	if err != nil {
		return fmt.Errorf("invalid email template: %w", err)
	}

	return nil
}
