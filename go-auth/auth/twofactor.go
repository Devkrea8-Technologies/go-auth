package auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/pquerna/otp/totp"

	"github.com/Devkrea8-Technologies/go-auth/config"
	"github.com/Devkrea8-Technologies/go-auth/types"
)

// TwoFactorService handles 2FA operations
type TwoFactorService struct {
	config *config.Config
}

// NewTwoFactorService creates a new 2FA service
func NewTwoFactorService(cfg *config.Config) *TwoFactorService {
	return &TwoFactorService{
		config: cfg,
	}
}

// GenerateSecret generates a new TOTP secret
func (t *TwoFactorService) GenerateSecret() (string, error) {
	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	if err != nil {
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}
	return base32.StdEncoding.EncodeToString(secret), nil
}

// GenerateQRCodeURL generates a QR code URL for the TOTP secret
func (t *TwoFactorService) GenerateQRCodeURL(secret, email, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		issuer, email, secret, issuer)
}

// GenerateBackupCodes generates backup codes for account recovery
func (t *TwoFactorService) GenerateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		codeBytes := make([]byte, 8)
		_, err := rand.Read(codeBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup codes: %w", err)
		}
		code := base32.StdEncoding.EncodeToString(codeBytes)
		codes[i] = strings.ToUpper(code[:8])
	}
	return codes, nil
}

// ValidateTOTP validates a TOTP code
func (t *TwoFactorService) ValidateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

// ValidateBackupCode validates a backup code
func (t *TwoFactorService) ValidateBackupCode(backupCodes []string, code string) (bool, []string) {
	code = strings.ToUpper(strings.TrimSpace(code))

	for i, backupCode := range backupCodes {
		if backupCode == code {
			newBackupCodes := make([]string, len(backupCodes)-1)
			copy(newBackupCodes, backupCodes[:i])
			copy(newBackupCodes[i:], backupCodes[i+1:])
			return true, newBackupCodes
		}
	}

	return false, backupCodes
}

// Setup2FA sets up 2FA for a user
func (t *TwoFactorService) Setup2FA(user *types.User, issuer string) (*types.TwoFactorSetupResponse, error) {
	secret, err := t.GenerateSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	backupCodes, err := t.GenerateBackupCodes(10)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	qrCodeURL := t.GenerateQRCodeURL(secret, user.Email, issuer)

	return &types.TwoFactorSetupResponse{
		Secret:      secret,
		QRCodeURL:   qrCodeURL,
		BackupCodes: backupCodes,
	}, nil
}

// Verify2FA verifies a 2FA code (TOTP or backup code)
func (t *TwoFactorService) Verify2FA(user *types.User, code string) (bool, error) {
	if !user.TwoFactorEnabled {
		return false, fmt.Errorf("2FA is not enabled for this user")
	}

	if t.ValidateTOTP(user.TwoFactorSecret, code) {
		return true, nil
	}

	if len(user.TwoFactorBackupCodes) > 0 {
		isValid, newBackupCodes := t.ValidateBackupCode(user.TwoFactorBackupCodes, code)
		if isValid {
			user.TwoFactorBackupCodes = newBackupCodes
			return true, nil
		}
	}

	return false, fmt.Errorf("invalid 2FA code")
}

// Enable2FA enables 2FA for a user
func (t *TwoFactorService) Enable2FA(user *types.User, secret string, backupCodes []string) {
	user.TwoFactorEnabled = true
	user.TwoFactorSecret = secret
	user.TwoFactorBackupCodes = backupCodes
}

// Disable2FA disables 2FA for a user
func (t *TwoFactorService) Disable2FA(user *types.User) {
	user.TwoFactorEnabled = false
	user.TwoFactorSecret = ""
	user.TwoFactorBackupCodes = nil
}
