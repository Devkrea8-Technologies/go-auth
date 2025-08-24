package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/go-auth/config"
	"github.com/go-auth/types"
)

// AppleService handles Apple Sign-In operations
type AppleService struct {
	config *config.Config
}

// NewAppleService creates a new Apple Sign-In service
func NewAppleService(cfg *config.Config) *AppleService {
	return &AppleService{
		config: cfg,
	}
}

// AppleTokenResponse represents Apple OAuth token response
type AppleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
}

// AppleIDTokenClaims represents Apple ID token claims
type AppleIDTokenClaims struct {
	Issuer         string `json:"iss"`
	Subject        string `json:"sub"`
	Audience       string `json:"aud"`
	ExpiresAt      int64  `json:"exp"`
	IssuedAt       int64  `json:"iat"`
	Email          string `json:"email,omitempty"`
	EmailVerified  string `json:"email_verified,omitempty"`
	IsPrivateEmail string `json:"is_private_email,omitempty"`
	RealUserStatus int    `json:"real_user_status,omitempty"`
	FirstName      string `json:"first_name,omitempty"`
	LastName       string `json:"last_name,omitempty"`
	jwt.RegisteredClaims
}

// AppleUserInfo represents Apple user information
type AppleUserInfo struct {
	ID             string `json:"sub"`
	Email          string `json:"email,omitempty"`
	EmailVerified  string `json:"email_verified,omitempty"`
	IsPrivateEmail string `json:"is_private_email,omitempty"`
	RealUserStatus int    `json:"real_user_status,omitempty"`
	FirstName      string `json:"first_name,omitempty"`
	LastName       string `json:"last_name,omitempty"`
}

// ApplePublicKey represents Apple's public key structure
type ApplePublicKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// AppleKeysResponse represents Apple's public keys response
type AppleKeysResponse struct {
	Keys []ApplePublicKey `json:"keys"`
}

// parseRSAPublicKey parses RSA public key from Apple's JWK format
func parseRSAPublicKey(key ApplePublicKey) (*rsa.PublicKey, error) {
	// Decode the modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode the exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert to big integers
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	// Create RSA public key
	publicKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	return publicKey, nil
}

// generateClientSecret generates a JWT client secret for Apple Sign-In
func (a *AppleService) generateClientSecret() (string, error) {
	// Parse the private key
	privateKey, err := x509.ParsePKCS8PrivateKey([]byte(a.config.Apple.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Type assert to ECDSA private key
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not ECDSA")
	}

	// Create JWT claims
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": a.config.Apple.TeamID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), // Token expires in 5 minutes
		"aud": "https://appleid.apple.com",
		"sub": a.config.Apple.ClientID,
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = a.config.Apple.KeyID

	// Sign the token
	tokenString, err := token.SignedString(ecdsaPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return tokenString, nil
}

// GetAuthURL generates Apple Sign-In authorization URL
func (a *AppleService) GetAuthURL(state string) string {
	if !a.config.Apple.Enabled {
		return ""
	}

	params := url.Values{}
	params.Add("client_id", a.config.Apple.ClientID)
	params.Add("redirect_uri", a.config.Apple.RedirectURL)
	params.Add("scope", "name email")
	params.Add("response_type", "code")
	params.Add("response_mode", "form_post")
	if state != "" {
		params.Add("state", state)
	}

	return fmt.Sprintf("https://appleid.apple.com/auth/authorize?%s", params.Encode())
}

// ExchangeCodeForToken exchanges authorization code for access token
func (a *AppleService) ExchangeCodeForToken(ctx context.Context, code string) (*AppleTokenResponse, error) {
	if !a.config.Apple.Enabled {
		return nil, fmt.Errorf("Apple Sign-In is not enabled")
	}

	// Generate client secret
	clientSecret, err := a.generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	data := url.Values{}
	data.Set("client_id", a.config.Apple.ClientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", a.config.Apple.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://appleid.apple.com/auth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Apple OAuth error: %s", resp.Status)
	}

	var tokenResp AppleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// VerifyIDToken verifies the Apple ID token
func (a *AppleService) VerifyIDToken(idToken string) (*AppleIDTokenClaims, error) {
	// Parse the token without verification first to get the key ID
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, &AppleIDTokenClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
	}

	// Get the key ID from the token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid key ID in token header")
	}

	// Fetch Apple's public keys
	keysURL := "https://appleid.apple.com/auth/keys"
	resp, err := http.Get(keysURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Apple public keys: %w", err)
	}
	defer resp.Body.Close()

	var keysResponse AppleKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&keysResponse); err != nil {
		return nil, fmt.Errorf("failed to decode keys response: %w", err)
	}

	// Find the matching key and parse it
	var publicKey interface{}
	for _, key := range keysResponse.Keys {
		if key.Kid == kid {
			if key.Kty == "RSA" {
				rsaKey, err := parseRSAPublicKey(key)
				if err != nil {
					return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
				}
				publicKey = rsaKey
				break
			} else {
				return nil, fmt.Errorf("unsupported key type: %s", key.Kty)
			}
		}
	}

	if publicKey == nil {
		return nil, fmt.Errorf("no matching public key found for kid: %s", kid)
	}

	// Parse and verify the token
	parsedToken, err := jwt.ParseWithClaims(idToken, &AppleIDTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	claims, ok := parsedToken.Claims.(*AppleIDTokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Verify the issuer
	if claims.Issuer != "https://appleid.apple.com" {
		return nil, fmt.Errorf("invalid issuer: %s", claims.Issuer)
	}

	// Verify the audience
	if claims.Audience != a.config.Apple.ClientID {
		return nil, fmt.Errorf("invalid audience: %s", claims.Audience)
	}

	// Verify the token is not expired
	if claims.ExpiresAt < time.Now().Unix() {
		return nil, fmt.Errorf("token has expired")
	}

	return claims, nil
}

// AuthenticateWithApple authenticates a user with Apple Sign-In
func (a *AppleService) AuthenticateWithApple(ctx context.Context, code string) (*types.User, error) {
	if !a.config.Apple.Enabled {
		return nil, fmt.Errorf("Apple Sign-In is not enabled")
	}

	// Exchange code for token
	tokenResp, err := a.ExchangeCodeForToken(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Verify ID token
	claims, err := a.VerifyIDToken(tokenResp.IDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Convert to our User type
	user := &types.User{
		AppleID:         claims.Subject,
		Email:           claims.Email,
		IsEmailVerified: claims.EmailVerified == "true",
		IsActive:        true,
		AppleProfile: &types.AppleProfile{
			ID:             claims.Subject,
			Email:          claims.Email,
			EmailVerified:  claims.EmailVerified,
			IsPrivateEmail: claims.IsPrivateEmail,
			RealUserStatus: claims.RealUserStatus,
			FirstName:      claims.FirstName,
			LastName:       claims.LastName,
		},
	}

	return user, nil
}
