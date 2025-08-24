package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/go-auth/config"
	"github.com/go-auth/types"

	_ "github.com/lib/pq"
)

// PostgreSQL represents PostgreSQL database connection and operations
type PostgreSQL struct {
	db     *sql.DB
	config *config.Config
}

// NewPostgreSQL creates a new PostgreSQL connection
func NewPostgreSQL(cfg *config.Config) (*PostgreSQL, error) {
	// Build connection string
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Username,
		cfg.Database.Password,
		cfg.Database.Database,
		cfg.Database.SSLMode,
	)

	// Open database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	db.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	pg := &PostgreSQL{
		db:     db,
		config: cfg,
	}

	// Create tables and indexes
	if err := pg.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return pg, nil
}

// createTables creates the necessary tables and indexes
func (p *PostgreSQL) createTables() error {
	// Create users table
	createUsersTable := `
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password VARCHAR(255),
			first_name VARCHAR(255) NOT NULL,
			last_name VARCHAR(255) NOT NULL,
			is_email_verified BOOLEAN DEFAULT FALSE,
			is_active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_login_at TIMESTAMP,
			google_id VARCHAR(255) UNIQUE,
			google_profile JSONB,
			tiktok_id VARCHAR(255) UNIQUE,
			tiktok_profile JSONB,
			custom_fields JSONB
		);
	`

	// Create email verification table
	createEmailVerificationTable := `
		CREATE TABLE IF NOT EXISTS email_verifications (
			id SERIAL PRIMARY KEY,
			user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
			token VARCHAR(255) UNIQUE NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			verified_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`

	// Create password reset table
	createPasswordResetTable := `
		CREATE TABLE IF NOT EXISTS password_resets (
			id SERIAL PRIMARY KEY,
			user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
			token VARCHAR(255) UNIQUE NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			used_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`

	// Execute table creation
	if _, err := p.db.Exec(createUsersTable); err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	if _, err := p.db.Exec(createEmailVerificationTable); err != nil {
		return fmt.Errorf("failed to create email verification table: %w", err)
	}

	if _, err := p.db.Exec(createPasswordResetTable); err != nil {
		return fmt.Errorf("failed to create password reset table: %w", err)
	}

	// Create indexes
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
		"CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);",
		"CREATE INDEX IF NOT EXISTS idx_users_tiktok_id ON users(tiktok_id);",
		"CREATE INDEX IF NOT EXISTS idx_email_verifications_token ON email_verifications(token);",
		"CREATE INDEX IF NOT EXISTS idx_email_verifications_user_id ON email_verifications(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token);",
		"CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);",
	}

	for _, index := range indexes {
		if _, err := p.db.Exec(index); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// CreateUser creates a new user in the database
func (p *PostgreSQL) CreateUser(ctx context.Context, user *types.User) error {
	query := `
		INSERT INTO users (email, password, first_name, last_name, is_email_verified, is_active, google_id, google_profile, tiktok_id, tiktok_profile, custom_fields)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at, updated_at
	`

	var id int
	var createdAt, updatedAt time.Time
	err := p.db.QueryRowContext(ctx, query,
		user.Email,
		user.Password,
		user.FirstName,
		user.LastName,
		user.IsEmailVerified,
		user.IsActive,
		user.GoogleID,
		user.GoogleProfile,
		user.TikTokID,
		user.TikTokProfile,
		user.CustomFields,
	).Scan(&id, &createdAt, &updatedAt)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Set the ID and timestamps
	user.ID = int64(id)
	user.CreatedAt = createdAt
	user.UpdatedAt = updatedAt

	// If there's email verification data, create it
	if user.EmailVerification != nil {
		if err := p.createEmailVerification(ctx, int64(id), user.EmailVerification); err != nil {
			return fmt.Errorf("failed to create email verification: %w", err)
		}
	}

	return nil
}

// GetUserByEmail retrieves a user by email
func (p *PostgreSQL) GetUserByEmail(ctx context.Context, email string) (*types.User, error) {
	query := `
		SELECT id, email, password, first_name, last_name, is_email_verified, is_active, 
		       created_at, updated_at, last_login_at, google_id, google_profile, tiktok_id, tiktok_profile, custom_fields
		FROM users 
		WHERE email = $1
	`

	var user types.User
	var lastLoginAt sql.NullTime
	err := p.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.IsEmailVerified,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLoginAt,
		&user.GoogleID,
		&user.GoogleProfile,
		&user.TikTokID,
		&user.TikTokProfile,
		&user.CustomFields,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}

	// Load email verification data
	if userID, ok := user.ID.(int64); ok {
		if err := p.loadEmailVerification(ctx, userID, &user); err != nil {
			return nil, fmt.Errorf("failed to load email verification: %w", err)
		}
	}

	return &user, nil
}

// GetUserByID retrieves a user by ID
func (p *PostgreSQL) GetUserByID(ctx context.Context, userID interface{}) (*types.User, error) {
	var id int64
	switch v := userID.(type) {
	case int64:
		id = v
	case int:
		id = int64(v)
	case string:
		// Try to parse as int64
		var err error
		_, err = fmt.Sscanf(v, "%d", &id)
		if err != nil {
			return nil, fmt.Errorf("invalid ID format: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported ID type: %T", userID)
	}
	query := `
		SELECT id, email, password, first_name, last_name, is_email_verified, is_active, 
		       created_at, updated_at, last_login_at, google_id, google_profile, tiktok_id, tiktok_profile, custom_fields
		FROM users 
		WHERE id = $1
	`

	var user types.User
	var lastLoginAt sql.NullTime
	err := p.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.IsEmailVerified,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLoginAt,
		&user.GoogleID,
		&user.GoogleProfile,
		&user.TikTokID,
		&user.TikTokProfile,
		&user.CustomFields,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}

	// Load email verification data
	if userID, ok := user.ID.(int64); ok {
		if err := p.loadEmailVerification(ctx, userID, &user); err != nil {
			return nil, fmt.Errorf("failed to load email verification: %w", err)
		}
	}

	return &user, nil
}

// GetUserByEmailVerificationToken retrieves a user by email verification token
func (p *PostgreSQL) GetUserByEmailVerificationToken(ctx context.Context, token string) (*types.User, error) {
	query := `
		SELECT u.id, u.email, u.password, u.first_name, u.last_name, u.is_email_verified, u.is_active, 
		       u.created_at, u.updated_at, u.last_login_at, u.custom_fields,
		       ev.token, ev.expires_at, ev.verified_at
		FROM users u
		JOIN email_verifications ev ON u.id = ev.user_id
		WHERE ev.token = $1
	`

	var user types.User
	var lastLoginAt sql.NullTime
	var evToken string
	var evExpiresAt time.Time
	var evVerifiedAt sql.NullTime

	err := p.db.QueryRowContext(ctx, query, token).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.IsEmailVerified,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLoginAt,
		&user.CustomFields,
		&evToken,
		&evExpiresAt,
		&evVerifiedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email verification token: %w", err)
	}

	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}

	// Set email verification data
	user.EmailVerification = &types.EmailVerification{
		Token:     evToken,
		ExpiresAt: evExpiresAt,
	}
	if evVerifiedAt.Valid {
		user.EmailVerification.VerifiedAt = &evVerifiedAt.Time
	}

	return &user, nil
}

// GetUserByPasswordResetToken retrieves a user by password reset token
func (p *PostgreSQL) GetUserByPasswordResetToken(ctx context.Context, token string) (*types.User, error) {
	query := `
		SELECT u.id, u.email, u.password, u.first_name, u.last_name, u.is_email_verified, u.is_active, 
		       u.created_at, u.updated_at, u.last_login_at, u.custom_fields,
		       pr.token, pr.expires_at, pr.used_at
		FROM users u
		JOIN password_resets pr ON u.id = pr.user_id
		WHERE pr.token = $1
	`

	var user types.User
	var lastLoginAt sql.NullTime
	var prToken string
	var prExpiresAt time.Time
	var prUsedAt sql.NullTime

	err := p.db.QueryRowContext(ctx, query, token).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.IsEmailVerified,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLoginAt,
		&user.CustomFields,
		&prToken,
		&prExpiresAt,
		&prUsedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by password reset token: %w", err)
	}

	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}

	// Set password reset data
	user.PasswordReset = &types.PasswordReset{
		Token:     prToken,
		ExpiresAt: prExpiresAt,
	}
	if prUsedAt.Valid {
		user.PasswordReset.UsedAt = &prUsedAt.Time
	}

	return &user, nil
}

// UpdateUser updates a user in the database
func (p *PostgreSQL) UpdateUser(ctx context.Context, user *types.User) error {
	query := `
		UPDATE users 
		SET email = $1, password = $2, first_name = $3, last_name = $4, 
		    is_email_verified = $5, is_active = $6, updated_at = CURRENT_TIMESTAMP,
		    last_login_at = $7, google_id = $8, google_profile = $9, tiktok_id = $10, tiktok_profile = $11, custom_fields = $12
		WHERE id = $13
	`

	_, err := p.db.ExecContext(ctx, query,
		user.Email,
		user.Password,
		user.FirstName,
		user.LastName,
		user.IsEmailVerified,
		user.IsActive,
		user.LastLoginAt,
		user.GoogleID,
		user.GoogleProfile,
		user.TikTokID,
		user.TikTokProfile,
		user.CustomFields,
		user.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// UpdateUserPassword updates user password
func (p *PostgreSQL) UpdateUserPassword(ctx context.Context, userID interface{}, password string) error {
	var id int64
	switch v := userID.(type) {
	case int64:
		id = v
	case int:
		id = int64(v)
	case string:
		// Try to parse as int64
		var err error
		_, err = fmt.Sscanf(v, "%d", &id)
		if err != nil {
			return fmt.Errorf("invalid ID format: %w", err)
		}
	default:
		return fmt.Errorf("unsupported ID type: %T", userID)
	}
	// Update password
	query := `
		UPDATE users 
		SET password = $1, updated_at = CURRENT_TIMESTAMP
		WHERE id = $2
	`

	_, err := p.db.ExecContext(ctx, query, password, id)
	if err != nil {
		return fmt.Errorf("failed to update user password: %w", err)
	}

	// Delete password reset tokens
	deleteQuery := `DELETE FROM password_resets WHERE user_id = $1`
	_, err = p.db.ExecContext(ctx, deleteQuery, id)
	if err != nil {
		return fmt.Errorf("failed to delete password reset tokens: %w", err)
	}

	return nil
}

// UpdateEmailVerification updates email verification status
func (p *PostgreSQL) UpdateEmailVerification(ctx context.Context, userID interface{}, verified bool) error {
	var id int64
	switch v := userID.(type) {
	case int64:
		id = v
	case int:
		id = int64(v)
	case string:
		// Try to parse as int64
		var err error
		_, err = fmt.Sscanf(v, "%d", &id)
		if err != nil {
			return fmt.Errorf("invalid ID format: %w", err)
		}
	default:
		return fmt.Errorf("unsupported ID type: %T", userID)
	}
	// Update user email verification status
	userQuery := `
		UPDATE users 
		SET is_email_verified = $1, updated_at = CURRENT_TIMESTAMP
		WHERE id = $2
	`

	_, err := p.db.ExecContext(ctx, userQuery, verified, id)
	if err != nil {
		return fmt.Errorf("failed to update email verification status: %w", err)
	}

	// If verified, update the verification record
	if verified {
		verificationQuery := `
			UPDATE email_verifications 
			SET verified_at = CURRENT_TIMESTAMP
			WHERE user_id = $1 AND verified_at IS NULL
		`

		_, err = p.db.ExecContext(ctx, verificationQuery, id)
		if err != nil {
			return fmt.Errorf("failed to update email verification record: %w", err)
		}
	}

	return nil
}

// UpdateLastLogin updates user's last login time
func (p *PostgreSQL) UpdateLastLogin(ctx context.Context, userID interface{}) error {
	var id int64
	switch v := userID.(type) {
	case int64:
		id = v
	case int:
		id = int64(v)
	case string:
		// Try to parse as int64
		var err error
		_, err = fmt.Sscanf(v, "%d", &id)
		if err != nil {
			return fmt.Errorf("invalid ID format: %w", err)
		}
	default:
		return fmt.Errorf("unsupported ID type: %T", userID)
	}
	query := `
		UPDATE users 
		SET last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`

	_, err := p.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// DeleteUser deletes a user from the database
func (p *PostgreSQL) DeleteUser(ctx context.Context, userID interface{}) error {
	var id int64
	switch v := userID.(type) {
	case int64:
		id = v
	case int:
		id = int64(v)
	case string:
		// Try to parse as int64
		var err error
		_, err = fmt.Sscanf(v, "%d", &id)
		if err != nil {
			return fmt.Errorf("invalid ID format: %w", err)
		}
	default:
		return fmt.Errorf("unsupported ID type: %T", userID)
	}
	query := `DELETE FROM users WHERE id = $1`

	_, err := p.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// Close closes the PostgreSQL connection
func (p *PostgreSQL) Close(ctx context.Context) error {
	return p.db.Close()
}

// Helper methods

// createEmailVerification creates an email verification record
func (p *PostgreSQL) createEmailVerification(ctx context.Context, userID int64, verification *types.EmailVerification) error {
	query := `
		INSERT INTO email_verifications (user_id, token, expires_at)
		VALUES ($1, $2, $3)
	`

	_, err := p.db.ExecContext(ctx, query, userID, verification.Token, verification.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to create email verification: %w", err)
	}

	return nil
}

// loadEmailVerification loads email verification data for a user
func (p *PostgreSQL) loadEmailVerification(ctx context.Context, userID int64, user *types.User) error {
	query := `
		SELECT token, expires_at, verified_at
		FROM email_verifications
		WHERE user_id = $1 AND verified_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1
	`

	var token string
	var expiresAt time.Time
	var verifiedAt sql.NullTime

	err := p.db.QueryRowContext(ctx, query, userID).Scan(&token, &expiresAt, &verifiedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil // No verification record found
		}
		return fmt.Errorf("failed to load email verification: %w", err)
	}

	user.EmailVerification = &types.EmailVerification{
		Token:     token,
		ExpiresAt: expiresAt,
	}
	if verifiedAt.Valid {
		user.EmailVerification.VerifiedAt = &verifiedAt.Time
	}

	return nil
}
