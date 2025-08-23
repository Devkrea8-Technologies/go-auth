package database

import (
	"context"

	"github.com/go-auth/types"
)

// Database interface that both MongoDB and PostgreSQL implement
type Database interface {
	CreateUser(ctx context.Context, user *types.User) error
	GetUserByEmail(ctx context.Context, email string) (*types.User, error)
	GetUserByID(ctx context.Context, userID interface{}) (*types.User, error)
	GetUserByEmailVerificationToken(ctx context.Context, token string) (*types.User, error)
	GetUserByPasswordResetToken(ctx context.Context, token string) (*types.User, error)
	UpdateUser(ctx context.Context, user *types.User) error
	UpdateUserPassword(ctx context.Context, userID interface{}, password string) error
	UpdateEmailVerification(ctx context.Context, userID interface{}, verified bool) error
	UpdateLastLogin(ctx context.Context, userID interface{}) error
	DeleteUser(ctx context.Context, userID interface{}) error
	Close(ctx context.Context) error
}
