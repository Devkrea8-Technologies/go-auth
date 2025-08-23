package database

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/go-auth/config"
	"github.com/go-auth/types"
)

// MongoDB represents MongoDB database connection and operations
type MongoDB struct {
	client     *mongo.Client
	database   *mongo.Database
	collection *mongo.Collection
	config     *config.Config
}

// NewMongoDB creates a new MongoDB connection
func NewMongoDB(cfg *config.Config) (*MongoDB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.Database.URI))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping the database
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	database := client.Database(cfg.Database.Database)
	collection := database.Collection(cfg.Database.Collection)

	// Create indexes
	if err := createIndexes(ctx, collection); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	return &MongoDB{
		client:     client,
		database:   database,
		collection: collection,
		config:     cfg,
	}, nil
}

// createIndexes creates necessary indexes for the users collection
func createIndexes(ctx context.Context, collection *mongo.Collection) error {
	// Email index (unique)
	emailIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	// Email verification token index
	emailTokenIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: "email_verification.token", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	}

	// Password reset token index
	passwordTokenIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: "password_reset.token", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	}

	// Created at index for cleanup operations
	createdAtIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "created_at", Value: 1}},
	}

	_, err := collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		emailIndex,
		emailTokenIndex,
		passwordTokenIndex,
		createdAtIndex,
	})

	return err
}

// CreateUser creates a new user in the database
func (m *MongoDB) CreateUser(ctx context.Context, user *types.User) error {
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	user.IsActive = true

	result, err := m.collection.InsertOne(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	user.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

// GetUserByEmail retrieves a user by email
func (m *MongoDB) GetUserByEmail(ctx context.Context, email string) (*types.User, error) {
	var user types.User
	err := m.collection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return &user, nil
}

// GetUserByID retrieves a user by ID
func (m *MongoDB) GetUserByID(ctx context.Context, id primitive.ObjectID) (*types.User, error) {
	var user types.User
	err := m.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}
	return &user, nil
}

// GetUserByEmailVerificationToken retrieves a user by email verification token
func (m *MongoDB) GetUserByEmailVerificationToken(ctx context.Context, token string) (*types.User, error) {
	var user types.User
	err := m.collection.FindOne(ctx, bson.M{"email_verification.token": token}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email verification token: %w", err)
	}
	return &user, nil
}

// GetUserByPasswordResetToken retrieves a user by password reset token
func (m *MongoDB) GetUserByPasswordResetToken(ctx context.Context, token string) (*types.User, error) {
	var user types.User
	err := m.collection.FindOne(ctx, bson.M{"password_reset.token": token}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by password reset token: %w", err)
	}
	return &user, nil
}

// UpdateUser updates a user in the database
func (m *MongoDB) UpdateUser(ctx context.Context, user *types.User) error {
	user.UpdatedAt = time.Now()

	_, err := m.collection.UpdateOne(
		ctx,
		bson.M{"_id": user.ID},
		bson.M{"$set": user},
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

// UpdateUserPassword updates user password
func (m *MongoDB) UpdateUserPassword(ctx context.Context, userID primitive.ObjectID, password string) error {
	_, err := m.collection.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"password":   password,
				"updated_at": time.Now(),
			},
			"$unset": bson.M{"password_reset": ""},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to update user password: %w", err)
	}
	return nil
}

// UpdateEmailVerification updates email verification status
func (m *MongoDB) UpdateEmailVerification(ctx context.Context, userID primitive.ObjectID, verified bool) error {
	update := bson.M{
		"is_email_verified": verified,
		"updated_at":        time.Now(),
	}

	if verified {
		now := time.Now()
		update["email_verification.verified_at"] = &now
	}

	_, err := m.collection.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{"$set": update},
	)
	if err != nil {
		return fmt.Errorf("failed to update email verification: %w", err)
	}
	return nil
}

// UpdateLastLogin updates user's last login time
func (m *MongoDB) UpdateLastLogin(ctx context.Context, userID primitive.ObjectID) error {
	now := time.Now()
	_, err := m.collection.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"last_login_at": &now,
				"updated_at":    time.Now(),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	return nil
}

// DeleteUser deletes a user from the database
func (m *MongoDB) DeleteUser(ctx context.Context, userID primitive.ObjectID) error {
	_, err := m.collection.DeleteOne(ctx, bson.M{"_id": userID})
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

// Close closes the MongoDB connection
func (m *MongoDB) Close(ctx context.Context) error {
	return m.client.Disconnect(ctx)
}
