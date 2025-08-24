# Database Setup

The Go Auth library supports both MongoDB and PostgreSQL databases. This document covers database setup, configuration, and best practices for both databases.

## Database Requirements

### MongoDB
- MongoDB 4.0 or higher
- Network access to MongoDB instance
- Proper authentication and authorization configured

### PostgreSQL
- PostgreSQL 12.0 or higher
- Network access to PostgreSQL instance
- Proper authentication and authorization configured
- `lib/pq` driver (automatically included)

## Connection Setup

### Local Development

For local development, you can use a local MongoDB instance:

```bash
# Install MongoDB (Ubuntu/Debian)
sudo apt-get install mongodb

# Install MongoDB (macOS with Homebrew)
brew install mongodb-community

# Start MongoDB service
sudo systemctl start mongodb  # Linux
brew services start mongodb-community  # macOS
```

### Connection String Format

The library supports various MongoDB connection string formats:

```go
// Basic local connection
"mongodb://localhost:27017"

// With authentication
"mongodb://username:password@localhost:27017"

// With database name
"mongodb://localhost:27017/mydatabase"

// With options
"mongodb://localhost:27017/?maxPoolSize=10&retryWrites=true"

// Replica set
"mongodb://host1:27017,host2:27017,host3:27017/?replicaSet=myReplicaSet"

// Atlas connection
"mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority"
```

### MongoDB Configuration Example

```go
cfg := &config.Config{
    Database: config.DatabaseConfig{
        Type:        config.DatabaseTypeMongoDB,
        URI:         "mongodb://localhost:27017",
        Database:    "myapp",
        Collection:  "users",
    },
    // ... other config
}
```

### PostgreSQL Configuration Example

```go
cfg := &config.Config{
    Database: config.DatabaseConfig{
        Type:         config.DatabaseTypePostgreSQL,
        Host:         "localhost",
        Port:         5432,
        Username:     "postgres",
        Password:     "password",
        Database:     "myapp",
        SSLMode:      "disable",
        MaxOpenConns: 25,
        MaxIdleConns: 5,
        ConnMaxLifetime: 5 * time.Minute,
    },
    // ... other config
}
```

## Database Schema

### MongoDB Schema

The library creates a `users` collection with the following document structure:

```javascript
{
  "_id": ObjectId,
  "email": String,                    // Unique email address
  "password": String,                 // Hashed password (optional with Google OAuth)
  "first_name": String,               // User's first name
  "last_name": String,                // User's last name
  "is_email_verified": Boolean,       // Email verification status
  "is_active": Boolean,               // Account status
  "created_at": Date,                 // Account creation timestamp
  "updated_at": Date,                 // Last update timestamp
  "last_login_at": Date,              // Last login timestamp (optional)
  
  // Google OAuth fields
  "google_id": String,                // Google OAuth ID (unique, optional)
  "google_profile": {                 // Google profile information (optional)
    "id": String,
    "email": String,
    "verified_email": Boolean,
    "name": String,
    "given_name": String,
    "family_name": String,
    "picture": String,
    "locale": String
  },
  
  // TikTok OAuth fields
  "tiktok_id": String,                // TikTok OAuth ID (unique, optional)
  "tiktok_profile": {                 // TikTok profile information (optional)
    "id": String,
    "username": String,
    "display_name": String,
    "profile_picture": String,
    "bio": String,
    "follower_count": Number,
    "following_count": Number,
    "likes_count": Number,
    "video_count": Number,
    "is_verified": Boolean,
    "is_private": Boolean
  },
  
  // Email verification
  "email_verification": {             // Email verification data (optional)
    "token": String,
    "expires_at": Date
  },
  
  // Password reset
  "password_reset": {                 // Password reset data (optional)
    "token": String,
    "expires_at": Date
  },
  
  // Custom fields
  "custom_fields": Object             // Flexible custom data (optional)
}
```

### PostgreSQL Schema

The library creates the following tables:

#### Users Table
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255),                    -- Optional with Google OAuth
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    is_email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP,
    google_id VARCHAR(255) UNIQUE,            -- Google OAuth ID
    google_profile JSONB,                     -- Google profile information
    tiktok_id VARCHAR(255) UNIQUE,            -- TikTok OAuth ID
    tiktok_profile JSONB,                     -- TikTok profile information
    custom_fields JSONB                       -- Flexible custom data
);
```

#### Email Verifications Table
```sql
CREATE TABLE email_verifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Password Resets Table
```sql
CREATE TABLE password_resets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Database Indexes

The library automatically creates the following indexes for optimal performance:

### MongoDB Indexes

#### Email Index (Unique)
```javascript
{
    "email": 1
}
```
- **Purpose**: Ensures email uniqueness and fast email lookups
- **Options**: Unique constraint

#### Google ID Index (Unique, Sparse)
```javascript
{
    "google_id": 1
}
```
- **Purpose**: Ensures Google ID uniqueness and fast Google OAuth lookups
- **Options**: Unique constraint, sparse index (only for documents with google_id)

#### TikTok ID Index (Unique, Sparse)
```javascript
{
    "tiktok_id": 1
}
```
- **Purpose**: Ensures TikTok ID uniqueness and fast TikTok OAuth lookups
- **Options**: Unique constraint, sparse index (only for documents with tiktok_id)

### Email Verification Token Index
```javascript
{
    "email_verification.token": 1
}
```
- **Purpose**: Fast token lookups for email verification
- **Options**: TTL index for automatic cleanup

### Password Reset Token Index
```javascript
{
    "password_reset.token": 1
}
```
- **Purpose**: Fast token lookups for password reset
- **Options**: TTL index for automatic cleanup

### Created At Index
```javascript
{
    "created_at": 1
}
```
- **Purpose**: Efficient cleanup operations and analytics

## PostgreSQL Setup

### Local Development

For local development, you can use a local PostgreSQL instance:

```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt-get install postgresql postgresql-contrib

# Install PostgreSQL (macOS with Homebrew)
brew install postgresql

# Start PostgreSQL service
sudo systemctl start postgresql  # Linux
brew services start postgresql    # macOS
```

### Database Schema

The library automatically creates the following tables and indexes:

#### Users Table
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    is_email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP,
    custom_fields JSONB
);
```

#### Email Verifications Table
```sql
CREATE TABLE email_verifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Password Resets Table
```sql
CREATE TABLE password_resets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### PostgreSQL Indexes

The library automatically creates the following indexes:

#### Email Index (Unique)
```sql
CREATE INDEX idx_users_email ON users(email);
```
- **Purpose**: Ensures email uniqueness and fast email lookups

#### Google ID Index (Unique)
```sql
CREATE INDEX idx_users_google_id ON users(google_id);
```
- **Purpose**: Ensures Google ID uniqueness and fast Google OAuth lookups

#### TikTok ID Index (Unique)
```sql
CREATE INDEX idx_users_tiktok_id ON users(tiktok_id);
```
- **Purpose**: Ensures TikTok ID uniqueness and fast TikTok OAuth lookups

#### Email Verification Token Index
```sql
CREATE INDEX idx_email_verifications_token ON email_verifications(token);
```
- **Purpose**: Fast token lookups for email verification

#### Password Reset Token Index
```sql
CREATE INDEX idx_password_resets_token ON password_resets(token);
```
- **Purpose**: Fast token lookups for password reset

#### User ID Indexes
```sql
CREATE INDEX idx_email_verifications_user_id ON email_verifications(user_id);
CREATE INDEX idx_password_resets_user_id ON password_resets(user_id);
```
- **Purpose**: Fast joins between users and verification/reset tables

#### Created At Index
```sql
CREATE INDEX idx_users_created_at ON users(created_at);
```
- **Purpose**: Efficient cleanup operations and time-based queries

## User Document Structure

The library stores user data in the following structure:

```javascript
{
    "_id": ObjectId("..."),
    "email": "user@example.com",
    "password": "$2a$10$...", // bcrypt hash
    "first_name": "John",
    "last_name": "Doe",
    "is_email_verified": false,
    "email_verification": {
        "token": "abc123...",
        "expires_at": ISODate("2024-01-01T12:00:00Z"),
        "verified_at": null
    },
    "password_reset": {
        "token": "def456...",
        "expires_at": ISODate("2024-01-01T12:00:00Z"),
        "used_at": null
    },
    "created_at": ISODate("2024-01-01T10:00:00Z"),
    "updated_at": ISODate("2024-01-01T10:00:00Z"),
    "last_login_at": ISODate("2024-01-01T11:00:00Z"),
    "is_active": true
}
```

## Security Considerations

### Authentication

Always use authentication in production:

```go
// With username/password
"mongodb://username:password@localhost:27017"

// With connection options
"mongodb://username:password@localhost:27017/?authSource=admin&authMechanism=SCRAM-SHA-256"
```

### Network Security

- Use TLS/SSL connections in production
- Restrict network access to MongoDB
- Use VPC or private networks when possible

```go
// With TLS
"mongodb://localhost:27017/?ssl=true&sslCertificateAuthorityFile=/path/to/ca.pem"
```

### Database Permissions

Create a dedicated user with minimal required permissions:

```javascript
// Create user with read/write access to specific database
use myapp
db.createUser({
    user: "auth_user",
    pwd: "secure_password",
    roles: [
        { role: "readWrite", db: "myapp" }
    ]
})
```

## Performance Optimization

### Connection Pooling

Configure connection pooling for better performance:

```go
// With connection pool settings
"mongodb://localhost:27017/?maxPoolSize=10&minPoolSize=5&maxIdleTimeMS=30000"
```

### Read Preferences

For replica sets, configure read preferences:

```go
// Read from secondary for better performance
"mongodb://host1:27017,host2:27017,host3:27017/?readPreference=secondary"
```

### Write Concerns

Configure write concerns for data durability:

```go
// Wait for majority acknowledgment
"mongodb://localhost:27017/?w=majority&journal=true"
```

## Monitoring and Maintenance

### Database Monitoring

Monitor your MongoDB instance for:

- Connection count
- Query performance
- Index usage
- Storage usage

### Regular Maintenance

Perform regular maintenance tasks:

```javascript
// Check index usage
db.users.getIndexes()

// Analyze query performance
db.users.find({email: "user@example.com"}).explain("executionStats")

// Clean up expired tokens (automatic with TTL indexes)
// Manual cleanup if needed
db.users.updateMany(
    {
        "email_verification.expires_at": {$lt: new Date()}
    },
    {
        $unset: {"email_verification": ""}
    }
)
```

## Backup and Recovery

### Backup Strategy

Implement a backup strategy:

```bash
# Create backup
mongodump --uri="mongodb://localhost:27017/myapp" --out=/backup

# Restore backup
mongorestore --uri="mongodb://localhost:27017/myapp" /backup/myapp
```

### Data Migration

For schema changes, implement migration scripts:

```javascript
// Example: Add new field to all users
db.users.updateMany(
    {},
    {
        $set: {
            "new_field": "default_value"
        }
    }
)
```

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Check if MongoDB is running
   - Verify port and host settings
   - Check firewall rules

2. **Authentication Failed**
   - Verify username/password
   - Check authentication database
   - Ensure user has proper permissions

3. **Index Creation Failed**
   - Check if indexes already exist
   - Verify user has index creation permissions
   - Check for duplicate key errors

### Debug Mode

Enable debug logging for troubleshooting:

```go
// Add logging to your application
log.SetLevel(log.DebugLevel)

// Or use MongoDB driver logging
client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri).SetLoggerOptions(
    options.Logger().SetLevel(options.LogLevelDebug),
))
```

## Production Checklist

Before deploying to production:

- [ ] MongoDB instance is properly secured
- [ ] Authentication is configured
- [ ] TLS/SSL is enabled
- [ ] Network access is restricted
- [ ] Backup strategy is implemented
- [ ] Monitoring is configured
- [ ] Connection pooling is optimized
- [ ] Indexes are created and optimized
- [ ] User permissions are minimal
- [ ] Write concerns are appropriate
