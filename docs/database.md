# Database Setup

The Go Auth library uses MongoDB as its primary database. This document covers database setup, configuration, and best practices.

## MongoDB Requirements

- MongoDB 4.0 or higher
- Network access to MongoDB instance
- Proper authentication and authorization configured

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

### Configuration Example

```go
cfg := &config.Config{
    Database: config.DatabaseConfig{
        URI:        "mongodb://localhost:27017",
        Database:   "myapp",
        Collection: "users",
    },
    // ... other config
}
```

## Database Indexes

The library automatically creates the following indexes for optimal performance:

### Email Index (Unique)
```javascript
{
    "email": 1
}
```
- **Purpose**: Ensures email uniqueness and fast email lookups
- **Options**: Unique constraint

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
