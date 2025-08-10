# Laravel Authentication API Documentation

This is a beginner-level Laravel API project that implements manual authentication without using any built-in packages like Sanctum or JWT.

## Features

- User registration with email verification
- User login with API token authentication
- User logout
- Email verification system
- Manual API token management

## API Endpoints

### Base URL
```
http://localhost:8000/api
```

### 1. User Registration (Signup)
**POST** `/signup`

**Request Body:**
```json
{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "password123",
    "password_confirmation": "password123"
}
```

**Response (201):**
```json
{
    "success": true,
    "message": "User registered successfully. Please check your email to verify your account.",
    "data": {
        "user": {
            "id": 1,
            "name": "John Doe",
            "email": "john@example.com",
            "email_verified": false
        }
    }
}
```

### 2. User Login
**POST** `/login`

**Request Body:**
```json
{
    "email": "john@example.com",
    "password": "password123"
}
```

**Response (200):**
```json
{
    "success": true,
    "message": "Login successful",
    "data": {
        "user": {
            "id": 1,
            "name": "John Doe",
            "email": "john@example.com",
            "email_verified": true
        },
        "token": "your-api-token-here",
        "token_type": "Bearer"
    }
}
```

### 3. User Logout
**POST** `/logout`

**Headers:**
```
Authorization: Bearer your-api-token-here
```

**Response (200):**
```json
{
    "success": true,
    "message": "Logged out successfully"
}
```

### 4. Email Verification
**GET** `/verify-email/{token}`

**Response (200):**
```json
{
    "success": true,
    "message": "Email verified successfully"
}
```

### 5. Resend Verification Email
**POST** `/resend-verification`

**Headers:**
```
Authorization: Bearer your-api-token-here
```

**Response (200):**
```json
{
    "success": true,
    "message": "Verification email sent successfully"
}
```

## Error Responses

### Validation Error (422)
```json
{
    "success": false,
    "message": "Validation failed",
    "errors": {
        "email": ["The email field is required."],
        "password": ["The password field is required."]
    }
}
```

### Authentication Error (401)
```json
{
    "success": false,
    "message": "Invalid credentials"
}
```

### Email Not Verified (403)
```json
{
    "success": false,
    "message": "Please verify your email before logging in"
}
```

### Token Required (401)
```json
{
    "success": false,
    "message": "Access token required"
}
```

## Setup Instructions

1. **Install Dependencies:**
   ```bash
   composer install
   ```

2. **Environment Setup:**
   ```bash
   cp .env.example .env
   php artisan key:generate
   ```

3. **Database Configuration:**
   - Update your `.env` file with database credentials
   - Run migrations:
   ```bash
   php artisan migrate
   ```

4. **Email Configuration (Optional):**
   - Update your `.env` file with mail settings
   - For testing, you can use Mailtrap or similar services

5. **Start the Server:**
   ```bash
   php artisan serve
   ```

## Database Schema

### Users Table
- `id` - Primary key
- `name` - User's full name
- `email` - Unique email address
- `password` - Hashed password
- `email_verified_at` - Email verification timestamp
- `email_verification_token` - Email verification token
- `email_verification_token_expires_at` - Token expiration
- `remember_token` - Remember me token
- `created_at` - Creation timestamp
- `updated_at` - Last update timestamp

### API Tokens Table
- `id` - Primary key
- `user_id` - Foreign key to users table
- `token` - Unique API token
- `name` - Token name
- `last_used_at` - Last usage timestamp
- `expires_at` - Token expiration
- `created_at` - Creation timestamp
- `updated_at` - Last update timestamp

## Security Features

- Password hashing using Laravel's built-in Hash facade
- Email verification required before login
- API tokens with expiration (30 days)
- Automatic cleanup of expired tokens
- CSRF protection (for web routes)
- Input validation and sanitization

## Notes

- This is a beginner-level implementation for learning purposes
- In production, consider using Laravel Sanctum or Passport for better security
- Email verification tokens expire after 24 hours
- API tokens expire after 30 days
- All passwords are hashed using bcrypt
