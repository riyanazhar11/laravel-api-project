# Laravel Authentication API Setup Guide

## Prerequisites

- PHP 8.2 or higher
- Composer
- MySQL/PostgreSQL/SQLite database
- Web server (Apache/Nginx) or PHP built-in server

## Installation Steps

### 1. Clone/Download the Project
```bash
# If you have the project files, navigate to the project directory
cd laravel-api-project
```

### 2. Install Dependencies
```bash
composer install
```

### 3. Environment Configuration
```bash
# Copy the environment file
cp .env.example .env

# Generate application key
php artisan key:generate
```

### 4. Database Configuration
Edit your `.env` file and configure your database:

```env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel_auth_api
DB_USERNAME=your_username
DB_PASSWORD=your_password
```

### 5. Run Migrations
```bash
php artisan migrate
```

### 6. Email Configuration (Optional)
For email verification to work, configure your mail settings in `.env`:

```env
MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=your_username
MAIL_PASSWORD=your_password
MAIL_ENCRYPTION=tls
MAIL_FROM_ADDRESS="noreply@yourapp.com"
MAIL_FROM_NAME="${APP_NAME}"
```

For testing, you can use:
- **Mailtrap.io** (free tier available)
- **Gmail SMTP** (requires app password)
- **Laravel Log Driver** (emails will be logged to storage/logs/laravel.log)

### 7. Start the Development Server
```bash
php artisan serve
```

The API will be available at: `http://localhost:8000/api`

## Testing the API

### Using the Test Script
```bash
php test_api.php
```

### Using cURL
```bash
# Register a new user
curl -X POST http://localhost:8000/api/signup \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "password123",
    "password_confirmation": "password123"
  }'

# Login (after email verification)
curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "password123"
  }'
```

### Using Postman
1. Import the API endpoints
2. Set the base URL to: `http://localhost:8000/api`
3. Use the provided request examples in the API documentation

## Console Commands

### List All Users
```bash
php artisan user:list
```

### Manually Verify User Email (for testing)
```bash
php artisan user:verify-email john@example.com
```

## Troubleshooting

### Common Issues

1. **"Class not found" errors**
   - Run `composer dump-autoload`

2. **Database connection errors**
   - Check your `.env` file database configuration
   - Ensure your database server is running

3. **Migration errors**
   - Run `php artisan migrate:fresh` (⚠️ This will delete all data)

4. **Email not sending**
   - Check your mail configuration in `.env`
   - Check the Laravel logs: `storage/logs/laravel.log`
   - For testing, emails are logged to the console

5. **API routes not working**
   - Ensure the server is running: `php artisan serve`
   - Check that API routes are properly registered in `bootstrap/app.php`

### Log Files
- Application logs: `storage/logs/laravel.log`
- Email logs: Check the console output when using the log driver

## Security Notes

- This is a beginner-level implementation for learning purposes
- In production, consider:
  - Using HTTPS
  - Implementing rate limiting
  - Using Laravel Sanctum or Passport for better security
  - Setting up proper email services
  - Implementing password reset functionality
  - Adding two-factor authentication

## Next Steps

1. Test all API endpoints
2. Implement additional features (password reset, profile management)
3. Add more validation rules
4. Implement rate limiting
5. Add API documentation using tools like Swagger/OpenAPI
6. Set up automated testing
