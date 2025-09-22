# Secure Node.js Auth Backend API

This project is a comprehensive Node.js backend API that includes all security measures. It has been developed in accordance with modern security standards.

## 🚀 Features

### Security Features
- **JWT Authentication**: Secure token-based authentication
- **Password Hashing**: Strong password hashing with bcrypt
- **Rate Limiting**: DDoS and brute force attack protection
- **XSS Protection**: Cross-site scripting attack protection
- **SQL/NoSQL Injection Prevention**: MongoDB injection protection
- **CORS Configuration**: Cross-origin resource sharing configuration
- **Security Headers**: Security headers with Helmet.js
- **Session Management**: Secure session management
- **Brute Force Protection**: Account lockout mechanism

### Technical Features
- **Express.js**: Web framework
- **MongoDB**: NoSQL database
- **Mongoose**: ODM (Object Document Mapper)
- **Compression**: Response compression

## 📁 Project Structure

```
src/
├── config/          # Configuration files
│   ├── database.js  # Database connection
│   └── security.js  # Security configuration
├── controllers/     # Controllers
│   └── auth.controller.js
├── middlewares/      # Middlewares
│   ├── auth.middleware.js      # Authentication
│   ├── security.js  # Security middlewares
├── models/          # Mongoose models
│   └── User.js
├── routes/          # Route definitions
│   ├── auth.route.js
│   └── index.route.js
└── server.js        # Main server file
```

## 🛠️ Installation

1. **Clone the project:**
```bash
git clone https://github.com/dpoetika/node-auth
cd node-auth
```

2. **Install dependencies:**
```bash
npm install
```

3. **Start MongoDB:**
```bash
# Make sure MongoDB is running
mongod
```

4. **Start the application:**
```bash
# Development mode
npm run dev

# Production mode
npm start
```

## 🔧 Environment Variables

```env
# Server Configuration
NODE_ENV=development
PORT=12000
HOST=0.0.0.0

# Database
MONGODB_URI=mongodb://localhost:27017/secure_backend

# JWT
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRE=7d
JWT_COOKIE_EXPIRE=7

# Security
BCRYPT_SALT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_TIME=30

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

## 📚 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Current user information
- `PUT /api/auth/change-password` - Change password
- `POST /api/auth/forgot-password` - Password reset request
- `PUT /api/auth/reset-password/:token` - Password reset
- `POST /api/auth/verify-email/:token` - Email verification
- `POST /api/auth/resend-verification` - Resend verification email

### System
- `GET /health` - System health check
- `GET /` - API information


## 🔒 Security Measures

### 1. Authentication & Authorization
- JWT token-based authentication
- Token expiration and refresh mechanism
- Secure cookie usage

### 2. Password Security
- Strong password hashing with bcrypt
- Password strength validation
- Password history control
- Account lockout mechanism

### 3. Rate Limiting
- Global rate limiting
- Endpoint-based rate limiting
- Brute force attack protection
- DDoS protection

### 4. Input Validation
- XSS protection
- SQL/NoSQL injection prevention

### 5. Security Headers
- Security headers with Helmet.js
- CORS configuration
- Content Security Policy (CSP)
- HSTS (HTTP Strict Transport Security)


## 🚀 Production Deployment

### 1. Environment Setup
```bash
NODE_ENV=production
```

### 2. Security Checklist
- [ ] Environment variables securely configured
- [ ] HTTPS enabled
- [ ] Database securely configured
- [ ] Rate limiting active
- [ ] Logging configured
- [ ] Error handling active
- [ ] Security headers configured

### 3. Performance Optimization
- Response compression enabled
- Database indexing
- Connection pooling
- Caching strategy


## 🤝 Contributing

1. Fork the project
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Create a Pull Request


## 🆘 Support

If you encounter any issues:
1. Report issues on GitHub Issues
2. Check the documentation
3. Review the logs

## 🔄 Updates

Regularly check for security updates:
```bash
npm audit
npm update
```