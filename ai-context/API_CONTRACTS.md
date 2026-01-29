# Dayflow HRMS - Authentication API Contracts

## Base URL
```
http://localhost:5000/api/auth
```

---

## Endpoints

### 1. Login
**Authenticate user and issue JWT token**

#### Request
```
POST /api/auth/login
Content-Type: application/json
```

**Body:**
```json
{
  "email": "string (required, valid email format, max 100 chars)",
  "password": "string (required, min 8 chars, max 64 chars)"
}
```

**Example:**
```json
{
  "email": "john@dayflow.com",
  "password": "Password123"
}
```

#### Response - Success (200 OK)
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "role": "ADMIN|EMPLOYEE",
    "user": {
      "id": 1,
      "full_name": "John Doe",
      "email": "john@dayflow.com"
    }
  }
}
```

#### Response - Failure (401 Unauthorized)
**Invalid email or password**
```json
{
  "success": false,
  "error": "Invalid email or password",
  "statusCode": 401
}
```

#### Response - Failure (404 Not Found)
**User doesn't exist**
```json
{
  "success": false,
  "error": "Invalid email or password",
  "statusCode": 404
}
```

#### Response - Failure (400 Bad Request)
**Validation error**
```json
{
  "success": false,
  "error": "Validation error",
  "statusCode": 400,
  "details": {
    "email": "Email is required",
    "password": "Password must be at least 8 characters"
  }
}
```

#### Response - Failure (500 Internal Server Error)
```json
{
  "success": false,
  "error": "Authentication service unavailable",
  "statusCode": 500
}
```

---

### 2. Logout
**Clear JWT token and end session**

#### Request
```
POST /api/auth/logout
Authorization: Bearer <token>
```

#### Response - Success (200 OK)
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

### 3. Verify Token (Optional)
**Verify JWT validity and get user info**

#### Request
```
GET /api/auth/verify
Authorization: Bearer <token>
```

#### Response - Success (200 OK)
```json
{
  "success": true,
  "data": {
    "user_id": 1,
    "role": "ADMIN",
    "iat": 1706507200,
    "exp": 1706593600
  }
}
```

#### Response - Failure (401 Unauthorized)
```json
{
  "success": false,
  "error": "Invalid or expired token",
  "statusCode": 401
}
```

---

### 4. Refresh Token (Optional - for token refresh flow)
**Issue new JWT using refresh token**

#### Request
```
POST /api/auth/refresh
Content-Type: application/json
```

**Body:**
```json
{
  "refreshToken": "string"
}
```

#### Response - Success (200 OK)
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": "24h"
  }
}
```

---

## JWT Token Structure

### Header
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### Payload
```json
{
  "user_id": 1,
  "role": "ADMIN|EMPLOYEE",
  "iat": 1706507200,
  "exp": 1706593600
}
```

### Signing
```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  env.JWT_SECRET
)
```

---

## Frontend Implementation Guide

### Storage
```javascript
// Store token in localStorage
localStorage.setItem('dayflow_token', token);
localStorage.setItem('dayflow_role', role);
```

### Headers for Protected Routes
```javascript
// Add to every API request after login
Authorization: `Bearer ${localStorage.getItem('dayflow_token')}`
```

### Redirects After Login
```javascript
const redirects = {
  'ADMIN': '/admin/dashboard',
  'EMPLOYEE': '/dashboard'
};

// After successful login
window.location.href = redirects[role];
```

---

## Backend Implementation Guide

### Environment Variables
```
JWT_SECRET=your_super_secret_key_min_32_chars
JWT_EXPIRES_IN=24h
NODE_ENV=development|production
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=password
DB_NAME=dayflow_hrms
PORT=5000
```

### Password Hashing
```javascript
// Use bcrypt v5+
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 10);
const isValid = await bcrypt.compare(password, hash);
```

### Auth Middleware
```javascript
// Extract and verify token
const token = req.headers.authorization?.split(' ')[1];
const decoded = jwt.verify(token, process.env.JWT_SECRET);
req.user = decoded; // Attach user info to request
```

### Role Guard Middleware
```javascript
// Check if user has required role
if (req.user.role !== requiredRole) {
  return res.status(403).json({
    success: false,
    error: 'Access denied',
    statusCode: 403
  });
}
```

---

## Security Standards

### Password Requirements
- Minimum 8 characters
- Maximum 64 characters
- Must be hashed with bcrypt before storage
- Never store plaintext passwords

### JWT Security
- Algorithm: HS256
- Expiry: 24 hours
- Secret: Stored in environment variables only
- Bearer token in Authorization header

### Error Handling
- Return generic "Invalid email or password" for both user not found and password mismatch
- Never expose which field is wrong
- Log detailed errors server-side only

### Rate Limiting
- Implement rate limiting on /login endpoint
- Recommended: 5 attempts per 15 minutes per IP
- Log all failed attempts in login_attempts table

### Additional Protections
- Use HTTPS only in production
- Set secure HTTP-only cookies for tokens (optional)
- Implement CORS restrictions
- Validate email format strictly
- Sanitize all inputs

---

## Testing Checklist

- [ ] Valid login with ADMIN role → token issued, redirects to /admin/dashboard
- [ ] Valid login with EMPLOYEE role → token issued, redirects to /dashboard
- [ ] Invalid password → 401 error with generic message
- [ ] Unknown email → 401 error with generic message
- [ ] Missing email field → 400 validation error
- [ ] Missing password field → 400 validation error
- [ ] Invalid email format → 400 validation error
- [ ] Password too short → 400 validation error
- [ ] Logout clears token from frontend
- [ ] Protected routes reject requests without valid token
- [ ] Expired token rejected with 401
