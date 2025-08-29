# Live Code Review Examples - Amazon Interview Scenarios

## Overview
This document contains code samples with intentional security vulnerabilities for live code review practice. Each example includes the vulnerable code, security issues, business impact, and secure implementations.

**Interview Context**: "Please review this code for security issues. You have 5-10 minutes to identify vulnerabilities and explain their business impact."

---

## 1. Java - Authentication & Authorization Vulnerabilities

### Scenario A: JWT Token Validation
```java
// File: AuthenticationService.java
@RestController
@RequestMapping("/api/auth")
public class AuthenticationService {
    
    private static final String SECRET_KEY = "mySecretKey123";
    
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        // Vulnerable: No input validation
        String username = request.getUsername();
        String password = request.getPassword();
        
        // Vulnerable: Weak password checking
        if (username != null && password.equals("admin123")) {
            String token = Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                // Vulnerable: Weak signing algorithm
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
            
            return ResponseEntity.ok(new AuthResponse(token));
        }
        
        // Vulnerable: Information disclosure in error messages
        return ResponseEntity.badRequest()
            .body("Login failed: Invalid username '" + username + "' or password");
    }
    
    @GetMapping("/user/{userId}")
    public ResponseEntity<?> getUserData(@PathVariable String userId, 
                                       @RequestHeader("Authorization") String token) {
        try {
            // Vulnerable: No token validation
            String tokenValue = token.replace("Bearer ", "");
            
            // Vulnerable: IDOR - no ownership check
            UserData userData = userService.findById(Long.parseLong(userId));
            
            if (userData != null) {
                return ResponseEntity.ok(userData);
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            // Vulnerable: Stack trace exposure
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }
}
```

### Security Issues Identified:

1. **Hardcoded Secret Key** (HIGH)
   - **Issue**: JWT secret key hardcoded in source code
   - **Business Impact**: Complete authentication bypass, affects all 200M+ Prime users
   - **Amazon Scale**: Single secret compromise affects entire platform globally
   - **Remediation**: Use AWS Secrets Manager or environment variables

2. **Weak Password Policy** (HIGH)
   - **Issue**: Hardcoded password "admin123"
   - **Business Impact**: Administrative account compromise
   - **Customer Impact**: Full system access, data breach potential
   - **Remediation**: Implement bcrypt hashing with proper password policies

3. **Insecure Direct Object Reference (IDOR)** (HIGH)
   - **Issue**: No authorization check for user data access
   - **Business Impact**: Any user can access any other user's data
   - **Compliance**: GDPR violation, potential €20M fine
   - **Remediation**: Verify token user ID matches requested user ID

4. **Information Disclosure** (MEDIUM)
   - **Issue**: Error messages reveal system internals and usernames
   - **Business Impact**: Assists attackers in reconnaissance
   - **Remediation**: Generic error messages, structured logging

5. **Weak JWT Configuration** (MEDIUM)
   - **Issue**: HS256 algorithm with weak secret
   - **Business Impact**: Token forgery possible
   - **Remediation**: Use RS256 with proper key management

### Secure Implementation:
```java
@RestController
@RequestMapping("/api/auth")
public class SecureAuthenticationService {
    
    @Value("${jwt.secret}")
    private String jwtSecret;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        String username = sanitizeInput(request.getUsername());
        String password = request.getPassword();
        
        Optional<User> user = userService.findByUsername(username);
        if (user.isPresent() && passwordEncoder.matches(password, user.get().getPasswordHash())) {
            String token = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
                .claim("userId", user.get().getId())
                .signWith(SignatureAlgorithm.RS256, getPrivateKey())
                .compact();
            
            auditLogger.logSuccessfulLogin(username, request.getRemoteAddr());
            return ResponseEntity.ok(new AuthResponse(token));
        }
        
        auditLogger.logFailedLogin(username, request.getRemoteAddr());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(new ErrorResponse("Invalid credentials"));
    }
    
    @GetMapping("/user/{userId}")
    @PreAuthorize("hasPermission(#userId, 'USER', 'READ')")
    public ResponseEntity<?> getUserData(@PathVariable Long userId,
                                       Authentication authentication) {
        try {
            UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
            
            // Verify user can only access their own data or has admin role
            if (!principal.getId().equals(userId) && !principal.hasRole("ADMIN")) {
                auditLogger.logUnauthorizedAccess(principal.getId(), userId);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("Access denied"));
            }
            
            UserData userData = userService.findById(userId);
            return ResponseEntity.ok(userData);
            
        } catch (Exception e) {
            logger.error("Error retrieving user data for userId: {}", userId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorResponse("Internal server error"));
        }
    }
}
```

---

## 2. Python - SQL Injection & Input Validation

### Scenario B: User Registration API
```python
# File: user_service.py
import mysql.connector
from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json()
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    # Vulnerable: No input validation
    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Vulnerable: Weak password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Vulnerable: SQL Injection
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='password123',  # Vulnerable: Hardcoded credentials
        database='users'
    )
    
    cursor = connection.cursor()
    
    # Vulnerable: String concatenation for SQL query
    query = f"INSERT INTO users (username, email, password_hash) VALUES ('{username}', '{email}', '{password_hash}')"
    
    try:
        cursor.execute(query)
        connection.commit()
        
        # Vulnerable: Information disclosure
        return jsonify({
            'message': 'User created successfully',
            'user_id': cursor.lastrowid,
            'query_executed': query  # Debug information exposed
        }), 201
        
    except mysql.connector.Error as err:
        # Vulnerable: Database error exposure
        return jsonify({'error': f'Database error: {str(err)}'}), 500
    
    finally:
        cursor.close()
        connection.close()

@app.route('/api/user/<user_id>', methods=['GET'])
def get_user(user_id):
    # Vulnerable: No authentication required
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='password123',
        database='users'
    )
    
    cursor = connection.cursor()
    
    # Vulnerable: SQL Injection in parameter
    query = f"SELECT username, email FROM users WHERE id = {user_id}"
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        
        if result:
            return jsonify({
                'username': result[0],
                'email': result[1]
            })
        else:
            return jsonify({'error': 'User not found'}), 404
            
    except mysql.connector.Error as err:
        return jsonify({'error': f'Database error: {str(err)}'}), 500
    
    finally:
        cursor.close()
        connection.close()

# Vulnerable: Debug mode enabled in production
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
```

### Security Issues Identified:

1. **SQL Injection** (CRITICAL)
   - **Issue**: Direct string concatenation in SQL queries
   - **Business Impact**: Complete database compromise, all customer data at risk
   - **Amazon Scale**: 200M+ customer records exposed, $33B potential breach cost
   - **Attack Example**: `user_id = "1 OR 1=1; DROP TABLE users; --"`
   - **Remediation**: Use parameterized queries/prepared statements

2. **Weak Password Hashing** (HIGH)
   - **Issue**: MD5 hashing without salt
   - **Business Impact**: Password recovery via rainbow tables
   - **Compliance**: Fails PCI DSS requirements for payment systems
   - **Remediation**: Use bcrypt, scrypt, or Argon2 with proper salt

3. **Hardcoded Database Credentials** (HIGH)
   - **Issue**: Database password in source code
   - **Business Impact**: Full database access if code is compromised
   - **Amazon Scale**: Single credential compromise affects entire system
   - **Remediation**: Use AWS Secrets Manager or environment variables

4. **No Authentication/Authorization** (HIGH)
   - **Issue**: Anyone can access user data without authentication
   - **Business Impact**: Complete privacy violation, GDPR non-compliance
   - **Remediation**: Implement JWT or session-based authentication

5. **Information Disclosure** (MEDIUM)
   - **Issue**: Debug information and database errors exposed
   - **Business Impact**: Assists attackers with system reconnaissance
   - **Remediation**: Generic error messages, structured logging

### Secure Implementation:
```python
# File: secure_user_service.py
import os
import bcrypt
import mysql.connector.pooling
from flask import Flask, request, jsonify, g
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
import logging
from marshmallow import Schema, fields, ValidationError

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')

jwt = JWTManager(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database connection pool
db_pool = mysql.connector.pooling.MySQLConnectionPool(
    pool_name="mypool",
    pool_size=10,
    host=os.environ.get('DB_HOST'),
    user=os.environ.get('DB_USER'),
    password=os.environ.get('DB_PASSWORD'),
    database=os.environ.get('DB_NAME')
)

class UserRegistrationSchema(Schema):
    username = fields.Str(required=True, validate=lambda x: 3 <= len(x) <= 50)
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=lambda x: len(x) >= 8)

@app.route('/api/register', methods=['POST'])
def register_user():
    schema = UserRegistrationSchema()
    
    try:
        data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'error': 'Validation failed', 'messages': err.messages}), 400
    
    username = data['username']
    email = data['email']
    password = data['password']
    
    # Secure password hashing
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    connection = db_pool.get_connection()
    cursor = connection.cursor(prepared=True)
    
    # Parameterized query prevents SQL injection
    query = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)"
    
    try:
        cursor.execute(query, (username, email, password_hash))
        connection.commit()
        
        logger.info(f"User registered successfully: {username}")
        
        return jsonify({
            'message': 'User created successfully',
            'user_id': cursor.lastrowid
        }), 201
        
    except mysql.connector.Error as err:
        logger.error(f"Database error during registration: {err}")
        connection.rollback()
        
        if err.errno == 1062:  # Duplicate entry
            return jsonify({'error': 'Username or email already exists'}), 409
        else:
            return jsonify({'error': 'Registration failed'}), 500
    
    finally:
        cursor.close()
        connection.close()

@app.route('/api/user/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    current_user_id = get_jwt_identity()
    
    # Authorization check - users can only access their own data
    if current_user_id != user_id:
        logger.warning(f"Unauthorized access attempt: user {current_user_id} tried to access user {user_id}")
        return jsonify({'error': 'Access denied'}), 403
    
    connection = db_pool.get_connection()
    cursor = connection.cursor(prepared=True)
    
    # Parameterized query
    query = "SELECT username, email FROM users WHERE id = ?"
    
    try:
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        
        if result:
            return jsonify({
                'username': result[0],
                'email': result[1]
            })
        else:
            return jsonify({'error': 'User not found'}), 404
            
    except mysql.connector.Error as err:
        logger.error(f"Database error during user retrieval: {err}")
        return jsonify({'error': 'Internal server error'}), 500
    
    finally:
        cursor.close()
        connection.close()

if __name__ == '__main__':
    # Secure production configuration
    app.run(debug=False, host='127.0.0.1', port=5000)
```

---

## 3. JavaScript - XSS & Client-Side Security

### Scenario C: User Profile Update
```javascript
// File: profile.js
class ProfileManager {
    constructor() {
        this.apiKey = 'sk-1234567890abcdef'; // Vulnerable: Hardcoded API key
        this.baseUrl = 'https://api.example.com';
    }
    
    async updateProfile(userData) {
        // Vulnerable: No input validation
        const profileData = {
            name: userData.name,
            bio: userData.bio,
            website: userData.website
        };
        
        try {
            // Vulnerable: API key exposed in client-side code
            const response = await fetch(`${this.baseUrl}/profile`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.apiKey}`
                },
                body: JSON.stringify(profileData)
            });
            
            const result = await response.json();
            
            if (response.ok) {
                this.displaySuccess(result.message);
                return result;
            } else {
                // Vulnerable: Error message displayed without sanitization
                this.displayError(result.error);
                throw new Error(result.error);
            }
        } catch (error) {
            // Vulnerable: Stack trace exposed to user
            console.error('Full error details:', error);
            this.displayError(`Network error: ${error.message}`);
            throw error;
        }
    }
    
    displayProfile(userProfile) {
        const profileContainer = document.getElementById('profile-container');
        
        // Vulnerable: Direct HTML insertion without sanitization (XSS)
        profileContainer.innerHTML = `
            <h2>${userProfile.name}</h2>
            <p class="bio">${userProfile.bio}</p>
            <a href="${userProfile.website}" target="_blank">Visit Website</a>
            <div class="last-updated">Last updated: ${userProfile.lastModified}</div>
        `;
        
        // Vulnerable: Direct script execution
        if (userProfile.customScript) {
            eval(userProfile.customScript); // Extremely dangerous
        }
    }
    
    handleProfileSubmit() {
        const form = document.getElementById('profile-form');
        
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            
            // Vulnerable: No CSRF protection
            const formData = new FormData(form);
            const userData = {
                name: formData.get('name'),
                bio: formData.get('bio'),
                website: formData.get('website')
            };
            
            // Vulnerable: Local storage of sensitive data
            localStorage.setItem('userProfile', JSON.stringify(userData));
            localStorage.setItem('apiKey', this.apiKey);
            
            try {
                await this.updateProfile(userData);
            } catch (error) {
                // Error already handled in updateProfile
            }
        });
    }
    
    displayError(message) {
        const errorDiv = document.getElementById('error-message');
        // Vulnerable: XSS in error messages
        errorDiv.innerHTML = `<div class="alert alert-danger">${message}</div>`;
    }
    
    displaySuccess(message) {
        const successDiv = document.getElementById('success-message');
        // Vulnerable: XSS in success messages
        successDiv.innerHTML = `<div class="alert alert-success">${message}</div>`;
    }
}

// Vulnerable: Global variable exposure
window.profileManager = new ProfileManager();

// Vulnerable: Initialize without proper security headers check
document.addEventListener('DOMContentLoaded', () => {
    profileManager.handleProfileSubmit();
    
    // Vulnerable: Load profile data without authentication check
    const userId = new URLSearchParams(window.location.search).get('userId');
    if (userId) {
        loadUserProfile(userId);
    }
});

async function loadUserProfile(userId) {
    // Vulnerable: Direct user input in URL construction
    const url = `${profileManager.baseUrl}/profile/${userId}`;
    
    try {
        const response = await fetch(url);
        const profile = await response.json();
        
        profileManager.displayProfile(profile);
    } catch (error) {
        console.error('Error loading profile:', error);
    }
}
```

### Security Issues Identified:

1. **Cross-Site Scripting (XSS)** (CRITICAL)
   - **Issue**: Direct HTML insertion without sanitization
   - **Business Impact**: Account takeover, session hijacking, malware distribution
   - **Amazon Scale**: Affects all users viewing malicious profiles
   - **Attack Example**: `userProfile.name = "<script>alert('XSS')</script>"`
   - **Remediation**: Use textContent or sanitization libraries like DOMPurify

2. **Code Injection via eval()** (CRITICAL)
   - **Issue**: Direct execution of user-provided JavaScript
   - **Business Impact**: Complete client-side compromise, data theft
   - **Customer Impact**: Full browser takeover, credential theft
   - **Remediation**: Never use eval(), implement proper sandboxing

3. **Hardcoded API Key** (HIGH)
   - **Issue**: API key exposed in client-side code
   - **Business Impact**: API abuse, unauthorized access to backend services
   - **Amazon Scale**: Single key compromise affects all users
   - **Remediation**: Use server-side proxy, implement proper token management

4. **Sensitive Data in Local Storage** (HIGH)
   - **Issue**: API keys and profile data stored in browser
   - **Business Impact**: Data persistence across sessions, XSS data theft
   - **Compliance**: GDPR data retention violations
   - **Remediation**: Use secure, httpOnly cookies or session storage

5. **Missing CSRF Protection** (MEDIUM)
   - **Issue**: No anti-CSRF tokens in form submissions
   - **Business Impact**: Unauthorized actions on behalf of users
   - **Remediation**: Implement CSRF tokens, SameSite cookies

### Secure Implementation:
```javascript
// File: secure-profile.js
class SecureProfileManager {
    constructor() {
        this.baseUrl = '/api'; // Use relative URLs, API key handled server-side
        this.csrfToken = this.getCSRFToken();
    }
    
    getCSRFToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.getAttribute('content') : null;
    }
    
    async updateProfile(userData) {
        // Input validation
        const validatedData = this.validateProfileData(userData);
        if (!validatedData.isValid) {
            throw new Error('Invalid profile data');
        }
        
        try {
            const response = await fetch(`${this.baseUrl}/profile`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': this.csrfToken
                },
                credentials: 'same-origin', // Include cookies for authentication
                body: JSON.stringify(validatedData.data)
            });
            
            const result = await response.json();
            
            if (response.ok) {
                this.displayMessage(result.message, 'success');
                return result;
            } else {
                this.displayMessage('Profile update failed', 'error');
                throw new Error('Update failed');
            }
        } catch (error) {
            console.error('Profile update error'); // No sensitive details
            this.displayMessage('Network error occurred', 'error');
            throw error;
        }
    }
    
    validateProfileData(userData) {
        const errors = [];
        
        if (!userData.name || userData.name.length > 100) {
            errors.push('Invalid name');
        }
        
        if (userData.bio && userData.bio.length > 500) {
            errors.push('Bio too long');
        }
        
        if (userData.website && !this.isValidURL(userData.website)) {
            errors.push('Invalid website URL');
        }
        
        return {
            isValid: errors.length === 0,
            errors: errors,
            data: {
                name: this.sanitizeInput(userData.name),
                bio: this.sanitizeInput(userData.bio),
                website: this.sanitizeInput(userData.website)
            }
        };
    }
    
    sanitizeInput(input) {
        if (!input) return '';
        return input.replace(/[<>\"']/g, ''); // Basic sanitization
    }
    
    isValidURL(url) {
        try {
            new URL(url);
            return url.startsWith('http://') || url.startsWith('https://');
        } catch {
            return false;
        }
    }
    
    displayProfile(userProfile) {
        const profileContainer = document.getElementById('profile-container');
        
        // Secure: Create elements programmatically to prevent XSS
        profileContainer.innerHTML = ''; // Clear existing content
        
        const nameElement = document.createElement('h2');
        nameElement.textContent = userProfile.name; // Safe text insertion
        
        const bioElement = document.createElement('p');
        bioElement.className = 'bio';
        bioElement.textContent = userProfile.bio;
        
        const websiteElement = document.createElement('a');
        if (userProfile.website && this.isValidURL(userProfile.website)) {
            websiteElement.href = userProfile.website;
            websiteElement.target = '_blank';
            websiteElement.rel = 'noopener noreferrer'; // Security best practice
            websiteElement.textContent = 'Visit Website';
        }
        
        const lastUpdatedElement = document.createElement('div');
        lastUpdatedElement.className = 'last-updated';
        lastUpdatedElement.textContent = `Last updated: ${userProfile.lastModified}`;
        
        profileContainer.appendChild(nameElement);
        profileContainer.appendChild(bioElement);
        if (websiteElement.href) {
            profileContainer.appendChild(websiteElement);
        }
        profileContainer.appendChild(lastUpdatedElement);
    }
    
    displayMessage(message, type) {
        const messageContainer = document.getElementById(`${type}-message`);
        if (messageContainer) {
            // Safe text content, no HTML injection
            messageContainer.textContent = message;
            messageContainer.className = `alert alert-${type}`;
            messageContainer.style.display = 'block';
            
            // Auto-hide after 5 seconds
            setTimeout(() => {
                messageContainer.style.display = 'none';
            }, 5000);
        }
    }
    
    handleProfileSubmit() {
        const form = document.getElementById('profile-form');
        
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            
            const formData = new FormData(form);
            const userData = {
                name: formData.get('name'),
                bio: formData.get('bio'),
                website: formData.get('website')
            };
            
            try {
                await this.updateProfile(userData);
            } catch (error) {
                // Error handling already done in updateProfile
            }
        });
    }
}

// Secure initialization with authentication check
document.addEventListener('DOMContentLoaded', () => {
    // Check if user is authenticated (server-side rendered check)
    const isAuthenticated = document.body.dataset.authenticated === 'true';
    
    if (isAuthenticated) {
        const profileManager = new SecureProfileManager();
        profileManager.handleProfileSubmit();
        
        // Only load own profile, no arbitrary user ID access
        const currentUserId = document.body.dataset.currentUserId;
        if (currentUserId) {
            loadUserProfile(currentUserId);
        }
    } else {
        window.location.href = '/login';
    }
});

async function loadUserProfile(userId) {
    // Server validates user authorization before returning data
    const url = `/api/profile`; // No user ID in URL, determined server-side
    
    try {
        const response = await fetch(url, {
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            const profile = await response.json();
            window.profileManager.displayProfile(profile);
        } else {
            console.error('Failed to load profile');
        }
    } catch (error) {
        console.error('Network error loading profile');
    }
}
```

---

## Interview Success Framework

### Time Management (5-10 minutes per review)
1. **Quick Scan** (60 seconds): Identify obvious issues like SQL injection, XSS
2. **Deep Analysis** (3-4 minutes): Explain business impact and Amazon scale implications
3. **Remediation** (2-3 minutes): Propose specific fixes with AWS services
4. **Summary** (60 seconds): Prioritize issues by risk level

### Key Points to Demonstrate
1. **Systematic Approach**: Follow consistent methodology (input validation, authentication, authorization, output encoding)
2. **Business Impact**: Connect technical issues to customer trust and financial impact
3. **Scale Awareness**: Consider Amazon's 200M+ users in remediation strategies
4. **AWS Integration**: Leverage AWS services for scalable security solutions

### Communication Excellence
- **Technical Accuracy**: Correctly identify vulnerability types and attack vectors
- **Business Translation**: Explain security issues in business risk terms
- **Practical Solutions**: Provide implementable fixes, not just theoretical advice
- **Confidence**: Demonstrate experience through specific examples and metrics

This code review framework prepares candidates to identify, analyze, and remediate security vulnerabilities at Amazon's scale while demonstrating the systematic thinking and business acumen expected from Application Security Engineers.