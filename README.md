# Secure Login API

## Description
Secure Login API is a robust and secure backend application developed with Node.js and Express. It provides a comprehensive authentication system with advanced security features, including Two-Factor Authentication (2FA) and Google OAuth integration.

## Key Features
- User registration
- Secure login
- Two-Factor Authentication (2FA)
- Google OAuth integration
- CSRF protection
- Rate limiting
- Input sanitization
- NoSQL injection prevention
- Secure HTTP headers with Helmet

## Technologies Used
- Node.js
- Express
- MongoDB
- Mongoose
- JSON Web Tokens (JWT)
- Passport.js
- Speakeasy (for 2FA)
- Helmet
- Express Rate Limit


## Installation
Install dependencies:
npm install

## Configuration
Create a `.env` file in the root directory with the following variables:
```
PORT=3000
MONGODB_URI=mongodb://localhost:27017/secureLoginApp
JWT_SECRET=tu_secreto_jwt_super_seguro
SESSION_SECRET=tu_secreto_de_sesion_super_seguro
GOOGLE_CLIENT_ID=tu_google_client_id
GOOGLE_CLIENT_SECRET=tu_google_client_secret
NODE_ENV=development
```
Make sure to replace the values with your own credentials and configurations.

## Usage
To start the server:
```
npm start
```

# API Endpoints

## `GET /api/auth/csrf-token`: 
Generate X-CSRF-Token

## `POST /api/auth/signup`: User registration
  ### Body (raw JSON):
      
              {
              "email": "user@example.com",
              "password": "password123"
              }
  ### Headers:

  `X-CSRF-Token`: [CSRF Token obtained in step 1]
    
  `Content-Type`: application/json


## `POST /api/auth/login`: User login

  ### Body (raw JSON):
     
           {
              "email": "",
              "password": ""
            }
      
   ### Headers:
      
  `X-CSRF-Token`: [Token CSRF obtenido en el paso 1]  
                        
  `Content-Type`: application/json
  
       
## `POST /api/auth/logout`: User logout
  ### Headers:
      
   `X-CSRF-Token`: [Token CSRF obtenido en el paso 1]
  
   `Authorization`: [Token JWT obtenido del login]
  
   `Content-Type`: application/json
  

## `POST /api/auth/generateTwoFactor`: Generate 2FA code
  
  `X-CSRF-Token`: [Token CSRF obtenido en el paso 1]
  
   `Authorization`: [Token JWT obtenido del login]
  

  Base64 representation of QR code (scan with auth app).
  

## `POST /api/auth/verifyTwoFactor`: Verify 2FA code

  `X-CSRF-Token`: [Token CSRF obtenido en el paso 1]
  
  `Authorization`: [Token JWT obtenido del login]
  
  `Content-Type`: application/json
  
      
  Body (raw JSON):
      
      {
        "token": "123456"  // El código de 6 dígitos de tu app de autenticación
      }
      
- `GET /api/auth/google`: Initiate Google authentication
- `GET /api/auth/google/callback`: Google authentication callback
