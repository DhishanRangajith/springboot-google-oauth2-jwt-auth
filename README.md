# Spring Boot Google OAuth2 with JWT Authentication

This project demonstrates how to implement **Google OAuth2 login** using **Spring Boot**, generate **JWT access/refresh tokens**, and securely manage authentication.

---

## Authentication Flow

![Auth Flow Chart](images/flowchart.png)

---

## API Endpoints

| Endpoint                       | Method | Description                                                                                 |
| ------------------------------ | ------ | ------------------------------------------------------------------------------------------- |
| `/oauth2/authorization/google` | GET    | Redirects to the backend from Google after the user logs in successfully to share user info |
| `/api/home`                    | GET    | Sample protected API (requires a valid JWT access token)                                    |
| `/api/token/refresh`           | POST   | Refreshes the JWT access token using a valid refresh token                                  |

---

## Key Features

* **Google OAuth2 login** via Spring Security
* **JWT Access & Refresh Token** generation on login
* Tokens are shared as **HttpOnly, Secure cookies** at login
* **Automatic token refresh** using the refresh token when the access token expires

---

## Technologies Used

* **Java 21**
* **Spring Boot 3.5**
* **Spring Security OAuth2 Client**
* **JWT (JSON Web Token)**
* **Google OAuth2**

---

## Screenshots

| Description                              | Screenshot Preview                                          |
| ---------------------------------------- | ----------------------------------------------------------- |
| Google Login Page                        | ![Google Login Page](images/google-login-page.png)          |
| Access & Refresh Tokens saved as cookies | ![Cookies](images/access-refresh-token-cookies.png)         |
| Refreshing Access Token via Postman      | ![Postman Refresh](images/postman-refresh-access-token.png) |

