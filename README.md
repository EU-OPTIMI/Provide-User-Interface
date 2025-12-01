# Provide-User-Interface

## Shared authentication middleware
This project now contains a reusable Django middleware that lets each microservice rely on a standalone authentication service (sessions + user profiles).

### How it works
- Middleware path: `core.middleware.auth_service.AuthServiceMiddleware`
- Looks for the shared session cookie, validates it against the auth service, and attaches the profile to `request.auth_profile` and `request.auth_user`.
- If `AUTH_SERVICE_ENFORCE=True`, unauthenticated requests are rejected with HTTP 401 (except allowlisted paths).

### Settings to configure
Add these environment variables (or set them directly in each service's settings):
```
AUTH_SERVICE_BASE_URL=https://auth.example.com
AUTH_SERVICE_PROFILE_ENDPOINT=/api/auth/me/        # endpoint that returns the logged-in user's profile
AUTH_SERVICE_LOGIN_PAGE=/api/auth/login-page/      # optional HTML login page for redirects
AUTH_SERVICE_SESSION_COOKIE=sessionid              # cookie name used by the auth service
AUTH_SERVICE_TIMEOUT=3                             # seconds
AUTH_SERVICE_VERIFY_SSL=True
AUTH_SERVICE_ALLOWLIST=/health,/metrics            # optional path prefixes to skip enforcement
AUTH_SERVICE_ENFORCE=True                          # enable to block anonymous traffic
```

### Using in your services
1. Ensure `requests` is installed (already in `requirements.txt` here).
2. Add the middleware to `MIDDLEWARE` **after** Django's `AuthenticationMiddleware`.
3. Access the authenticated user info in views as `request.auth_user` (lightweight user object with `is_authenticated` and `profile`) or `request.auth_profile` (raw dict).

### Profile integration prompt (service on :8000, auth on :8001)
```
Auth base: http://localhost:8001
Endpoints:
  - Profile: GET {AUTH_BASE}/api/auth/me/
  - Login:   POST {AUTH_BASE}/api/auth/login/
  - Logout:  POST {AUTH_BASE}/api/auth/logout/
  - Login page: GET {AUTH_BASE}/api/auth/login-page/?next=<return_url>
Cookie: sessionid (or whatever SESSION_COOKIE_NAME is); send it on all auth calls.

Flow:
- On page load, call /api/auth/me/ with credentials: 'include' (or forward cookie server-side).
  - If 200: render profile (id, username, email, is_staff, is_superuser).
  - If 401: redirect to the login page with next=<current_url>.
- Logout UI: POST to /api/auth/logout/ with the cookie (include X-CSRFToken in browser),
  clear local user state, then redirect to the login page with next back to your page.

Dev CORS/cookies:
- CORS_ALLOWED_ORIGINS includes http://localhost:8000 and http://localhost:8001
- CORS_ALLOW_CREDENTIALS=True
- SESSION_COOKIE_SAMESITE=None (and SESSION_COOKIE_SECURE=False with DEBUG=True) to allow cross-port cookies on localhost.
```

### Local integration prompt (service on :8000, auth on :8001)
```
Auth base: http://localhost:8001
Session cookie: sessionid
Profile: GET  {AUTH_BASE}/api/auth/me/
Login API: POST {AUTH_BASE}/api/auth/login/
Logout API: POST {AUTH_BASE}/api/auth/logout/
Login page: GET  {AUTH_BASE}/api/auth/login-page/?next=<return_url>

Browser flow:
- Request checks /api/auth/me/ with credentials: 'include'.
- If 200, proceed with profile.
- If 401, redirect to login-page with ?next=<original_url>.
- Login form posts username/email + password to /api/auth/login/ (credentials: 'include', X-CSRFToken from csrftoken).
- Logout posts to /api/auth/logout/ (credentials: 'include', X-CSRFToken) and then redirect to the login page (or home).

Dev CORS/cookies:
- CORS_ALLOWED_ORIGINS include http://localhost:8000 and http://localhost:8001
- CORS_ALLOW_CREDENTIALS=True
- SESSION_COOKIE_SAMESITE=None and SESSION_COOKIE_SECURE=False (with DEBUG=True) for HTTP localhost.
```
# Authentication
