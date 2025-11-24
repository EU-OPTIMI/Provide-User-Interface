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
# Authentication
