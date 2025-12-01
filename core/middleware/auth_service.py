import logging
from urllib.parse import urljoin

import requests
from django.conf import settings
from django.http import JsonResponse

logger = logging.getLogger(__name__)


class RemoteAuthUser:
    """
    Lightweight user object built from the authentication service profile.
    Only the minimal attributes used by Django auth-aware code are provided.
    """

    def __init__(self, profile: dict):
        self.profile = profile or {}
        self.id = self.profile.get("id") or self.profile.get("uuid")
        self.username = (
            self.profile.get("username")
            or self.profile.get("email")
            or self.profile.get("name")
        )
        self.email = self.profile.get("email")
        self.is_staff = bool(self.profile.get("is_staff", False))
        self.is_superuser = bool(self.profile.get("is_superuser", False))
        self.is_authenticated = True  # mirrors Django's User API

    @property
    def is_anonymous(self):
        return False

    def __str__(self):
        return self.username or "authenticated-user"


class AuthServiceMiddleware:
    """
    Middleware that validates the incoming session cookie against a shared
    authentication service and attaches the resolved profile to the request.

    Expected settings (all optional):
    - AUTH_SERVICE_BASE_URL: Base URL of the auth service (e.g., https://auth.internal)
    - AUTH_SERVICE_PROFILE_ENDPOINT: Relative endpoint returning the current user's profile.
    - AUTH_SERVICE_SESSION_COOKIE: Cookie name shared by the auth service (defaults to SESSION_COOKIE_NAME).
    - AUTH_SERVICE_TIMEOUT: Seconds to wait for the auth service (default: 3).
    - AUTH_SERVICE_VERIFY_SSL: Whether to verify SSL certs (default: True).
    - AUTH_SERVICE_ALLOWLIST: Iterable of path prefixes that should bypass enforcement (e.g., health checks).
    - AUTH_SERVICE_ENFORCE: If True, rejects unauthenticated requests with 401 responses.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.base_url = getattr(settings, "AUTH_SERVICE_BASE_URL", "").rstrip("/")
        self.profile_endpoint = getattr(
            settings, "AUTH_SERVICE_PROFILE_ENDPOINT", "/api/auth/me/"
        )
        self.login_page = getattr(
            settings, "AUTH_SERVICE_LOGIN_PAGE", "/api/auth/login-page/"
        )
        self.session_cookie_name = getattr(
            settings, "AUTH_SERVICE_SESSION_COOKIE", settings.SESSION_COOKIE_NAME
        )
        self.timeout = getattr(settings, "AUTH_SERVICE_TIMEOUT", 3)
        self.verify_ssl = getattr(settings, "AUTH_SERVICE_VERIFY_SSL", True)
        configured_allowlist = tuple(getattr(settings, "AUTH_SERVICE_ALLOWLIST", []))
        builtin_allowlist = (
            "/health",
            "/metrics",
            "/api/auth/profile",
            "/api/auth/profile/",
        )
        self.allowlist = tuple(dict.fromkeys([*configured_allowlist, *builtin_allowlist]))
        self.enforce = getattr(settings, "AUTH_SERVICE_ENFORCE", False)

    def __call__(self, request):
        request.auth_user = None
        request.auth_profile = None

        if not self.base_url or self._is_allowlisted(request.path):
            if not self.base_url:
                logger.debug("Auth middleware disabled: AUTH_SERVICE_BASE_URL not set.")
            else:
                logger.debug("Auth middleware allowlisted path: %s", request.path)
            return self.get_response(request)

        session_token = request.COOKIES.get(self.session_cookie_name)
        if not session_token:
            if self.enforce:
                logger.info(
                    "Auth rejected: no session cookie (%s) on %s", self.session_cookie_name, request.path
                )
                return self._reject_or_redirect(request, "Authentication cookie missing.")
            return self.get_response(request)

        profile, failure_reason = self._fetch_profile(session_token)
        if profile:
            user = RemoteAuthUser(profile)
            request.auth_user = user
            request.auth_profile = profile
            # Override request.user so downstream views can rely on is_authenticated
            request.user = user
            request._cached_user = user
            logger.info(
                "Auth success for user_id=%s username=%s path=%s",
                user.id,
                user.username,
                request.path,
            )
        elif self.enforce:
            logger.info(
                "Auth rejected: %s path=%s", failure_reason or "unknown", request.path
            )
            return self._reject_or_redirect(request, failure_reason or "Authentication failed.")

        return self.get_response(request)

    def _is_allowlisted(self, path: str) -> bool:
        return any(path.startswith(prefix) for prefix in self.allowlist)

    def _fetch_profile(self, session_token):
        url = urljoin(f"{self.base_url}/", self.profile_endpoint.lstrip("/"))
        try:
            response = requests.get(
                url,
                headers={"Accept": "application/json"},
                cookies={self.session_cookie_name: session_token},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except requests.RequestException as exc:
            logger.warning("Auth service unreachable: %s", exc)
            return None, "Authentication service unavailable."

        if response.status_code == 200:
            try:
                payload = response.json()
            except ValueError:
                logger.warning("Auth service returned non-JSON response.")
                return None, "Invalid response from authentication service."
            profile = payload.get("user") or payload.get("data") or payload
            return profile, None

        if response.status_code == 401:
            return None, "Authentication expired or invalid."

        logger.warning(
            "Auth service error (status %s): %s",
            response.status_code,
            response.text[:200],
        )
        return None, "Authentication service error."

    @staticmethod
    def _reject_unauthorized(message: str):
        return JsonResponse({"detail": message}, status=401)

    def _reject_or_redirect(self, request, message: str):
        """Redirect browsers to login page when available; otherwise 401 JSON."""
        # Redirect only for GET/HEAD browser flows and when a login page is configured.
        if request.method in ("GET", "HEAD") and self.login_page:
            next_url = request.build_absolute_uri()
            login_url = urljoin(f"{self.base_url}/", self.login_page.lstrip("/"))
            redirect_url = f"{login_url}?next={next_url}"
            logger.debug("Redirecting to login page: %s", redirect_url)
            from django.http import HttpResponseRedirect

            return HttpResponseRedirect(redirect_url)
        return self._reject_unauthorized(message)
