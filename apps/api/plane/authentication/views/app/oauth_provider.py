# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
OAuth 2.0 Authorization Server endpoints for Plane CE.

Implements RFC 6749 Authorization Code flow with PKCE (RFC 7636),
enabling third-party apps to authenticate Plane users.

Endpoints:
  GET  /auth/o/authorize-app/  — Authorization request (shows consent or redirects)
  POST /auth/o/authorize-app/  — User approves/denies authorization
  POST /auth/o/token/          — Token exchange (auth code → access token)
  POST /auth/o/token/revoke/   — Token revocation
  POST /auth/o/app-installation/ — Install app in a workspace
"""

import base64
import hashlib
from datetime import timedelta
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from django.http import HttpResponseRedirect, JsonResponse
from django.utils import timezone
from django.views import View

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

from plane.authentication.session import BaseSessionAuthentication
from plane.db.models import (
    OAuthApp,
    OAuthAppInstallation,
    OAuthAuthorizationCode,
    OAuthAccessToken,
    OAuthRefreshToken,
)
from plane.db.models.oauth import (
    generate_access_token,
    generate_auth_code,
    generate_refresh_token,
    validate_scopes,
    VALID_SCOPES,
    _hash_secret,
)


# ── Constants ───────────────────────────────────────────────────────

AUTH_CODE_TTL = timedelta(minutes=10)
ACCESS_TOKEN_TTL = timedelta(hours=24)
REFRESH_TOKEN_TTL = timedelta(days=30)


# ── Authorization Endpoint ──────────────────────────────────────────

class OAuthAuthorizeEndpoint(View):
    """
    GET: Validate parameters and redirect to consent screen.
    POST: User approves — create auth code and redirect back to app.
    """

    def get(self, request):
        """Validate OAuth parameters and redirect to the admin consent page."""
        client_id = request.GET.get("client_id", "")
        redirect_uri = request.GET.get("redirect_uri", "")
        response_type = request.GET.get("response_type", "")
        scope = request.GET.get("scope", "")
        state = request.GET.get("state", "")
        code_challenge = request.GET.get("code_challenge", "")
        code_challenge_method = request.GET.get("code_challenge_method", "")

        # Validate required parameters
        if response_type != "code":
            return self._error_redirect(
                redirect_uri, state, "unsupported_response_type",
                "Only response_type=code is supported"
            )

        # Look up app
        try:
            app = OAuthApp.objects.get(client_id=client_id, is_active=True)
        except OAuthApp.DoesNotExist:
            return JsonResponse(
                {"error": "invalid_client", "error_description": "Unknown client_id"},
                status=400,
            )

        # Validate redirect URI
        if not app.is_redirect_uri_valid(redirect_uri):
            return JsonResponse(
                {"error": "invalid_request", "error_description": "Invalid redirect_uri"},
                status=400,
            )

        # Validate scopes
        requested_scopes = scope.split() if scope else []
        try:
            validate_scopes(requested_scopes)
        except ValueError:
            return self._error_redirect(
                redirect_uri, state, "invalid_scope", "One or more scopes are invalid"
            )

        # Validate PKCE method if provided
        if code_challenge and code_challenge_method not in ("S256", "plain"):
            return self._error_redirect(
                redirect_uri, state, "invalid_request",
                "code_challenge_method must be S256 or plain"
            )

        # If user is not authenticated, redirect to login first
        if not request.user.is_authenticated:
            # Store OAuth params in session and redirect to login
            request.session["oauth_params"] = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
            }
            login_url = f"/?next=/auth/o/authorize-app/?{request.GET.urlencode()}"
            return HttpResponseRedirect(login_url)

        # Store validated params in session for the POST handler
        request.session["oauth_authorize"] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "app_name": app.name,
            "app_description": app.description,
        }

        # Redirect to the consent page in the admin UI.
        # The admin app is served at /god-mode/ by the Nginx proxy.
        consent_params = urlencode({
            "client_id": client_id,
            "app_name": app.name,
            "scope": scope,
            "state": state,
        })
        return HttpResponseRedirect(f"/god-mode/oauth-consent/?{consent_params}")

    def post(self, request):
        """User approved authorization — create auth code and redirect."""
        if not request.user.is_authenticated:
            return JsonResponse(
                {"error": "login_required"}, status=401
            )

        oauth_params = request.session.get("oauth_authorize")
        if not oauth_params:
            return JsonResponse(
                {"error": "invalid_request", "error_description": "No pending authorization"},
                status=400,
            )

        # Check if user denied
        if request.POST.get("action") == "deny":
            return self._error_redirect(
                oauth_params["redirect_uri"],
                oauth_params["state"],
                "access_denied",
                "User denied the authorization request",
            )

        # Validate workspace selection
        workspace_id = request.POST.get("workspace_id")
        if not workspace_id:
            return JsonResponse(
                {"error": "invalid_request", "error_description": "workspace_id required"},
                status=400,
            )

        # Look up app
        try:
            app = OAuthApp.objects.get(
                client_id=oauth_params["client_id"], is_active=True
            )
        except OAuthApp.DoesNotExist:
            return JsonResponse(
                {"error": "invalid_client"}, status=400
            )

        # Generate authorization code
        raw_code = generate_auth_code()
        scopes = oauth_params["scope"].split() if oauth_params["scope"] else []

        OAuthAuthorizationCode.objects.create(
            code_hash=_hash_secret(raw_code),
            app=app,
            user=request.user,
            workspace_id=workspace_id,
            redirect_uri=oauth_params["redirect_uri"],
            scopes=scopes,
            code_challenge=oauth_params.get("code_challenge", ""),
            code_challenge_method=oauth_params.get("code_challenge_method", ""),
            expires_at=timezone.now() + AUTH_CODE_TTL,
        )

        # Ensure app is installed in workspace
        OAuthAppInstallation.objects.get_or_create(
            app=app,
            workspace_id=workspace_id,
            defaults={"installed_by": request.user},
        )

        # Clean up session
        del request.session["oauth_authorize"]

        # Redirect back to app with auth code
        params = {"code": raw_code}
        if oauth_params["state"]:
            params["state"] = oauth_params["state"]

        redirect_url = self._build_redirect(
            oauth_params["redirect_uri"], params
        )
        return HttpResponseRedirect(redirect_url)

    def _error_redirect(self, redirect_uri, state, error, description):
        """Redirect to the app with an error."""
        if not redirect_uri:
            return JsonResponse(
                {"error": error, "error_description": description},
                status=400,
            )
        params = {"error": error, "error_description": description}
        if state:
            params["state"] = state
        return HttpResponseRedirect(self._build_redirect(redirect_uri, params))

    def _build_redirect(self, base_uri, params):
        """Append query parameters to a redirect URI."""
        parsed = urlparse(base_uri)
        existing = parse_qs(parsed.query)
        existing.update(params)
        new_query = urlencode(existing, doseq=True)
        return urlunparse(parsed._replace(query=new_query))


# ── Token Endpoint ──────────────────────────────────────────────────

class OAuthTokenEndpoint(APIView):
    """
    Exchange authorization code for access token, or refresh a token.
    No authentication required (client authenticates via client_secret).
    """

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        grant_type = request.data.get("grant_type", "")

        if grant_type == "authorization_code":
            return self._handle_auth_code(request)
        elif grant_type == "refresh_token":
            return self._handle_refresh(request)
        else:
            return Response(
                {"error": "unsupported_grant_type"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def _handle_auth_code(self, request):
        """Exchange authorization code for access + refresh tokens."""
        client_id = request.data.get("client_id", "")
        client_secret = request.data.get("client_secret", "")
        code = request.data.get("code", "")
        redirect_uri = request.data.get("redirect_uri", "")
        code_verifier = request.data.get("code_verifier", "")

        # Validate client
        try:
            app = OAuthApp.objects.get(client_id=client_id, is_active=True)
        except OAuthApp.DoesNotExist:
            return Response(
                {"error": "invalid_client"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not app.verify_client_secret(client_secret):
            return Response(
                {"error": "invalid_client"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Look up auth code
        auth_code = OAuthAuthorizationCode.lookup_by_code(code)
        if not auth_code:
            return Response(
                {"error": "invalid_grant", "error_description": "Invalid authorization code"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate auth code
        if auth_code.used:
            return Response(
                {"error": "invalid_grant", "error_description": "Code already used"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if auth_code.is_expired:
            return Response(
                {"error": "invalid_grant", "error_description": "Code expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if auth_code.app_id != app.id:
            return Response(
                {"error": "invalid_grant", "error_description": "Code not issued to this client"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if auth_code.redirect_uri != redirect_uri:
            return Response(
                {"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate PKCE if code_challenge was set
        if auth_code.code_challenge:
            if not code_verifier:
                return Response(
                    {"error": "invalid_grant", "error_description": "code_verifier required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if auth_code.code_challenge_method == "S256":
                expected = (
                    base64.urlsafe_b64encode(
                        hashlib.sha256(code_verifier.encode()).digest()
                    )
                    .rstrip(b"=")
                    .decode()
                )
            else:  # plain
                expected = code_verifier

            if expected != auth_code.code_challenge:
                return Response(
                    {"error": "invalid_grant", "error_description": "PKCE verification failed"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # Mark code as used
        auth_code.used = True
        auth_code.save(update_fields=["used", "updated_at"])

        # Generate tokens
        raw_access = generate_access_token()
        raw_refresh = generate_refresh_token()

        access_token = OAuthAccessToken.objects.create(
            token_hash=_hash_secret(raw_access),
            token_prefix=raw_access[:20],
            app=app,
            user=auth_code.user,
            workspace=auth_code.workspace,
            scopes=auth_code.scopes,
            expires_at=timezone.now() + ACCESS_TOKEN_TTL,
        )

        OAuthRefreshToken.objects.create(
            token_hash=_hash_secret(raw_refresh),
            access_token=access_token,
            expires_at=timezone.now() + REFRESH_TOKEN_TTL,
        )

        return Response({
            "access_token": raw_access,
            "token_type": "Bearer",
            "expires_in": int(ACCESS_TOKEN_TTL.total_seconds()),
            "refresh_token": raw_refresh,
            "scope": " ".join(auth_code.scopes),
        })

    def _handle_refresh(self, request):
        """Exchange refresh token for a new access token."""
        client_id = request.data.get("client_id", "")
        client_secret = request.data.get("client_secret", "")
        refresh_token_raw = request.data.get("refresh_token", "")

        # Validate client
        try:
            app = OAuthApp.objects.get(client_id=client_id, is_active=True)
        except OAuthApp.DoesNotExist:
            return Response(
                {"error": "invalid_client"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if client_secret and not app.verify_client_secret(client_secret):
            return Response(
                {"error": "invalid_client"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Look up refresh token
        rt = OAuthRefreshToken.lookup_by_token(refresh_token_raw)
        if not rt or not rt.is_valid:
            return Response(
                {"error": "invalid_grant", "error_description": "Invalid or expired refresh token"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        old_access = rt.access_token
        if old_access.app_id != app.id:
            return Response(
                {"error": "invalid_grant"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Revoke old access token
        old_access.is_revoked = True
        old_access.save(update_fields=["is_revoked", "updated_at"])

        # Revoke old refresh token
        rt.is_revoked = True
        rt.save(update_fields=["is_revoked", "updated_at"])

        # Issue new tokens (token rotation)
        raw_access = generate_access_token()
        raw_refresh = generate_refresh_token()

        new_access = OAuthAccessToken.objects.create(
            token_hash=_hash_secret(raw_access),
            token_prefix=raw_access[:20],
            app=app,
            user=old_access.user,
            workspace=old_access.workspace,
            scopes=old_access.scopes,
            expires_at=timezone.now() + ACCESS_TOKEN_TTL,
        )

        OAuthRefreshToken.objects.create(
            token_hash=_hash_secret(raw_refresh),
            access_token=new_access,
            expires_at=timezone.now() + REFRESH_TOKEN_TTL,
        )

        return Response({
            "access_token": raw_access,
            "token_type": "Bearer",
            "expires_in": int(ACCESS_TOKEN_TTL.total_seconds()),
            "refresh_token": raw_refresh,
            "scope": " ".join(old_access.scopes),
        })


# ── Token Revocation ────────────────────────────────────────────────

class OAuthTokenRevokeEndpoint(APIView):
    """Revoke an access or refresh token (RFC 7009)."""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        token = request.data.get("token", "")
        token_type_hint = request.data.get("token_type_hint", "")

        if not token:
            return Response(
                {"error": "invalid_request"}, status=status.HTTP_400_BAD_REQUEST
            )

        token_hash = _hash_secret(token)

        # Try to revoke as access token
        if token_type_hint != "refresh_token":
            at = OAuthAccessToken.objects.filter(token_hash=token_hash).first()
            if at and not at.is_revoked:
                at.is_revoked = True
                at.save(update_fields=["is_revoked", "updated_at"])
                # Also revoke associated refresh token
                OAuthRefreshToken.objects.filter(
                    access_token=at, is_revoked=False
                ).update(is_revoked=True)
                return Response(status=status.HTTP_200_OK)

        # Try to revoke as refresh token
        rt = OAuthRefreshToken.objects.filter(token_hash=token_hash).first()
        if rt and not rt.is_revoked:
            rt.is_revoked = True
            rt.save(update_fields=["is_revoked", "updated_at"])
            # Also revoke associated access token
            if not rt.access_token.is_revoked:
                rt.access_token.is_revoked = True
                rt.access_token.save(update_fields=["is_revoked", "updated_at"])
            return Response(status=status.HTTP_200_OK)

        # RFC 7009: return 200 even if token not found
        return Response(status=status.HTTP_200_OK)


# ── App Installation ────────────────────────────────────────────────

class OAuthAppInstallationEndpoint(APIView):
    """Install an OAuth app in a workspace. Requires authenticated user."""

    authentication_classes = [BaseSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        client_id = request.data.get("client_id", "")
        workspace_id = request.data.get("workspace_id", "")

        if not client_id or not workspace_id:
            return Response(
                {"error": "client_id and workspace_id are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            app = OAuthApp.objects.get(client_id=client_id, is_active=True)
        except OAuthApp.DoesNotExist:
            return Response(
                {"error": "invalid_client"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        installation, created = OAuthAppInstallation.objects.get_or_create(
            app=app,
            workspace_id=workspace_id,
            defaults={"installed_by": request.user},
        )

        return Response(
            {
                "id": str(installation.id),
                "app_id": str(app.id),
                "client_id": app.client_id,
                "workspace_id": str(installation.workspace_id),
                "created": created,
            },
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )
