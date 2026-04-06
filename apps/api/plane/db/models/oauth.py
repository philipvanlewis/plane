# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import hashlib
import hmac
import secrets
from urllib.parse import urlparse
from uuid import uuid4

from django.conf import settings
from django.db import models
from django.utils import timezone

from .base import BaseModel


# ── Valid scopes ────────────────────────────────────────────────────
VALID_SCOPES = frozenset([
    "read:projects",
    "write:projects",
    "read:issues",
    "write:issues",
    "read:pages",
    "write:pages",
    "read:cycles",
    "write:cycles",
    "read:modules",
    "write:modules",
    "read:members",
    "admin",
])


# ── Token generators ───────────────────────────────────────────────

def generate_client_id():
    return "plane_ci_" + uuid4().hex


def generate_client_secret():
    return "plane_cs_" + secrets.token_urlsafe(48)


def generate_auth_code():
    return secrets.token_urlsafe(48)


def generate_access_token():
    return "plane_oauth_" + secrets.token_urlsafe(48)


def generate_refresh_token():
    return "plane_rt_" + secrets.token_urlsafe(48)


def _hash_secret(value):
    """SHA-256 hash for token/secret storage."""
    return hashlib.sha256(value.encode()).hexdigest()


def _constant_time_compare(a, b):
    """Timing-safe comparison to prevent side-channel attacks."""
    return hmac.compare_digest(a, b)


# ── Validators ──────────────────────────────────────────────────────

def validate_redirect_uris(uris):
    """Validate redirect URIs are well-formed with https or localhost."""
    if not isinstance(uris, list):
        raise ValueError("redirect_uris must be a list")
    for uri in uris:
        if not isinstance(uri, str) or not uri.strip():
            raise ValueError(f"Invalid redirect URI: {uri!r}")
        parsed = urlparse(uri)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Malformed redirect URI: {uri}")
        # Allow http only for localhost (development)
        if parsed.scheme == "http" and parsed.hostname not in (
            "localhost",
            "127.0.0.1",
            "[::1]",
        ):
            raise ValueError(
                f"Non-localhost redirect URIs must use https: {uri}"
            )


def validate_scopes(scopes):
    """Validate scopes are from the known set."""
    if not isinstance(scopes, list):
        raise ValueError("scopes must be a list")
    invalid = set(scopes) - VALID_SCOPES
    if invalid:
        raise ValueError(f"Invalid scopes: {', '.join(sorted(invalid))}")


# ── Models ──────────────────────────────────────────────────────────

class OAuthApp(BaseModel):
    """
    A registered OAuth application that can request authorization
    from Plane users. Managed by instance admins.
    """

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    client_id = models.CharField(
        max_length=64, unique=True, db_index=True, default=generate_client_id
    )
    # Client secret stored as SHA-256 hash. Plaintext shown once at creation.
    client_secret_hash = models.CharField(max_length=64)
    redirect_uris = models.JSONField(default=list)
    homepage_url = models.URLField(blank=True, default="")
    logo_url = models.URLField(blank=True, default="")
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="oauth_apps",
    )
    allowed_scopes = models.JSONField(default=list)

    class Meta:
        verbose_name = "OAuth App"
        verbose_name_plural = "OAuth Apps"
        db_table = "oauth_apps"
        ordering = ("-created_at",)

    def __str__(self):
        return self.name

    def set_client_secret(self, raw_secret):
        self.client_secret_hash = _hash_secret(raw_secret)

    def verify_client_secret(self, raw_secret):
        return _constant_time_compare(
            _hash_secret(raw_secret), self.client_secret_hash
        )

    def is_redirect_uri_valid(self, uri):
        return uri in self.redirect_uris

    def revoke_all_tokens(self):
        """Revoke all active access and refresh tokens for this app."""
        self.access_tokens.filter(is_revoked=False).update(is_revoked=True)


class OAuthAppInstallation(BaseModel):
    """An OAuth app installed in a specific workspace."""

    app = models.ForeignKey(
        OAuthApp,
        on_delete=models.CASCADE,
        related_name="installations",
    )
    workspace = models.ForeignKey(
        "db.Workspace",
        on_delete=models.CASCADE,
        related_name="oauth_installations",
    )
    installed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="oauth_installations",
    )
    is_active = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict)

    class Meta:
        verbose_name = "OAuth App Installation"
        verbose_name_plural = "OAuth App Installations"
        db_table = "oauth_app_installations"
        ordering = ("-created_at",)
        unique_together = ("app", "workspace")

    def __str__(self):
        return f"{self.app.name} @ {self.workspace.name}"


class OAuthAuthorizationCode(BaseModel):
    """
    Temporary authorization code issued during the OAuth consent flow.
    Single-use and short-lived (10 minutes).

    The code is stored as a SHA-256 hash. The plaintext is returned
    to the client once via redirect and cannot be recovered from the DB.
    """

    # Hash of the authorization code for lookup
    code_hash = models.CharField(max_length=64, unique=True, db_index=True)
    app = models.ForeignKey(
        OAuthApp, on_delete=models.CASCADE, related_name="auth_codes"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE
    )
    workspace = models.ForeignKey(
        "db.Workspace", on_delete=models.CASCADE
    )
    redirect_uri = models.TextField()
    scopes = models.JSONField(default=list)
    # PKCE support (RFC 7636)
    code_challenge = models.CharField(max_length=128, blank=True, default="")
    code_challenge_method = models.CharField(
        max_length=10,
        blank=True,
        default="",
        choices=[("", ""), ("S256", "S256"), ("plain", "plain")],
    )
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    class Meta:
        verbose_name = "OAuth Authorization Code"
        verbose_name_plural = "OAuth Authorization Codes"
        db_table = "oauth_authorization_codes"
        ordering = ("-created_at",)

    def __str__(self):
        return f"AuthCode for {self.app.name} by {self.user}"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @classmethod
    def lookup_by_code(cls, raw_code):
        """Look up an auth code by its plaintext value (hashed for query)."""
        return cls.objects.filter(code_hash=_hash_secret(raw_code)).first()


class OAuthAccessToken(BaseModel):
    """
    Access token issued to an OAuth app for a specific user + workspace.

    The token is stored as a SHA-256 hash. The plaintext is returned
    once at issuance and cannot be recovered from the DB.
    """

    # Hash of the access token for lookup
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    # First 8 chars of the token for display/identification
    token_prefix = models.CharField(max_length=20, default="")
    app = models.ForeignKey(
        OAuthApp, on_delete=models.CASCADE, related_name="access_tokens"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="oauth_access_tokens",
    )
    workspace = models.ForeignKey(
        "db.Workspace",
        on_delete=models.CASCADE,
        related_name="oauth_access_tokens",
    )
    scopes = models.JSONField(default=list)
    expires_at = models.DateTimeField()
    is_revoked = models.BooleanField(default=False)

    class Meta:
        verbose_name = "OAuth Access Token"
        verbose_name_plural = "OAuth Access Tokens"
        db_table = "oauth_access_tokens"
        ordering = ("-created_at",)

    def __str__(self):
        return f"Token {self.token_prefix}... for {self.app.name}"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        return not self.is_revoked and not self.is_expired

    @classmethod
    def lookup_by_token(cls, raw_token):
        """Look up an access token by its plaintext value (hashed for query)."""
        return cls.objects.filter(token_hash=_hash_secret(raw_token)).first()


class OAuthRefreshToken(BaseModel):
    """
    Refresh token for obtaining new access tokens.

    Stored as SHA-256 hash like access tokens.
    """

    # Hash of the refresh token for lookup
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    access_token = models.OneToOneField(
        OAuthAccessToken,
        on_delete=models.CASCADE,
        related_name="refresh_token",
    )
    expires_at = models.DateTimeField(null=True, blank=True)
    is_revoked = models.BooleanField(default=False)

    class Meta:
        verbose_name = "OAuth Refresh Token"
        verbose_name_plural = "OAuth Refresh Tokens"
        db_table = "oauth_refresh_tokens"
        ordering = ("-created_at",)

    def __str__(self):
        return f"RefreshToken for {self.access_token}"

    @property
    def is_expired(self):
        if self.expires_at is None:
            return False
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        return not self.is_revoked and not self.is_expired

    @classmethod
    def lookup_by_token(cls, raw_token):
        """Look up a refresh token by its plaintext value (hashed for query)."""
        return cls.objects.filter(token_hash=_hash_secret(raw_token)).first()
