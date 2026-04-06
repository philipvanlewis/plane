# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
OAuth Bearer token authentication for DRF.

Validates tokens issued by the OAuth provider endpoints against the
OAuthAccessToken model. Coexists with existing APIKeyAuthentication
and SessionAuthentication.
"""

from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from plane.db.models import OAuthAccessToken


class OAuthTokenAuthentication(authentication.BaseAuthentication):
    """
    Authenticates requests with OAuth Bearer tokens.

    Header format: Authorization: Bearer plane_oauth_xxx

    Sets request.auth to a dict with token metadata (scopes, app, workspace)
    so views can check authorization.
    """

    keyword = "Bearer"

    def authenticate(self, request):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith(f"{self.keyword} "):
            return None

        raw_token = auth_header[len(self.keyword) + 1 :]

        # Only handle our OAuth tokens (prefix check avoids hashing
        # every Bearer token from other systems)
        if not raw_token.startswith("plane_oauth_"):
            return None

        token_obj = OAuthAccessToken.lookup_by_token(raw_token)

        if token_obj is None:
            raise AuthenticationFailed("Invalid OAuth access token")

        if not token_obj.is_valid:
            if token_obj.is_revoked:
                raise AuthenticationFailed("OAuth access token has been revoked")
            if token_obj.is_expired:
                raise AuthenticationFailed("OAuth access token has expired")
            raise AuthenticationFailed("Invalid OAuth access token")

        if not token_obj.app.is_active:
            raise AuthenticationFailed("OAuth app has been deactivated")

        # Return (user, auth_info) — auth_info is available as request.auth
        return (
            token_obj.user,
            {
                "type": "oauth",
                "token_id": str(token_obj.id),
                "app_id": str(token_obj.app_id),
                "app_name": token_obj.app.name,
                "workspace_id": str(token_obj.workspace_id),
                "scopes": token_obj.scopes,
            },
        )

    def authenticate_header(self, request):
        return f'{self.keyword} realm="plane"'
