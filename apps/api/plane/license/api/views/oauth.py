# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from rest_framework import status
from rest_framework.response import Response

from .base import BaseAPIView
from plane.license.api.permissions import InstanceAdminPermission
from plane.db.models import OAuthApp, OAuthAppInstallation
from plane.db.models.oauth import (
    generate_client_secret,
    validate_redirect_uris,
    validate_scopes,
)
from plane.license.api.serializers.oauth import (
    OAuthAppSerializer,
    OAuthAppInstallationSerializer,
)


class OAuthAppEndpoint(BaseAPIView):
    """Admin CRUD for OAuth app registrations."""

    permission_classes = [InstanceAdminPermission]

    def get(self, request, pk=None):
        if pk:
            try:
                app = OAuthApp.objects.get(pk=pk)
            except OAuthApp.DoesNotExist:
                return Response(
                    {"error": "OAuth app not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            serializer = OAuthAppSerializer(app)
            return Response(serializer.data, status=status.HTTP_200_OK)

        apps = OAuthApp.objects.all().order_by("-created_at")[:100]
        serializer = OAuthAppSerializer(apps, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        name = request.data.get("name", "").strip()
        if not name:
            return Response(
                {"error": "App name is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        redirect_uris = request.data.get("redirect_uris", [])
        allowed_scopes = request.data.get("allowed_scopes", [])

        # Validate redirect URIs and scopes
        try:
            validate_redirect_uris(redirect_uris)
        except ValueError as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            validate_scopes(allowed_scopes)
        except ValueError as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_400_BAD_REQUEST
            )

        # Generate client secret
        raw_secret = generate_client_secret()

        # Create the app
        app = OAuthApp(
            name=name,
            description=request.data.get("description", ""),
            redirect_uris=redirect_uris,
            homepage_url=request.data.get("homepage_url", ""),
            logo_url=request.data.get("logo_url", ""),
            allowed_scopes=allowed_scopes,
            created_by=request.user,
        )
        app.set_client_secret(raw_secret)
        app.save()

        # Return the app data with the plaintext secret (shown only once)
        response_data = OAuthAppSerializer(app).data
        response_data["client_secret"] = raw_secret

        return Response(response_data, status=status.HTTP_201_CREATED)

    def patch(self, request, pk=None):
        if not pk:
            return Response(
                {"error": "App ID is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            app = OAuthApp.objects.get(pk=pk)
        except OAuthApp.DoesNotExist:
            return Response(
                {"error": "OAuth app not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Validate updated fields if present
        if "redirect_uris" in request.data:
            try:
                validate_redirect_uris(request.data["redirect_uris"])
            except ValueError as e:
                return Response(
                    {"error": str(e)}, status=status.HTTP_400_BAD_REQUEST
                )

        if "allowed_scopes" in request.data:
            try:
                validate_scopes(request.data["allowed_scopes"])
            except ValueError as e:
                return Response(
                    {"error": str(e)}, status=status.HTTP_400_BAD_REQUEST
                )

        serializer = OAuthAppSerializer(app, data=request.data, partial=True)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, pk=None):
        if not pk:
            return Response(
                {"error": "App ID is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            app = OAuthApp.objects.get(pk=pk)
        except OAuthApp.DoesNotExist:
            return Response(
                {"error": "OAuth app not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Cascade delete handles tokens, codes, and installations
        app.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class OAuthAppRegenerateSecretEndpoint(BaseAPIView):
    """Regenerate the client secret for an OAuth app and revoke all tokens."""

    permission_classes = [InstanceAdminPermission]

    def post(self, request, pk=None):
        if not pk:
            return Response(
                {"error": "App ID is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            app = OAuthApp.objects.get(pk=pk)
        except OAuthApp.DoesNotExist:
            return Response(
                {"error": "OAuth app not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Generate new secret
        raw_secret = generate_client_secret()
        app.set_client_secret(raw_secret)
        app.save(update_fields=["client_secret_hash", "updated_at"])

        # Revoke all existing tokens — if the secret is being rotated,
        # the previous secret may have been compromised.
        app.revoke_all_tokens()

        return Response(
            {
                "client_secret": raw_secret,
                "tokens_revoked": True,
            },
            status=status.HTTP_200_OK,
        )


class OAuthAppInstallationEndpoint(BaseAPIView):
    """List installations for an OAuth app."""

    permission_classes = [InstanceAdminPermission]

    def get(self, request, pk=None):
        if not pk:
            return Response(
                {"error": "App ID is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify app exists first for consistent error semantics
        if not OAuthApp.objects.filter(pk=pk).exists():
            return Response(
                {"error": "OAuth app not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        installations = OAuthAppInstallation.objects.filter(
            app_id=pk
        ).select_related("app", "workspace")[:100]
        serializer = OAuthAppInstallationSerializer(installations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
