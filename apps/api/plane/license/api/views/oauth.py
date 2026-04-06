# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from rest_framework import status
from rest_framework.response import Response

from .base import BaseAPIView
from plane.license.api.permissions import InstanceAdminPermission
from plane.db.models import OAuthApp, OAuthAppInstallation
from plane.db.models.oauth import generate_client_secret
from plane.license.api.serializers.oauth import (
    OAuthAppSerializer,
    OAuthAppCreateSerializer,
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

        apps = OAuthApp.objects.all().order_by("-created_at")
        serializer = OAuthAppSerializer(apps, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = OAuthAppCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        # Generate client secret
        raw_secret = generate_client_secret()

        # Create the app
        app = OAuthApp(
            name=serializer.validated_data["name"],
            description=serializer.validated_data.get("description", ""),
            redirect_uris=serializer.validated_data.get("redirect_uris", []),
            homepage_url=serializer.validated_data.get("homepage_url", ""),
            logo_url=serializer.validated_data.get("logo_url", ""),
            allowed_scopes=serializer.validated_data.get("allowed_scopes", []),
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

        app.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class OAuthAppRegenerateSecretEndpoint(BaseAPIView):
    """Regenerate the client secret for an OAuth app."""

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

        raw_secret = generate_client_secret()
        app.set_client_secret(raw_secret)
        app.save(update_fields=["client_secret_hash", "updated_at"])

        return Response(
            {"client_secret": raw_secret},
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

        installations = OAuthAppInstallation.objects.filter(
            app_id=pk
        ).select_related("app", "workspace")
        serializer = OAuthAppInstallationSerializer(installations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
