# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from rest_framework import serializers
from plane.db.models import OAuthApp, OAuthAppInstallation


class OAuthAppSerializer(serializers.ModelSerializer):
    class Meta:
        model = OAuthApp
        fields = [
            "id",
            "name",
            "description",
            "client_id",
            "redirect_uris",
            "homepage_url",
            "logo_url",
            "is_active",
            "allowed_scopes",
            "created_at",
            "updated_at",
            "created_by",
        ]
        read_only_fields = [
            "id",
            "client_id",
            "created_at",
            "updated_at",
            "created_by",
        ]


class OAuthAppInstallationSerializer(serializers.ModelSerializer):
    app_name = serializers.CharField(source="app.name", read_only=True)

    class Meta:
        model = OAuthAppInstallation
        fields = [
            "id",
            "app",
            "app_name",
            "workspace",
            "installed_by",
            "is_active",
            "metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
        ]
