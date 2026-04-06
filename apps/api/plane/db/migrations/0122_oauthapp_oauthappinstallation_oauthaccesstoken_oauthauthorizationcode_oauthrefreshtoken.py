# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import plane.db.models.oauth
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("db", "0121_alter_estimate_type"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="OAuthApp",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Created At")),
                ("updated_at", models.DateTimeField(auto_now=True, verbose_name="Last Modified At")),
                ("id", models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ("name", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True, default="")),
                ("client_id", models.CharField(db_index=True, default=plane.db.models.oauth.generate_client_id, max_length=64, unique=True)),
                ("client_secret_hash", models.CharField(max_length=64)),
                ("redirect_uris", models.JSONField(default=list)),
                ("homepage_url", models.URLField(blank=True, default="")),
                ("logo_url", models.URLField(blank=True, default="")),
                ("is_active", models.BooleanField(default=True)),
                ("allowed_scopes", models.JSONField(default=list)),
                ("created_by", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="oauth_apps", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "verbose_name": "OAuth App",
                "verbose_name_plural": "OAuth Apps",
                "db_table": "oauth_apps",
                "ordering": ("-created_at",),
            },
        ),
        migrations.CreateModel(
            name="OAuthAppInstallation",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Created At")),
                ("updated_at", models.DateTimeField(auto_now=True, verbose_name="Last Modified At")),
                ("id", models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ("is_active", models.BooleanField(default=True)),
                ("metadata", models.JSONField(default=dict)),
                ("app", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="installations", to="db.oauthapp")),
                ("workspace", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="oauth_installations", to="db.workspace")),
                ("installed_by", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="oauth_installations", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "verbose_name": "OAuth App Installation",
                "verbose_name_plural": "OAuth App Installations",
                "db_table": "oauth_app_installations",
                "ordering": ("-created_at",),
                "unique_together": {("app", "workspace")},
            },
        ),
        migrations.CreateModel(
            name="OAuthAuthorizationCode",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Created At")),
                ("updated_at", models.DateTimeField(auto_now=True, verbose_name="Last Modified At")),
                ("id", models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ("code", models.CharField(db_index=True, default=plane.db.models.oauth.generate_auth_code, max_length=128, unique=True)),
                ("redirect_uri", models.TextField()),
                ("scopes", models.JSONField(default=list)),
                ("code_challenge", models.CharField(blank=True, default="", max_length=128)),
                ("code_challenge_method", models.CharField(blank=True, default="", max_length=10)),
                ("expires_at", models.DateTimeField()),
                ("used", models.BooleanField(default=False)),
                ("app", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="auth_codes", to="db.oauthapp")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ("workspace", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="db.workspace")),
            ],
            options={
                "verbose_name": "OAuth Authorization Code",
                "verbose_name_plural": "OAuth Authorization Codes",
                "db_table": "oauth_authorization_codes",
                "ordering": ("-created_at",),
            },
        ),
        migrations.CreateModel(
            name="OAuthAccessToken",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Created At")),
                ("updated_at", models.DateTimeField(auto_now=True, verbose_name="Last Modified At")),
                ("id", models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ("token", models.CharField(db_index=True, default=plane.db.models.oauth.generate_access_token, max_length=128, unique=True)),
                ("scopes", models.JSONField(default=list)),
                ("expires_at", models.DateTimeField()),
                ("is_revoked", models.BooleanField(default=False)),
                ("app", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="access_tokens", to="db.oauthapp")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="oauth_access_tokens", to=settings.AUTH_USER_MODEL)),
                ("workspace", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="oauth_access_tokens", to="db.workspace")),
            ],
            options={
                "verbose_name": "OAuth Access Token",
                "verbose_name_plural": "OAuth Access Tokens",
                "db_table": "oauth_access_tokens",
                "ordering": ("-created_at",),
            },
        ),
        migrations.CreateModel(
            name="OAuthRefreshToken",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Created At")),
                ("updated_at", models.DateTimeField(auto_now=True, verbose_name="Last Modified At")),
                ("id", models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ("token", models.CharField(db_index=True, default=plane.db.models.oauth.generate_refresh_token, max_length=128, unique=True)),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                ("is_revoked", models.BooleanField(default=False)),
                ("access_token", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="refresh_token", to="db.oauthaccesstoken")),
            ],
            options={
                "verbose_name": "OAuth Refresh Token",
                "verbose_name_plural": "OAuth Refresh Tokens",
                "db_table": "oauth_refresh_tokens",
                "ordering": ("-created_at",),
            },
        ),
    ]
