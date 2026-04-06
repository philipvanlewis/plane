# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from django.urls import path

from plane.license.api.views import (
    EmailCredentialCheckEndpoint,
    InstanceAdminEndpoint,
    InstanceAdminSignInEndpoint,
    InstanceAdminSignUpEndpoint,
    InstanceConfigurationEndpoint,
    DisableEmailFeatureEndpoint,
    InstanceEndpoint,
    SignUpScreenVisitedEndpoint,
    InstanceAdminUserMeEndpoint,
    InstanceAdminSignOutEndpoint,
    InstanceAdminUserSessionEndpoint,
    InstanceWorkSpaceAvailabilityCheckEndpoint,
    InstanceWorkSpaceEndpoint,
)
from plane.license.api.views.oauth import (
    OAuthAppEndpoint,
    OAuthAppRegenerateSecretEndpoint,
    OAuthAppInstallationEndpoint,
)

urlpatterns = [
    path("", InstanceEndpoint.as_view(), name="instance"),
    path("admins/", InstanceAdminEndpoint.as_view(), name="instance-admins"),
    path("admins/me/", InstanceAdminUserMeEndpoint.as_view(), name="instance-admins"),
    path(
        "admins/session/",
        InstanceAdminUserSessionEndpoint.as_view(),
        name="instance-admin-session",
    ),
    path(
        "admins/sign-out/",
        InstanceAdminSignOutEndpoint.as_view(),
        name="instance-admins",
    ),
    path("admins/<uuid:pk>/", InstanceAdminEndpoint.as_view(), name="instance-admins"),
    path(
        "configurations/",
        InstanceConfigurationEndpoint.as_view(),
        name="instance-configuration",
    ),
    path(
        "configurations/disable-email-feature/",
        DisableEmailFeatureEndpoint.as_view(),
        name="disable-email-configuration",
    ),
    path(
        "admins/sign-in/",
        InstanceAdminSignInEndpoint.as_view(),
        name="instance-admin-sign-in",
    ),
    path(
        "admins/sign-up/",
        InstanceAdminSignUpEndpoint.as_view(),
        name="instance-admin-sign-in",
    ),
    path(
        "admins/sign-up-screen-visited/",
        SignUpScreenVisitedEndpoint.as_view(),
        name="instance-sign-up",
    ),
    path(
        "email-credentials-check/",
        EmailCredentialCheckEndpoint.as_view(),
        name="email-credential-check",
    ),
    path(
        "workspace-slug-check/",
        InstanceWorkSpaceAvailabilityCheckEndpoint.as_view(),
        name="instance-workspace-availability",
    ),
    path("workspaces/", InstanceWorkSpaceEndpoint.as_view(), name="instance-workspace"),
    # OAuth app management (admin only)
    path("oauth-apps/", OAuthAppEndpoint.as_view(), name="oauth-apps"),
    path("oauth-apps/<uuid:pk>/", OAuthAppEndpoint.as_view(), name="oauth-app-detail"),
    path(
        "oauth-apps/<uuid:pk>/regenerate-secret/",
        OAuthAppRegenerateSecretEndpoint.as_view(),
        name="oauth-app-regenerate-secret",
    ),
    path(
        "oauth-apps/<uuid:pk>/installations/",
        OAuthAppInstallationEndpoint.as_view(),
        name="oauth-app-installations",
    ),
]
