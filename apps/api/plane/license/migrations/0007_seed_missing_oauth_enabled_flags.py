# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
Data migration to seed missing IS_*_ENABLED rows for OAuth providers.

The configure_instance management command had a bug where an all-or-nothing
exists() check prevented IS_GOOGLE_ENABLED, IS_GITHUB_ENABLED, and
IS_GITLAB_ENABLED from being created if IS_GITEA_ENABLED already existed.

This migration ensures all four flags exist, creating any that are missing
with a default value of "0" (disabled). Existing rows are left untouched.

See: https://github.com/makeplane/plane/issues/8739
See: https://github.com/makeplane/plane/issues/8679
"""

from django.db import migrations


def seed_oauth_enabled_flags(apps, schema_editor):
    InstanceConfiguration = apps.get_model("license", "InstanceConfiguration")

    flags = [
        "IS_GOOGLE_ENABLED",
        "IS_GITHUB_ENABLED",
        "IS_GITLAB_ENABLED",
        "IS_GITEA_ENABLED",
    ]

    for flag in flags:
        _, created = InstanceConfiguration.objects.get_or_create(
            key=flag,
            defaults={
                "value": "0",
                "category": "AUTHENTICATION",
                "is_encrypted": False,
            },
        )


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("license", "0006_instance_is_current_version_deprecated"),
    ]

    operations = [
        migrations.RunPython(seed_oauth_enabled_flags, noop),
    ]
