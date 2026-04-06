# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
from smtplib import (
    SMTPAuthenticationError,
    SMTPConnectError,
    SMTPRecipientsRefused,
    SMTPSenderRefused,
    SMTPServerDisconnected,
)

# Django imports
from django.core.mail import BadHeaderError, EmailMultiAlternatives, get_connection
from django.db.models import Q, Case, When, Value

# Third party imports
from rest_framework import status
from rest_framework.response import Response

# Module imports
from .base import BaseAPIView
from plane.license.api.permissions import InstanceAdminPermission
from plane.license.models import InstanceConfiguration
from plane.license.api.serializers import InstanceConfigurationSerializer
from plane.license.utils.encryption import encrypt_data
from plane.utils.cache import cache_response, invalidate_cache
from plane.license.utils.instance_value import get_email_configuration


def _infer_category(key):
    """Infer the configuration category from the key name."""
    prefixes = {
        "GOOGLE_": "GOOGLE",
        "GITHUB_": "GITHUB",
        "GITLAB_": "GITLAB",
        "GITEA_": "GITEA",
        "EMAIL_": "SMTP",
        "ENABLE_SMTP": "SMTP",
        "LLM_": "AI",
        "GPT_": "AI",
        "UNSPLASH_": "UNSPLASH",
        "INTERCOM": "INTERCOM",
    }
    for prefix, category in prefixes.items():
        if key.startswith(prefix):
            return category
    # IS_*_ENABLED flags for auth providers
    if key.startswith("IS_") and key.endswith("_ENABLED"):
        return "AUTHENTICATION"
    return "AUTHENTICATION"


class InstanceConfigurationEndpoint(BaseAPIView):
    permission_classes = [InstanceAdminPermission]

    @cache_response(60 * 60 * 2, user=False)
    def get(self, request):
        instance_configurations = InstanceConfiguration.objects.all()
        serializer = InstanceConfigurationSerializer(instance_configurations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @invalidate_cache(path="/api/instances/configurations/", user=False)
    @invalidate_cache(path="/api/instances/", user=False)
    def patch(self, request):
        # Build lookup of known config metadata for creating missing rows
        from plane.utils.instance_config_variables import instance_config_variables

        config_meta = {item["key"]: item for item in instance_config_variables}

        existing_configurations = InstanceConfiguration.objects.filter(
            key__in=request.data.keys()
        )
        existing_keys = set(existing_configurations.values_list("key", flat=True))

        # Update existing rows
        bulk_configurations = []
        for configuration in existing_configurations:
            value = request.data.get(configuration.key, configuration.value)
            if value and isinstance(value, str):
                value = value.strip()
            if configuration.is_encrypted:
                configuration.value = encrypt_data(value)
            else:
                configuration.value = value
            bulk_configurations.append(configuration)

        if bulk_configurations:
            InstanceConfiguration.objects.bulk_update(
                bulk_configurations, ["value"], batch_size=100
            )

        # Create missing rows — this handles the case where IS_*_ENABLED
        # flags were never seeded due to the configure_instance bug.
        # See: https://github.com/makeplane/plane/issues/8739
        missing_keys = set(request.data.keys()) - existing_keys
        created_configurations = []
        for key in missing_keys:
            value = request.data[key]
            if value and isinstance(value, str):
                value = value.strip()
            meta = config_meta.get(key, {})
            is_encrypted = meta.get("is_encrypted", "SECRET" in key or "PASSWORD" in key)
            category = meta.get("category", _infer_category(key))
            created_configurations.append(
                InstanceConfiguration(
                    key=key,
                    value=encrypt_data(value) if is_encrypted else value,
                    category=category,
                    is_encrypted=is_encrypted,
                )
            )

        if created_configurations:
            InstanceConfiguration.objects.bulk_create(created_configurations)

        # Return all affected configurations
        all_configurations = InstanceConfiguration.objects.filter(
            key__in=request.data.keys()
        )
        serializer = InstanceConfigurationSerializer(all_configurations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class DisableEmailFeatureEndpoint(BaseAPIView):
    permission_classes = [InstanceAdminPermission]

    @invalidate_cache(path="/api/instances/", user=False)
    def delete(self, request):
        try:
            InstanceConfiguration.objects.filter(
                Q(
                    key__in=[
                        "EMAIL_HOST",
                        "EMAIL_HOST_USER",
                        "EMAIL_HOST_PASSWORD",
                        "ENABLE_SMTP",
                        "EMAIL_PORT",
                        "EMAIL_FROM",
                    ]
                )
            ).update(value=Case(When(key="ENABLE_SMTP", then=Value("0")), default=Value("")))
            return Response(status=status.HTTP_200_OK)
        except Exception:
            return Response(
                {"error": "Failed to disable email configuration"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class EmailCredentialCheckEndpoint(BaseAPIView):
    def post(self, request):
        receiver_email = request.data.get("receiver_email", False)
        if not receiver_email:
            return Response(
                {"error": "Receiver email is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        (
            EMAIL_HOST,
            EMAIL_HOST_USER,
            EMAIL_HOST_PASSWORD,
            EMAIL_PORT,
            EMAIL_USE_TLS,
            EMAIL_USE_SSL,
            EMAIL_FROM,
        ) = get_email_configuration()

        # Configure all the connections
        connection = get_connection(
            host=EMAIL_HOST,
            port=int(EMAIL_PORT),
            username=EMAIL_HOST_USER,
            password=EMAIL_HOST_PASSWORD,
            use_tls=EMAIL_USE_TLS == "1",
            use_ssl=EMAIL_USE_SSL == "1",
        )
        # Prepare email details
        subject = "Email Notification from Plane"
        message = "This is a sample email notification sent from Plane application."
        # Send the email
        try:
            msg = EmailMultiAlternatives(
                subject=subject,
                body=message,
                from_email=EMAIL_FROM,
                to=[receiver_email],
                connection=connection,
            )
            msg.send(fail_silently=False)
            return Response({"message": "Email successfully sent."}, status=status.HTTP_200_OK)
        except BadHeaderError:
            return Response({"error": "Invalid email header."}, status=status.HTTP_400_BAD_REQUEST)
        except SMTPAuthenticationError:
            return Response(
                {"error": "Invalid credentials provided"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except SMTPConnectError:
            return Response(
                {"error": "Could not connect with the SMTP server."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except SMTPSenderRefused:
            return Response(
                {"error": "From address is invalid."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except SMTPServerDisconnected:
            return Response(
                {"error": "SMTP server disconnected unexpectedly."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except SMTPRecipientsRefused:
            return Response(
                {"error": "All recipient addresses were refused."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except TimeoutError:
            return Response(
                {"error": "Timeout error while trying to connect to the SMTP server."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except ConnectionError:
            return Response(
                {"error": "Network connection error. Please check your internet connection."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception:
            return Response(
                {"error": "Could not send email. Please check your configuration"},
                status=status.HTTP_400_BAD_REQUEST,
            )
