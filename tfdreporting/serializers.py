from datetime import timedelta
from decimal import Decimal

from django.utils import timezone
from rest_framework import serializers

from tfdreporting.models import NetworkAvailability


ALLOWED_STATUSES = ("up", "degraded", "down", "unknown")
MAX_FUTURE_SKEW = timedelta(minutes=10)


class NetworkAvailabilitySerializer(serializers.ModelSerializer):
    status = serializers.ChoiceField(choices=ALLOWED_STATUSES)
    availability_pct = serializers.DecimalField(
        max_digits=6,
        decimal_places=3,
        required=False,
        allow_null=True,
        min_value=Decimal("0"),
        max_value=Decimal("100"),
    )
    latency_ms = serializers.DecimalField(
        max_digits=10,
        decimal_places=3,
        required=False,
        allow_null=True,
        min_value=Decimal("0"),
    )
    packet_loss_pct = serializers.DecimalField(
        max_digits=6,
        decimal_places=3,
        required=False,
        allow_null=True,
        min_value=Decimal("0"),
        max_value=Decimal("100"),
    )
    idempotency_key = serializers.CharField(
        max_length=128,
        required=False,
        allow_blank=True,
        allow_null=True,
    )

    class Meta:
        model = NetworkAvailability
        fields = (
            "id",
            "client_name",
            "site_name",
            "device_name",
            "source",
            "timestamp",
            "status",
            "availability_pct",
            "latency_ms",
            "packet_loss_pct",
            "idempotency_key",
            "ingested_by",
            "received_at",
        )
        read_only_fields = ("id", "ingested_by", "received_at")
        # Disable DRF's auto-generated UniqueTogetherValidator for
        # source + idempotency_key. Idempotency semantics are handled by
        # the view so exact replays can return 200 and conflicts can return 409.
        # The database uniqueness constraint remains the race-condition guard.
        validators = []

    def _strip_required_text(self, value, field_name):
        value = value.strip()
        if not value:
            raise serializers.ValidationError(f"{field_name} must not be blank.")
        return value

    def validate_client_name(self, value):
        return self._strip_required_text(value, "client_name")

    def validate_site_name(self, value):
        return self._strip_required_text(value, "site_name")

    def validate_device_name(self, value):
        return self._strip_required_text(value, "device_name")

    def validate_source(self, value):
        return self._strip_required_text(value, "source")

    def validate_idempotency_key(self, value):
        if value is None:
            return None
        value = value.strip()
        return value or None

    def validate_timestamp(self, value):
        if value > timezone.now() + MAX_FUTURE_SKEW:
            raise serializers.ValidationError(
                "timestamp cannot be more than 10 minutes in the future."
            )
        return value
