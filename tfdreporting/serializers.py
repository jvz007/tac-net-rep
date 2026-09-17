from decimal import Decimal

from rest_framework import serializers

from tfdreporting.models import NetworkAvailability


class NetworkAvailabilitySerializer(serializers.ModelSerializer):
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
        )
        read_only_fields = ("id",)
