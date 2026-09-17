from django.db import IntegrityError, transaction
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from tacticalrmm.auth import APIAuthentication
from tfdreporting.models import NetworkAvailability
from tfdreporting.permissions import NetworkAvailabilityPermission
from tfdreporting.serializers import NetworkAvailabilitySerializer


IMMUTABLE_INGEST_FIELDS = (
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


def _same_ingest_payload(existing, validated_data):
    for field in IMMUTABLE_INGEST_FIELDS:
        if getattr(existing, field) != validated_data.get(field):
            return False
    return True


@extend_schema_view(
    get=extend_schema(
        tags=["TFD Reporting"],
        summary="List network availability records",
        description=(
            "Requires Tactical API-key authentication and the "
            "tfdreporting.networkavailability.list TFD permission."
        ),
    ),
    post=extend_schema(
        tags=["TFD Reporting"],
        summary="Ingest a network availability record",
        description=(
            "Requires Tactical API-key authentication and the "
            "tfdreporting.networkavailability.manage TFD permission. "
            "Optional idempotency_key values are unique per source. Replaying "
            "the same payload with the same source/idempotency_key returns the "
            "existing record with HTTP 200; reusing the key for different data "
            "returns HTTP 409."
        ),
    ),
)
class NetworkAvailabilityListCreateView(ListCreateAPIView):
    authentication_classes = [APIAuthentication]
    permission_classes = [IsAuthenticated, NetworkAvailabilityPermission]
    serializer_class = NetworkAvailabilitySerializer
    queryset = NetworkAvailability.objects.all()

    def _idempotent_response(self, existing, validated_data):
        if _same_ingest_payload(existing, validated_data):
            response = Response(
                self.get_serializer(existing).data,
                status=status.HTTP_200_OK,
            )
            response["X-TFD-Idempotent-Replay"] = "true"
            return response

        return Response(
            {
                "detail": (
                    "idempotency_key has already been used for a different "
                    "payload from this source."
                ),
                "code": "idempotency_conflict",
                "existing_id": existing.pk,
            },
            status=status.HTTP_409_CONFLICT,
        )

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        source = validated_data["source"]
        idempotency_key = validated_data.get("idempotency_key")

        if idempotency_key:
            existing = NetworkAvailability.objects.filter(
                source=source,
                idempotency_key=idempotency_key,
            ).first()
            if existing:
                return self._idempotent_response(existing, validated_data)

        try:
            with transaction.atomic():
                instance = serializer.save(
                    ingested_by=request.user.username,
                )
        except IntegrityError:
            if not idempotency_key:
                raise

            existing = NetworkAvailability.objects.get(
                source=source,
                idempotency_key=idempotency_key,
            )
            return self._idempotent_response(existing, validated_data)

        output = self.get_serializer(instance)
        headers = self.get_success_headers(output.data)
        return Response(
            output.data,
            status=status.HTTP_201_CREATED,
            headers=headers,
        )
