from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import IsAuthenticated

from tacticalrmm.auth import APIAuthentication
from tfdreporting.models import NetworkAvailability
from tfdreporting.permissions import NetworkAvailabilityPermission
from tfdreporting.serializers import NetworkAvailabilitySerializer


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
            "tfdreporting.networkavailability.manage TFD permission."
        ),
    ),
)
class NetworkAvailabilityListCreateView(ListCreateAPIView):
    authentication_classes = [APIAuthentication]
    permission_classes = [IsAuthenticated, NetworkAvailabilityPermission]
    serializer_class = NetworkAvailabilitySerializer
    queryset = NetworkAvailability.objects.all()
