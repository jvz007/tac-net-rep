from django.urls import path

from tfdreporting.views import NetworkAvailabilityListCreateView


app_name = "tfdreporting"

urlpatterns = [
    path(
        "network-availability/",
        NetworkAvailabilityListCreateView.as_view(),
        name="network-availability",
    ),
]
