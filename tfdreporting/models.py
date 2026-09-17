from django.db import models
from django.db.models import Q


class NetworkAvailability(models.Model):
    client_name = models.CharField(max_length=255)
    site_name = models.CharField(max_length=255)
    device_name = models.CharField(max_length=255)
    source = models.CharField(max_length=100)
    timestamp = models.DateTimeField()
    status = models.CharField(max_length=50)
    availability_pct = models.DecimalField(
        max_digits=6, decimal_places=3, null=True, blank=True
    )
    latency_ms = models.DecimalField(
        max_digits=10, decimal_places=3, null=True, blank=True
    )
    packet_loss_pct = models.DecimalField(
        max_digits=6, decimal_places=3, null=True, blank=True
    )
    idempotency_key = models.CharField(max_length=128, null=True, blank=True)
    ingested_by = models.CharField(max_length=150, blank=True, default="")
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]
        constraints = [
            models.UniqueConstraint(
                fields=["source", "idempotency_key"],
                condition=Q(idempotency_key__isnull=False),
                name="tfd_netavail_source_idempotency_unique",
            )
        ]

    def __str__(self):
        return f"{self.client_name} - {self.site_name} - {self.device_name}"


class ExtensionRolePermission(models.Model):
    """TFD extension permission attached to an existing Tactical Role ID.

    role_id is deliberately stored as an integer instead of a ForeignKey so
    TFD migrations remain independent of Tactical's accounts migration graph.
    """

    role_id = models.PositiveIntegerField()
    codename = models.CharField(max_length=150)
    granted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["role_id", "codename"],
                name="tfd_unique_role_permission",
            )
        ]
        indexes = [
            models.Index(
                fields=["role_id", "codename"],
                name="tfd_role_perm_lookup",
            )
        ]
        ordering = ["role_id", "codename"]

    def __str__(self):
        return f"{self.role_id}: {self.codename} = {self.granted}"
