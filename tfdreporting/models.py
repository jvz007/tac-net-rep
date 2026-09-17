from django.db import models


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

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.client_name} - {self.site_name} - {self.device_name}"
