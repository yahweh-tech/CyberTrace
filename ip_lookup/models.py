from django.db import models

from investigations.models import Investigation


class IPLookup(models.Model):

    investigation = models.ForeignKey(
        Investigation,
        on_delete=models.CASCADE,
        related_name="ip_lookups",
    )

    ip_address = models.GenericIPAddressField()

    country = models.CharField(max_length=100, blank=True)
    region = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    isp = models.CharField(max_length=200, blank=True)
    org = models.CharField(max_length=200, blank=True)
    is_proxy = models.BooleanField(default=False)
    latitude = models.DecimalField(
        max_digits=9,
        decimal_places=6,
        null=True,
        blank=True,
    )
    longitude = models.DecimalField(
        max_digits=9,
        decimal_places=6,
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address
