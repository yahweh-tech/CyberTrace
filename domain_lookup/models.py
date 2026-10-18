from django.db import models

from investigations.models import Investigation


class DomainLookup(models.Model):

    investigation = models.ForeignKey(
        Investigation,
        on_delete=models.CASCADE,
        related_name="domain_lookups",
    )

    domain = models.CharField(max_length=255)
    registrar = models.CharField(max_length=200, blank=True)
    registrant_org = models.CharField(max_length=200, blank=True)
    creation_date = models.DateField(null=True, blank=True)
    expiry_date = models.DateField(null=True, blank=True)
    name_servers = models.TextField(blank=True)
    hosting_provider = models.CharField(max_length=200, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.domain
