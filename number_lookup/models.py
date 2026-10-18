from django.db import models

from investigations.models import Investigation


class NumberLookup(models.Model):

    investigation = models.ForeignKey(
        Investigation,
        on_delete=models.CASCADE,
        related_name="number_lookups",
    )

    phone_number = models.CharField(max_length=20)

    country = models.CharField(
        max_length=100,
        blank=True,
    )

    carrier = models.CharField(
        max_length=100,
        blank=True,
    )

    line_type = models.CharField(
        max_length=50,
        blank=True,
    )

    is_virtual = models.BooleanField(default=False)

    provider = models.CharField(
        max_length=100,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    def __str__(self):
        return self.phone_number