from django.contrib import admin

from .models import DomainLookup


@admin.register(DomainLookup)
class DomainLookupAdmin(admin.ModelAdmin):

    list_display = (
        "domain",
        "registrar",
        "creation_date",
        "expiry_date",
        "investigation",
    )

    search_fields = ("domain", "registrar", "registrant_org")
