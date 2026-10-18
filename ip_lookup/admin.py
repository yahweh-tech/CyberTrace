from django.contrib import admin

from .models import IPLookup


@admin.register(IPLookup)
class IPLookupAdmin(admin.ModelAdmin):

    list_display = (
        "ip_address",
        "country",
        "city",
        "isp",
        "is_proxy",
        "investigation",
    )

    search_fields = ("ip_address", "isp", "org")
