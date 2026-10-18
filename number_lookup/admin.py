from django.contrib import admin

from .models import NumberLookup


@admin.register(NumberLookup)
class NumberLookupAdmin(admin.ModelAdmin):

    list_display = (
        "phone_number",
        "country",
        "carrier",
        "line_type",
        "is_virtual",
        "provider",
    )

    search_fields = (
        "phone_number",
        "carrier",
    )