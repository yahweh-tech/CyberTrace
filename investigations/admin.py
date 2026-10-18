from django.contrib import admin
from .models import Investigation


@admin.register(Investigation)
class InvestigationAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "title",
        "investigator",
        "status",
        "created_at",
    )

    list_filter = ("status",)

    search_fields = (
        "title",
        "investigator__username",
    )