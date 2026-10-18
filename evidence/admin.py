from django.contrib import admin

from .models import Evidence


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):

    list_display = (
        "title",
        "file_type",
        "uploaded_by",
        "uploaded_at",
    )

    search_fields = (
        "title",
    )