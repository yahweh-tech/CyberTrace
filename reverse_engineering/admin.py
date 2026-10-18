from django.contrib import admin
from .models import BinaryAnalysis


@admin.register(BinaryAnalysis)
class BinaryAnalysisAdmin(admin.ModelAdmin):
    list_display = ("file_name", "investigation", "threat_level", "threat_score", "file_type", "is_packed", "created_at")
    list_filter = ("threat_level", "is_packed", "file_type", "created_at")
    search_fields = ("file_name", "sha256", "md5", "imphash")
