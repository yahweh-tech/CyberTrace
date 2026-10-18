from django.contrib import admin

from .models import PacketAnalysis


@admin.register(PacketAnalysis)
class PacketAnalysisAdmin(admin.ModelAdmin):

    list_display = (
        "call_id",
        "sip_method",
        "from_uri",
        "to_uri",
        "investigation",
    )

    search_fields = ("call_id", "from_uri", "to_uri", "user_agent")
