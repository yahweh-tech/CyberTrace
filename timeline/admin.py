from django.contrib import admin

from .models import TimelineEvent


@admin.register(TimelineEvent)
class TimelineAdmin(admin.ModelAdmin):

    list_display = (
        "event",
        "investigation",
        "user",
        "created_at",
    )

    list_filter = (
        "created_at",
    )

    search_fields = (
        "event",
    )