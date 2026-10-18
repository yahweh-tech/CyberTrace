from django.contrib import admin
from .models import AtlasTactic, AtlasTechnique, AtlasAssessment, AtlasAssessmentTechnique


@admin.register(AtlasTactic)
class AtlasTacticAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "order")
    search_fields = ("code", "name")


@admin.register(AtlasTechnique)
class AtlasTechniqueAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "tactic", "severity")
    list_filter = ("tactic", "severity")
    search_fields = ("code", "name", "description")


class AtlasAssessmentTechniqueInline(admin.TabularInline):
    model = AtlasAssessmentTechnique
    extra = 1


@admin.register(AtlasAssessment)
class AtlasAssessmentAdmin(admin.ModelAdmin):
    list_display = ("system_name", "investigation", "system_type", "risk_level", "risk_score", "created_at")
    list_filter = ("system_type", "risk_level")
    search_fields = ("system_name", "investigation__title")
    inlines = [AtlasAssessmentTechniqueInline]
