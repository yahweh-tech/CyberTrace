from django.urls import path

from . import views

app_name = "packet_analysis"

urlpatterns = [
    path(
        "<int:investigation_id>/",
        views.analyze_packets,
        name="search",
    ),
    path(
        "<int:investigation_id>/result/",
        views.analysis_results,
        name="results",
    ),
]
