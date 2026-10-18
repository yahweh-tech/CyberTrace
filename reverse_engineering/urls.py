from django.urls import path
from . import views

app_name = "reverse_engineering"

urlpatterns = [
    path(
        "<int:investigation_id>/",
        views.upload_and_analyze,
        name="upload",
    ),
    path(
        "<int:investigation_id>/results/",
        views.analysis_results,
        name="results_latest",
    ),
    path(
        "<int:investigation_id>/results/<int:analysis_id>/",
        views.analysis_results,
        name="results",
    ),
]
