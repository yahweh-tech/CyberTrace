from django.urls import path

from . import views

app_name = "reports"

urlpatterns = [
    path(
        "<int:investigation_id>/export/csv/",
        views.export_csv,
        name="export_csv",
    ),
]
