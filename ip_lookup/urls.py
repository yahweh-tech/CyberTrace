from django.urls import path

from . import views

app_name = "ip_lookup"

urlpatterns = [
    path(
        "<int:investigation_id>/",
        views.lookup_ip,
        name="search",
    ),
    path(
        "<int:investigation_id>/result/",
        views.lookup_results,
        name="results",
    ),
]
