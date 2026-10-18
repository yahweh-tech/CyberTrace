from django.urls import path

from . import views

app_name = "domain_lookup"

urlpatterns = [
    path(
        "<int:investigation_id>/",
        views.lookup_domain,
        name="search",
    ),
    path(
        "<int:investigation_id>/result/",
        views.lookup_results,
        name="results",
    ),
]
