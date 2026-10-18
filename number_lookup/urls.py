from django.urls import path

from . import views

app_name = "number_lookup"

urlpatterns = [

    path(
        "<int:investigation_id>/",
        views.lookup_number,
        name="search",
    ),

    path(
        "<int:investigation_id>/result/",
        views.lookup_results,
        name="results",
    ),

]