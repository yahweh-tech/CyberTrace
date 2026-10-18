from django.urls import path

from . import views

app_name = "investigations"

urlpatterns = [

    path(
        "",
        views.investigation_list,
        name="list",
    ),

    path(
        "create/",
        views.investigation_create,
        name="create",
    ),

    path(
    "<int:pk>/",
    views.investigation_detail,
    name="detail",
),
]