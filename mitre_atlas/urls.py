from django.urls import path
from . import views

app_name = "mitre_atlas"

urlpatterns = [
    path("matrix/", views.matrix_view, name="matrix"),
    path("api/technique/<str:code>/", views.technique_detail_api, name="technique_detail_api"),
    path("api/analyze-payload/", views.analyze_payload_api, name="analyze_payload_api"),
    path("api/correlate-case/<int:investigation_id>/", views.correlate_case_api, name="correlate_case_api"),
    path("investigation/<int:investigation_id>/assess/", views.assessment_create, name="assessment_create"),
    path("assessment/<int:pk>/", views.assessment_detail, name="assessment_detail"),
]
