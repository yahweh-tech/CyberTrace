from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("dashboard.urls")),
    path("accounts/", include("accounts.urls")),
    path("investigations/", include("investigations.urls")),
    path("number-lookup/", include("number_lookup.urls")),
    path("ip-lookup/", include("ip_lookup.urls")),
    path("domain-lookup/", include("domain_lookup.urls")),
    path("packet-analysis/", include("packet_analysis.urls")),
    path("reports/", include("reports.urls")),
    path("atlas/", include("mitre_atlas.urls")),
    path("reverse-engineering/", include("reverse_engineering.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)