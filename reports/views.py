from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404

from investigations.models import Investigation

from .services import ReportService


@login_required
def export_csv(request, investigation_id):

    investigation = get_object_or_404(
        Investigation,
        id=investigation_id,
        investigator=request.user,
    )

    return ReportService.csv_response(investigation)
