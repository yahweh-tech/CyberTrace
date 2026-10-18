from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404

from reports.services import ReportService

from .forms import InvestigationForm
from .models import Investigation
from .services import InvestigationService
from django.contrib import messages


@login_required
def investigation_list(request):

    investigations = Investigation.objects.filter(
        investigator=request.user
    ).order_by("-created_at")

    context = {
        "investigations": investigations,
    }

    return render(
        request,
        "inves_list.html",
        context,
    )


@login_required
def investigation_create(request):

    if request.method == "POST":

        form = InvestigationForm(request.POST)

        if form.is_valid():

            InvestigationService.create_investigation(
                request.user,
                form,
            )

            messages.success(
                request,
                "Investigation created successfully."
            )

            return redirect("investigations:list")

    else:

        form = InvestigationForm()

    context = {
        "form": form,
    }

    return render(
        request,
        "inves_create.html",
        context,
    )

@login_required
def investigation_detail(request, pk):

    investigation = get_object_or_404(
        Investigation,
        pk=pk,
        investigator=request.user,
    )

    context = {
        "investigation": investigation,
        "number_lookup": investigation.number_lookups.last(),
        "ip_lookup": investigation.ip_lookups.last(),
        "domain_lookup": investigation.domain_lookups.last(),
        "packet_analysis": investigation.packet_analyses.last(),
        "binary_analysis": investigation.binary_analyses.first(),
        "atlas_assessment": investigation.atlas_assessments.last(),
        "timeline_events": investigation.timeline.all()[:10],
        "has_report_data": ReportService.has_data(investigation),
    }

    return render(
        request,
        "inves_detail.html",
        context,
    )