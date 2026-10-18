from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from investigations.models import Investigation
from .forms import BinaryUploadForm
from .models import BinaryAnalysis
from .services import BinaryAnalysisError, ReverseEngineeringService


@login_required
def upload_and_analyze(request, investigation_id):
    investigation = get_object_or_404(
        Investigation,
        id=investigation_id,
        investigator=request.user,
    )

    if request.method == "POST":
        form = BinaryUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                analysis = ReverseEngineeringService.save_analysis(
                    investigation=investigation,
                    sample_file=form.cleaned_data["sample_file"],
                    source_label=form.cleaned_data.get("source_label", ""),
                    user=request.user,
                )
                messages.success(request, f"Binary triage complete for {analysis.file_name}!")
                return redirect("reverse_engineering:results", investigation.id, analysis.id)
            except BinaryAnalysisError as err:
                messages.error(request, f"Analysis error: {err}")
            except Exception as err:
                messages.error(request, f"Unexpected error while analyzing file: {err}")
    else:
        form = BinaryUploadForm()

    recent_samples = investigation.binary_analyses.all()[:5]

    return render(
        request,
        "reverse_engineering_upload.html",
        {
            "form": form,
            "investigation": investigation,
            "recent_samples": recent_samples,
        },
    )


@login_required
def analysis_results(request, investigation_id, analysis_id=None):
    investigation = get_object_or_404(
        Investigation,
        id=investigation_id,
        investigator=request.user,
    )

    if analysis_id:
        analysis = get_object_or_404(
            BinaryAnalysis,
            id=analysis_id,
            investigation=investigation,
        )
    else:
        analysis = investigation.binary_analyses.first()

    all_analyses = investigation.binary_analyses.all()

    return render(
        request,
        "reverse_engineering_result.html",
        {
            "investigation": investigation,
            "analysis": analysis,
            "all_analyses": all_analyses,
        },
    )
