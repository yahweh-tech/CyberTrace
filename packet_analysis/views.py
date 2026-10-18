from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from investigations.models import Investigation

from .forms import PacketAnalysisForm
from .services import PacketAnalysisError, PacketAnalysisService


@login_required
def analyze_packets(request, investigation_id):

    investigation = get_object_or_404(
        Investigation,
        id=investigation_id,
        investigator=request.user,
    )

    if request.method == "POST":
        form = PacketAnalysisForm(request.POST, request.FILES)

        if form.is_valid():

            try:
                PacketAnalysisService.save_analysis(
                    investigation=investigation,
                    pcap_file=form.cleaned_data["pcap_file"],
                    source_label=form.cleaned_data.get("source_label", ""),
                    user=request.user,
                )
            except PacketAnalysisError as exc:
                messages.error(
                    request,
                    f"Packet analysis failed: {exc}",
                )
                return render(
                    request,
                    "packet_analysis_search.html",
                    {
                        "form": form,
                        "investigation": investigation,
                    },
                )

            messages.success(request, "Packet capture analysis completed.")

            return redirect("packet_analysis:results", investigation.id)

    else:
        form = PacketAnalysisForm()

    return render(
        request,
        "packet_analysis_search.html",
        {
            "form": form,
            "investigation": investigation,
        },
    )


@login_required
def analysis_results(request, investigation_id):

    investigation = get_object_or_404(
        Investigation,
        id=investigation_id,
        investigator=request.user,
    )

    analysis = investigation.packet_analyses.last()

    return render(
        request,
        "packet_analysis_result.html",
        {
            "investigation": investigation,
            "analysis": analysis,
        },
    )
