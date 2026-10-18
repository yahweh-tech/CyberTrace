import json
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from investigations.models import Investigation
from timeline.models import TimelineEvent

from .forms import AtlasAssessmentForm
from .models import AtlasAssessment, AtlasAssessmentTechnique, AtlasTactic, AtlasTechnique
from .services import AtlasService


@login_required
def matrix_view(request):
    """
    Global MITRE ATLAS interactive matrix explorer.
    """
    # Auto-seed if empty
    if not AtlasTactic.objects.exists() or not AtlasTechnique.objects.exists():
        AtlasService.seed_atlas_data()

    tactics = AtlasTactic.objects.prefetch_related("techniques").all()
    total_techniques = AtlasTechnique.objects.count()
    critical_count = AtlasTechnique.objects.filter(severity="CRITICAL").count()
    high_count = AtlasTechnique.objects.filter(severity="HIGH").count()

    context = {
        "tactics": tactics,
        "total_tactics": tactics.count(),
        "total_techniques": total_techniques,
        "critical_count": critical_count,
        "high_count": high_count,
    }
    return render(request, "mitre_atlas/matrix.html", context)


@login_required
def technique_detail_api(request, code):
    """
    JSON API returning rich metadata for a specific MITRE ATLAS technique.
    """
    tech = get_object_or_404(AtlasTechnique, code=code)
    data = {
        "code": tech.code,
        "name": tech.name,
        "tactic": tech.tactic.name,
        "tactic_code": tech.tactic.code,
        "attack_surface": tech.attack_surface,
        "severity": tech.severity,
        "severity_display": tech.get_severity_display(),
        "description": tech.description,
        "detection_guidance": tech.detection_guidance,
        "mitigation_guidance": tech.mitigation_guidance,
        "real_world_example": tech.real_world_example,
    }
    return JsonResponse(data)


@login_required
@require_POST
def analyze_payload_api(request):
    """
    AI Threat Triage endpoint:
    Scans a submitted prompt or payload and suggests matching ATLAS techniques.
    """
    try:
        data = json.loads(request.body)
        payload = data.get("payload", "")
    except Exception:
        payload = request.POST.get("payload", "")

    suggestions = AtlasService.analyze_payload(payload)
    results = [
        {
            "id": s["technique"].id,
            "code": s["technique"].code,
            "name": s["technique"].name,
            "severity": s["technique"].severity,
            "tactic": s["technique"].tactic.name,
            "confidence": s["confidence"],
            "reason": s["reason"],
        }
        for s in suggestions
    ]
    return JsonResponse({"results": results, "count": len(results)})


@login_required
def correlate_case_api(request, investigation_id):
    """
    JSON API that returns correlated IP, Domain, and Packet evidence with ATLAS suggestions.
    """
    investigation = get_object_or_404(
        Investigation,
        pk=investigation_id,
        investigator=request.user,
    )
    data = AtlasService.correlate_investigation_evidence(investigation)

    # Format techniques for JSON serialization
    serialized_techniques = [
        {
            "id": item["technique"].id,
            "code": item["technique"].code,
            "name": item["technique"].name,
            "severity": item["technique"].severity,
            "source": item["source"],
            "confidence": item["confidence"],
            "evidence": item["evidence"],
        }
        for item in data["correlated_techniques"]
    ]

    return JsonResponse({
        "correlated_techniques": serialized_techniques,
        "ip_evidence": data["ip_evidence"],
        "domain_evidence": data["domain_evidence"],
        "packet_evidence": data["packet_evidence"],
        "phone_evidence": data["phone_evidence"],
        "has_evidence": data["has_evidence"],
    })


@login_required
def assessment_create(request, investigation_id):
    """
    Create an AI Security Assessment for a specific investigation.
    """
    investigation = get_object_or_404(
        Investigation,
        pk=investigation_id,
        investigator=request.user,
    )

    # Ensure ATLAS data is seeded
    if not AtlasTactic.objects.exists():
        AtlasService.seed_atlas_data()

    tactics = AtlasTactic.objects.prefetch_related("techniques").all()
    case_evidence = AtlasService.correlate_investigation_evidence(investigation)

    if request.method == "POST":
        form = AtlasAssessmentForm(request.POST)
        if form.is_valid():
            assessment = form.save(commit=False)
            assessment.investigation = investigation

            selected_technique_ids = request.POST.getlist("selected_techniques")
            selected_techniques = list(
                AtlasTechnique.objects.filter(id__in=selected_technique_ids)
            )

            # Compute risk
            score, level = AtlasService.calculate_risk(selected_techniques)
            assessment.risk_score = score
            assessment.risk_level = level
            assessment.save()

            # Create technique mappings
            for tech in selected_techniques:
                status_key = f"status_{tech.id}"
                tech_status = request.POST.get(status_key, "SUSPECTED")
                notes_key = f"notes_{tech.id}"
                tech_notes = request.POST.get(notes_key, "")

                AtlasAssessmentTechnique.objects.create(
                    assessment=assessment,
                    technique=tech,
                    status=tech_status,
                    evidence_notes=tech_notes,
                )

            # Record timeline event
            TimelineEvent.objects.create(
                investigation=investigation,
                user=request.user,
                event="MITRE ATLAS AI Assessment Completed",
                description=(
                    f"Assessed AI system '{assessment.system_name}' ({assessment.get_system_type_display()}) "
                    f"with {len(selected_techniques)} ATLAS technique(s) mapped. Risk Level: {level} ({score}/100)."
                ),
            )

            messages.success(
                request,
                f"MITRE ATLAS AI Security Assessment generated successfully! Risk Level: {level}.",
            )
            return redirect("mitre_atlas:assessment_detail", pk=assessment.pk)
    else:
        form = AtlasAssessmentForm()

    context = {
        "form": form,
        "investigation": investigation,
        "tactics": tactics,
        "case_evidence": case_evidence,
    }
    return render(request, "mitre_atlas/assessment_form.html", context)


@login_required
def assessment_detail(request, pk):
    """
    Displays the AI security risk report, mapped ATLAS techniques, and mitigations.
    """
    assessment = get_object_or_404(
        AtlasAssessment,
        pk=pk,
        investigation__investigator=request.user,
    )
    mapped_techniques = assessment.mapped_techniques.select_related("technique", "technique__tactic").all()

    # Distinct tactics affected
    affected_tactics = {}
    for mt in mapped_techniques:
        tac = mt.technique.tactic
        if tac.code not in affected_tactics:
            affected_tactics[tac.code] = {
                "tactic": tac,
                "techniques": [],
            }
        affected_tactics[tac.code]["techniques"].append(mt)

    context = {
        "assessment": assessment,
        "investigation": assessment.investigation,
        "mapped_techniques": mapped_techniques,
        "affected_tactics": affected_tactics.values(),
        "ip_lookups": assessment.investigation.ip_lookups.all(),
        "domain_lookups": assessment.investigation.domain_lookups.all(),
        "packet_analyses": assessment.investigation.packet_analyses.all(),
        "number_lookups": assessment.investigation.number_lookups.all(),
    }
    return render(request, "mitre_atlas/assessment_detail.html", context)
