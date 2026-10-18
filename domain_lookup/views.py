from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from investigations.models import Investigation

from .forms import DomainLookupForm
from .services import DomainLookupService


@login_required
def lookup_domain(request, investigation_id):

    investigation = get_object_or_404(
        Investigation,
        id=investigation_id,
        investigator=request.user,
    )

    if request.method == "POST":
        form = DomainLookupForm(request.POST)

        if form.is_valid():
            DomainLookupService.save_lookup(
                investigation=investigation,
                domain=form.cleaned_data["domain"],
                user=request.user,
            )

            messages.success(request, "Domain lookup completed successfully.")

            return redirect("domain_lookup:results", investigation.id)

    else:
        initial = {}
        if "domain" in request.GET:
            initial["domain"] = request.GET.get("domain")
        form = DomainLookupForm(initial=initial)

    return render(
        request,
        "domain_lookup_search.html",
        {
            "form": form,
            "investigation": investigation,
        },
    )


@login_required
def lookup_results(request, investigation_id):

    investigation = get_object_or_404(
        Investigation,
        id=investigation_id,
        investigator=request.user,
    )

    lookup = investigation.domain_lookups.last()

    return render(
        request,
        "domain_lookup_result.html",
        {
            "investigation": investigation,
            "lookup": lookup,
        },
    )
