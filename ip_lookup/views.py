from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from investigations.models import Investigation

from .forms import IPLookupForm
from .services import IPLookupService


@login_required
def lookup_ip(request, investigation_id):

    investigation = get_object_or_404(
        Investigation,
        id=investigation_id,
        investigator=request.user,
    )

    if request.method == "POST":
        form = IPLookupForm(request.POST)

        if form.is_valid():
            IPLookupService.save_lookup(
                investigation=investigation,
                ip_address=form.cleaned_data["ip_address"],
                user=request.user,
            )

            messages.success(request, "IP lookup completed successfully.")

            return redirect("ip_lookup:results", investigation.id)

    else:
        initial = {}
        if "ip" in request.GET:
            initial["ip_address"] = request.GET.get("ip")
        form = IPLookupForm(initial=initial)

    return render(
        request,
        "ip_lookup_search.html",
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

    lookup = investigation.ip_lookups.last()

    return render(
        request,
        "ip_lookup_result.html",
        {
            "investigation": investigation,
            "lookup": lookup,
        },
    )
