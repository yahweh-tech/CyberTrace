from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from investigations.models import Investigation

from .forms import NumberLookupForm
from .services import NumberLookupError, NumberLookupService


@login_required
def lookup_number(request, investigation_id):

    investigation = get_object_or_404(
        Investigation,
        id=investigation_id,
        investigator=request.user,
    )

    if request.method == "POST":

        form = NumberLookupForm(request.POST)

        if form.is_valid():

            try:
                NumberLookupService.save_lookup(
                    investigation=investigation,
                    phone_number=form.cleaned_data["phone_number"],
                    user=request.user,
                )
            except NumberLookupError as exc:
                messages.error(
                    request,
                    f"Phone lookup failed: {exc}",
                )
                return render(
                    request,
                    "number_lookup_search.html",
                    {
                        "form": form,
                        "investigation": investigation,
                    },
                )

            messages.success(
                request,
                "Phone lookup completed successfully."
            )

            return redirect(
                "number_lookup:results",
                investigation.id,
            )

    else:

        form = NumberLookupForm()

    return render(
        request,
        "number_lookup_search.html",
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

    lookup = investigation.number_lookups.last()

    return render(
        request,
        "number_lookup_result.html",
        {
            "investigation": investigation,
            "lookup": lookup,
        },
    )