from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from investigations.models import Investigation


@login_required
def dashboard(request):

    investigations = Investigation.objects.filter(
        investigator=request.user
    )

    context = {
        "total_investigations": investigations.count(),
        "pending": investigations.filter(status="PENDING").count(),
        "in_progress": investigations.filter(status="IN_PROGRESS").count(),
        "completed": investigations.filter(status="COMPLETED").count(),
        "recent_investigations": investigations.order_by("-created_at")[:5],
    }

    return render(
        request,
        "dashboard.html",
        context,
    )