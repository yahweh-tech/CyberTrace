from .models import Investigation
from timeline.services import TimelineService

class InvestigationService:

    @staticmethod
    def create_investigation(user, form):

        investigation = form.save(commit=False)

        investigation.investigator = user

        investigation.save()
        TimelineService.log(investigation,user,"Investigation Created",f"Case '{investigation.title}' was created.")

        return investigation