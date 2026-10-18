from .models import TimelineEvent


class TimelineService:

    @staticmethod
    def log(
        investigation,
        user,
        event,
        description="",
    ):

        return TimelineEvent.objects.create(
            investigation=investigation,
            user=user,
            event=event,
            description=description,
        )