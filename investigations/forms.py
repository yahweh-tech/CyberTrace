from django import forms

from .models import Investigation


class InvestigationForm(forms.ModelForm):

    class Meta:
        model = Investigation

        fields = [
            "title",
            "description",
            "status",
        ]

        widgets = {
            "title": forms.TextInput(attrs={
                "class": "form-control",
            }),

            "description": forms.Textarea(attrs={
                "class": "form-control",
                "rows": 4,
            }),

            "status": forms.Select(attrs={
                "class": "form-select",
            }),
        }