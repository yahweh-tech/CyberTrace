from django import forms
from .models import AtlasAssessment, AtlasTechnique


class AtlasAssessmentForm(forms.ModelForm):
    selected_techniques = forms.ModelMultipleChoiceField(
        queryset=AtlasTechnique.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False,
    )

    class Meta:
        model = AtlasAssessment
        fields = [
            "system_name",
            "system_type",
            "incident_payload",
            "notes",
        ]
        widgets = {
            "system_name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "e.g. Enterprise RAG Chatbot, LLM Agent Assistant, Vision OCR Engine",
                }
            ),
            "system_type": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
            "incident_payload": forms.Textarea(
                attrs={
                    "class": "form-control font-monospace",
                    "rows": 4,
                    "placeholder": "Paste observed attack prompt, jailbreak query, model deserialization trace, or log excerpt...",
                }
            ),
            "notes": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 3,
                    "placeholder": "Add analyst observations, impacted assets, or operational scope...",
                }
            ),
        }
