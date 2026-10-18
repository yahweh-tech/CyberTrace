from django import forms

MAX_BINARY_SIZE = 35 * 1024 * 1024  # 35 MB limit for web triage


class BinaryUploadForm(forms.Form):
    source_label = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Optional label, e.g. payload_drop_stage2.exe",
            }
        ),
    )

    sample_file = forms.FileField(
        widget=forms.ClearableFileInput(
            attrs={
                "class": "form-control",
            }
        ),
        help_text="Upload any binary, executable (.exe, .dll, .elf, .bin, .sys) or script (max 35 MB).",
    )

    def clean_sample_file(self):
        uploaded = self.cleaned_data["sample_file"]
        if uploaded.size > MAX_BINARY_SIZE:
            raise forms.ValidationError("Binary file exceeds maximum allowed size (35 MB).")
        return uploaded
