from django import forms

ALLOWED_EXTENSIONS = (".pcap", ".pcapng", ".cap")
MAX_UPLOAD_SIZE = 25 * 1024 * 1024  # 25 MB


class PacketAnalysisForm(forms.Form):

    source_label = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Optional label, e.g. suspect-router-capture",
            }
        ),
    )

    pcap_file = forms.FileField(
        widget=forms.ClearableFileInput(
            attrs={
                "class": "form-control",
                "accept": ".pcap,.pcapng,.cap",
            }
        ),
        help_text="Upload a .pcap / .pcapng / .cap file (max 25 MB).",
    )

    def clean_pcap_file(self):
        uploaded = self.cleaned_data["pcap_file"]

        name = uploaded.name.lower()
        if not name.endswith(ALLOWED_EXTENSIONS):
            raise forms.ValidationError(
                "Unsupported file type. Upload a .pcap, .pcapng, or .cap file."
            )

        if uploaded.size > MAX_UPLOAD_SIZE:
            raise forms.ValidationError("File is too large (max 25 MB).")

        return uploaded
