from django import forms


class DomainLookupForm(forms.Form):

    domain = forms.CharField(
        max_length=255,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "example.com",
            }
        ),
    )

    def clean_domain(self):
        domain = self.cleaned_data["domain"].strip().lower()
        domain = domain.removeprefix("http://").removeprefix("https://").split("/")[0]
        if "." not in domain:
            raise forms.ValidationError("Enter a valid domain name.")
        return domain
