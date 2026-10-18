from django import forms


class IPLookupForm(forms.Form):

    ip_address = forms.GenericIPAddressField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "192.168.1.1",
            }
        ),
    )
