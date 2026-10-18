from django import forms


class NumberLookupForm(forms.Form):

    phone_number = forms.CharField(
        max_length=20,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "+919876543210",
            }
        ),
    )