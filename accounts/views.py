from django.contrib.auth import login, logout
from django.shortcuts import render, redirect

from .forms import LoginForm


def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard:dashboard")

    if request.method == "POST":
        form = LoginForm(request, data=request.POST)

        if form.is_valid():
            login(request, form.get_user())
            return redirect("dashboard:dashboard")
    else:
        form = LoginForm()

    return render(request, "login.html", {"form": form})


def logout_view(request):
    logout(request)
    return redirect("accounts:login")