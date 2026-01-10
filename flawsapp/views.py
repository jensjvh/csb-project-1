from functools import wraps

from django.db import IntegrityError
from django.http import HttpResponse, HttpRequest, HttpResponseNotFound
from django.shortcuts import render, redirect

from .models import CustomUser, Message
from .utils import check_password, encrypt_password


def require_login(func):
    @wraps(func)
    def wrapped_func(request, *args, **kwargs):
        if "user_id" not in request.session:
            return redirect("login")
        return func(request, *args, **kwargs)

    return wrapped_func


def index(request: HttpRequest):
    messages = []
    try:
        user_id = request.session["user_id"]
        user = CustomUser.objects.get(id=user_id)
        messages = Message.objects.all
        username = user.username
    except KeyError:
        username = None
    return render(
        request, "home.html", {"username": username, "messages": messages}, status=200
    )


def register(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        username = request.POST.get("username", None)
        password = request.POST.get("password", None)
        ## Flaw: The password is saved as plain text to a database (AA07:2021 – Identification and Authentication Failures).
        user = CustomUser.objects.create(username=username, password=password)
        user.save()
        ## Flaw ends
        ## Fix: Hash the password and store it into a database.
        # password = encrypt_password(password)
        # try:
        #   user = CustomUser.objects.create(
        #       username=username, password=password.decode(encoding="utf-8")
        #   )
        #   user.save()
        # except IntegrityError:
        #   return redirect("register")
        ## Fix ends
        return index(request)
    return render(request, "registration/register.html", {"key": "value"}, status=201)


def login(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        username = request.POST.get("username", None)
        raw_password = request.POST.get("password", None)

        try:
            ## Flaw starts: Raw SQL query is used for finding the desired user (A03:2021 – Injection)
            query = f"SELECT * FROM flawsapp_customuser WHERE username = '{username}'"
            try:
              user = CustomUser.objects.raw(query)[0]
            except IndexError:
              return HttpResponse("No users exist")
            ## Fix:
            # user = CustomUser.objects.get(username=username)
            password = user.password.encode('utf-8')
            if check_password(password, raw_password):
                request.session["user_id"] = user.id
                return index(request)
        except CustomUser.DoesNotExist:
            return HttpResponse("Unknown user")
    return render(request, "registration/login.html", {"key": "value"})


def logout(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        try:
            del request.session["user_id"]
        except KeyError:
            return HttpResponseNotFound("You are not logged in")
    return index(request)


@require_login
def create_message(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        try:
            user_id = request.session["user_id"]
            content = request.POST.get("message", "")
            user = CustomUser.objects.get(id=user_id)
            message = Message.objects.create(user_id=user, content=content)
            print(message)
        except KeyError:
            return HttpResponseNotFound("You are not logged in")
    return index(request)


@require_login
def secret(request):
    users = CustomUser.objects.all()
    return render(request, "secret.html", {"users": users})
