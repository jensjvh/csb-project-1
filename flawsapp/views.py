from functools import wraps

from django.db import IntegrityError
from django.http import HttpResponse, HttpRequest, HttpResponseNotFound
from django.shortcuts import render, redirect
from django_ratelimit.decorators import ratelimit

from .models import CustomUser, Message
from .utils import check_password, encrypt_password

import logging
logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%d-%m-%Y %H:%M:%S')
logger = logging.getLogger(__name__)


def require_login(func):
    @wraps(func)
    def wrapped_func(request, *args, **kwargs):
        if "user_id" not in request.session:
            return redirect("login")
        return func(request, *args, **kwargs)

    return wrapped_func

def check_is_admin(request):
    user_id = request.session["user_id"]
    user = CustomUser.objects.get(id=user_id)
    return user.is_admin


def index(request: HttpRequest):
    messages = []
    admin = False
    try:
        user_id = request.session["user_id"]
        user = CustomUser.objects.get(id=user_id)
        messages = Message.objects.all
        username = user.username
        admin = check_is_admin(request)
    except KeyError:
        username = None
    return render(
        request, "home.html", {"username": username, "messages": messages, "is_admin": admin}, status=200
    )


def register(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        username = request.POST.get("username", None)
        password = request.POST.get("password", None)
        ## Flaw 1: The password is saved as plain text to a database (AA07:2021 – Identification and Authentication Failures).
        try:
          user = CustomUser.objects.create(username=username, password=password)
          user.save()
          request.session["user_id"] = user.id
        ## Flaw 1 ends
        ## Fix 1: Hash the password and store it into a database.
        # password = encrypt_password(password)
        # try:
        #   user = CustomUser.objects.create(
        #       username=username, password=password.decode(encoding="utf-8")
        #   )
        #   user.save()
        #   request.session["user_id"] = user.id
        # except IntegrityError:
        #   return redirect("register")
        ## Also uncomment lines 94-97 to update the login method to use this.
        ## Fix 1 ends
        except IntegrityError:
            return redirect("register")
        return index(request)
    return render(request, "registration/register.html", status=201)


## Flaw 5: Logging in is not rate limited (A04:2021 Insecure Design)
@ratelimit(key='ip', rate='5/m', block=True, method='POSTx1')
def login(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        username = request.POST.get("username", None)
        raw_password = request.POST.get("password", None)

        try:
            ## Flaw 2: Raw SQL query is used for finding the desired user (A03:2021 Injection)
            query = f"SELECT * FROM flawsapp_customuser WHERE username = '{username}'"
            try:
              user = CustomUser.objects.raw(query)[0]
              password = user.password
              if password == raw_password:
                  request.session["user_id"] = user.id
                  return index(request)
              # password = user.password.encode('utf-8')
              # if check_password(password, raw_password):
              #     request.session["user_id"] = user.id
              #     return index(request)
            except IndexError:
              ## Flaw 3: Invalid logins are not logged, spam or brute force is hard to detect (A09:2021 - Security Logging and Monitoring Failures)
              ## Fix 3 starts
              # logger.info('User failed to log in')
              ## Fix 3 ends
              return render(request, "registration/login.html", {"message": "invalid username or password"})
              # Flaw 3 ends
            ## Flaw 2 ends
            ## Fix 2 starts
            # user = CustomUser.objects.get(username=username)
            # password = user.password.encode('utf-8')
            # if check_password(password, raw_password):
            #     request.session["user_id"] = user.id
            #     return index(request)
            ## Fix 2 ends
        except CustomUser.DoesNotExist:
            return HttpResponse("Unknown user")
    return render(request, "registration/login.html")


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

## Flaw 4: User view and deletion URLs are available to any user. (A01:2021 Broken Access Control)
@require_login
def users(request):
    # Fix 4: Check for admin status
    is_admin = check_is_admin(request)
    if not is_admin:
        return index(request)
    # Fix 4 ends
    users_list = CustomUser.objects.all()
    return render(request, "users.html", {"users": users_list})


@require_login
def delete_user(request, user_id):
    # Fix 4: Check for admin status
    is_admin = check_is_admin(request)
    if not is_admin:
        return index(request)
    # Fix 4 ends
    user = CustomUser.objects.get(id=user_id)
    user.delete()
    # This needs to be here to properly refresh the user list
    users_list = CustomUser.objects.all()
    return render(request, "users.html", {"users": users_list})
# Flaw 4 ends