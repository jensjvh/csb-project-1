from django.urls import path, include

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.login, name="login"),
    path("register/", views.register, name="register"),
    path("logout/", views.logout, name="logout"),
    path("secret/", views.secret, name="secret"),
    path("create_message/", views.create_message, name="create_message"),
]
