from django.urls import path, include

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.login, name="login"),
    path("register/", views.register, name="register"),
    path("logout/", views.logout, name="logout"),
    path("users/", views.users, name="users"),
    path("users/delete_user/<int:user_id>", views.delete_user, name="delete_user"),
    path("create_message/", views.create_message, name="create_message"),
]
