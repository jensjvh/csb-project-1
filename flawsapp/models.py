from django.db import models


class CustomUser(models.Model):
    username = models.CharField(max_length=30, unique=True)
    password = models.CharField(max_length=30)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return self.username


class Message(models.Model):
    user_id = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    content = models.TextField(
        max_length=300,
    )

    def __str__(self):
        return self.content
