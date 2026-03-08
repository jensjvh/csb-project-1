import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "owaspflaws.settings")
django.setup()

from flawsapp.models import CustomUser

username = "admin"
password = "admin123"

if CustomUser.objects.filter(username=username).exists():
    print(f'Admin user already exists')
else:
    user = CustomUser.objects.create(
        username=username,
        password=password,
        is_admin=True
    )
    user.save()
    print(f'Successfully created admin user {username} with password {password}')