# # signals.py
# from django.db.models.signals import post_save
# from django.dispatch import receiver
# from django.contrib.auth import get_user_model
# from .models import UserAuthentication

# User = get_user_model()

# @receiver(post_save, sender=User)
# def create_auth_profile(sender, instance, created, **kwargs):
#     if created:
#         UserAuthentication.objects.create(user=instance)

# @receiver(post_save, sender=User)
# def save_auth_profile(sender, instance, **kwargs):
#     try:
#         instance.auth_profile.save()
#     except UserAuthentication.DoesNotExist:
#         UserAuthentication.objects.create(user=instance)