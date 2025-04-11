from django.db import models
from django.utils import timezone


class PricingPlan(models.Model):
    name = models.CharField(max_length=100)
    subtitle = models.CharField(max_length=100, blank=True)
    price = models.CharField(max_length=50)  
    billing_cycle = models.CharField(max_length=50, blank=True)  # e.g., /month
    features = models.TextField(help_text="Separate features with newline")
    cta_text = models.CharField(max_length=50, default="Get Started")
    is_popular = models.BooleanField(default=False)
    order = models.IntegerField(default=0)

    def feature_list(self):
        return self.features.strip().split('\n')

    def __str__(self):
        return self.name



class WaitingSubscriber(models.Model):
    email = models.EmailField(unique=True)
    subscribed_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.email

    class Meta:
        verbose_name = "Waiting Subscriber"
        verbose_name_plural = "Waiting Subscribers" 