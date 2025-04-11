from django.contrib import admin
from .models import PricingPlan, WaitingSubscriber


@admin.register(PricingPlan)
class PricingPlanAdmin(admin.ModelAdmin):
    list_display = ('name', 'price', 'billing_cycle', 'is_popular', 'order')
    ordering = ('order',)



@admin.register(WaitingSubscriber)
class WaitingSubscriberAdmin(admin.ModelAdmin):
    list_display = ('email', 'subscribed_at', 'is_active')
    search_fields = ('email',)
    list_filter = ('subscribed_at', 'is_active')
    date_hierarchy = 'subscribed_at'  