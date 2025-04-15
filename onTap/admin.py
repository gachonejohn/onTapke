from django.contrib import admin
from .models import PricingPlan, WaitingSubscriber


# @admin.register(PricingPlan)
# class PricingPlanAdmin(admin.ModelAdmin):
#     list_display = ('name', 'price', 'billing_cycle', 'is_popular', 'order')
#     ordering = ('order',)


@admin.register(PricingPlan)
class PricingPlanAdmin(admin.ModelAdmin):
    list_display = ('name', 'price', 'billing_cycle', 'yearly_price', 'yearly_billing_cycle', 'is_popular', 'order')
    ordering = ('order',)
    fieldsets = (
        (None, {
            'fields': ('name', 'subtitle', 'is_popular', 'order')
        }),
        ('Monthly Pricing', {
            'fields': ('price', 'billing_cycle')
        }),
        ('Yearly Pricing', {
            'fields': ('yearly_price', 'yearly_billing_cycle')
        }),
        ('Details', {
            'fields': ('features', 'cta_text')
        }),
    )



@admin.register(WaitingSubscriber)
class WaitingSubscriberAdmin(admin.ModelAdmin):
    list_display = ('email', 'subscribed_at', 'is_active')
    search_fields = ('email',)
    list_filter = ('subscribed_at', 'is_active')
    date_hierarchy = 'subscribed_at'  