from django.shortcuts import render, redirect
from .models import PricingPlan



def home(request):
    return render(request, 'home.html')


def dashboard(request):
    return render(request, 'dashboard.html')    


def contact_us(request):
    return render(request, 'contact_us.html')


def about_us(request):
    return render(request, 'about_us.html')

# shop cards
def shop(request):
    return render(request, 'shop.html')


# pricing 

# def pricing(request):
#     pricing_plans = PricingPlan.objects.all().order_by('order')
#     context = {
#         'pricing_plans': pricing_plans
#     }
#     return render(request, 'pricing.html', context)




def pricing(request):
    plans = PricingPlan.objects.all().order_by('order')
    return render(request, 'pricing.html', {'plans': plans})



# registration
# def signup(request):
#     return render(request, 'registration/signup.html')

# def login(request):
#     return render(request, 'registration/login.html')    









