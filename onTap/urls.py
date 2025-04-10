from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('shop', views.shop, name='shop'),
    path('pricing', views.pricing, name='pricing'),
    path('contact', views.contact_us, name='contact_us'),
    path('about', views.about_us, name='about_us'),

    # path('signup', views.signup, name='signup'),
    # path('login', views.login, name="login")

    path('dashboard', views.dashboard, name='dashboard'),
]