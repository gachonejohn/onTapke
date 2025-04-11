from django.shortcuts import render, redirect
from .models import PricingPlan
from .forms import ContactForm, WaitingSubscriptionForm 
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings


def home(request):
    return render(request, 'home.html')


def dashboard(request):
    return render(request, 'dashboard.html')    


# def contact_us(request):
#     return render(request, 'contact_us.html')


def contact_us(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            # Extract form data
            name = form.cleaned_data['name']
            email = form.cleaned_data['email']
            message = form.cleaned_data['message']
            
            try:
                # Email to site admin
                send_mail(
                    subject=f'New Contact Form Submission from {name}',
                    message=f'Name: {name}\nEmail: {email}\n\nMessage:\n{message}',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[settings.CONTACT_EMAIL],
                    fail_silently=False,
                )
                
                # Optional: Send confirmation email to user
                send_mail(
                    subject='Thank you for contacting us',
                    message=f'Dear {name},\n\nThank you for contacting us. We have received your message and will get back to you shortly.\n\nBest regards,\nAdpro team',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False,
                )
                
                # Add success message
                messages.success(request, 'Your message has been sent successfully!')
                return redirect('contact_success')
            
            except Exception as e:
                # Log the error (in a real app)
                print(f"Error sending email: {e}")
                messages.error(request, 'There was an error sending your message. Please try again later.')
    else:
        form = ContactForm()
    
    return render(request, 'contact_us.html', {'form': form})

def contact_success(request):
    return render(request, 'contact_success.html')
    


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









def subscribe_view(request):
    
    if request.method == 'POST':
        form = WaitingSubscriptionForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            
            # Save the subscriber
            form.save()
            

            subject = 'New Waiting email'
            message = f'A new user has subscribed to the waiting list: {email}'
            admin_email = settings.CONTACT_EMAIL  
            
            try:
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [admin_email],
                    fail_silently=True,
                )
                messages.success(request, 'Thank you for Joining our waiting list!')
            except Exception as e:
                messages.error(request, 'There was an error joining the list. Please try again.')
                print(f"Email error: {e}")
   
            return redirect(request.path)
    else:
        form = WaitingSubscriptionForm()
    
    return render(request, 'dashboard.html', {
        'form': form,
    })