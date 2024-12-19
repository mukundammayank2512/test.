import random
from twilio.rest import Client
from django.conf import settings
from functools import wraps
from django.http import JsonResponse, HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden

def generate_otp():
    """Generate a random 6-digit OTP."""
    return str(random.randint(100000, 999999))


def send_otp_sms(phone_number, otp):
    """
    Send an OTP via SMS to the given phone number.
    phone_number: The recipient's phone number (e.g., "+1234567890").
    otp: The OTP to send.
    """
    account_sid = settings.TWILIO_ACCOUNT_SID  # Replace with your Twilio Account SID
    auth_token = settings.TWILIO_PHONE_NUMBER    # Replace with your Twilio Auth Token
    twilio_phone_number = settings.TWILIO_PHONE_NUMBER  # Replace with your Twilio number

    client = Client(account_sid, auth_token)
    # print("##### ", ' ', client)

    message = f"Your login OTP is: {otp}"
    try:
        client.messages.create(
            to=phone_number,            # Recipient's phone number
            from_=twilio_phone_number,  # Twilio phone number
            body=message,               # Message content
        )
        print("Message sent successfully!")
    except Exception as e:
        print(f"Failed to send message: {e}")

def role_required(allowed_roles):
    """
    Decorator to restrict access based on user roles.
    :param allowed_roles: List of roles allowed to access the view.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            user = request.user
            print(user)
            print(allowed_roles)
            if user.role in allowed_roles:
                return view_func(request, *args, **kwargs)
            return JsonResponse({"error": "Access denied: Insufficient permissions"}, status=403)
        return wrapper
    return decorator



def require_https(view_func):
    """
    Custom decorator to enforce HTTPS requests.
    """
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if not request.is_secure():
            return HttpResponseForbidden("HTTPS is required.")
        return view_func(request, *args, **kwargs)
    return wrapped_view
