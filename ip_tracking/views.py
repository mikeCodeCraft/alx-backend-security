from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/m', block=True, method='GET')
@ratelimit(key='ip', rate='10/m', block=True, method='POST')
def login_view(request):
    if request.method == "POST":
        return HttpResponse("Login attempt...")
    return HttpResponse("Login page")


from django.shortcuts import render
from django.http import HttpResponse

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        ip = get_client_ip(request)
        print(f"Login attempt from IP: {ip}, Username: {username}")

        return HttpResponse("Login attempt recorded.")

    return render(request, "login.html")


def get_client_ip(request):
    # This checks for X-Forwarded-For header first (for proxies)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
