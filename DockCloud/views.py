from .custom_decorators import *
from .forms import *
from .models import *
from base64 import urlsafe_b64encode, urlsafe_b64decode
from hashlib import sha3_512
from io import BytesIO
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordResetConfirmView, LogoutView
from django.contrib import messages
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseRedirect, HttpResponseBadRequest
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.encoding import force_bytes
import qrcode, datetime, time




def index(request):
    Articles = Article.objects.all()
    context = {'title': 'Home'}
    return render(request, 'index.jinja', context, using='jinja2')


def about_us(request):
    Articles = Article.objects.all()
    context = {'title': 'About Us'}
    return render(request, 'about-us.jinja', context, using='jinja2')

def page_not_found(request, exception):
    context = {"title": "Page Not Found"}
    return render(request, 'error-404.jinja', context,status=404, using='jinja2')


class MyLogoutView(LogoutView):
    next_page = reverse_lazy('auth_login')

    def get_next_url(self):
        return self.next_page


def newsletter(request):
    if request.method == "POST":
        if 'email' in request.POST:
            context = {
                "message" : "Thank you, you will receive all new updates on your email now..."
            }
        else:
            context = {
                "message" : "Please enter a valid email..."
            }
    else:
        context = {
            "message" : "Invalid request method..."
        }

    return render(request, 'index.jinja', context, using='jinja2')


def contact(request):
    if request.method == "POST":
        if len(request.POST["name"]) > 0 and request.POST["email"] is not None and request.POST["subject"] is not None and request.POST["phone"] is not None and request.POST["message"] is not None:
            context = {
                "message": "we have received your message, our team will review it and contact you as soon as possible", "color": "chartreuse", "title": "Contact Us"}
            return render(request, 'contact.jinja', context, using='jinja2')
        else:
            context = {
                "message": "an error has occured... please check your submission and try again.", "color": "red", "title": "Contact Us"}
            return render(request, 'contact.jinja', context, using='jinja2')
    context = {"title": "Contact Us"}
    return render(request, 'contact.jinja', context, using='jinja2')


def account_register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            # process the form data
            user = form.save(commit=False)
            # create security questions hashes
            user.security_q1 = sha3_512(user.security_q1.encode('utf-8')).hexdigest()
            user.security_q2 = sha3_512(user.security_q2.encode('utf-8')).hexdigest()
            user.security_q3 = sha3_512(user.security_q3.encode('utf-8')).hexdigest()
            # save the user
            user.save()
            return redirect(reverse('account_login'))
        else:
            # form is not valid
            context = {"title": "Account Register", "form": form}
    else:
        form = FreelancerCreationForm()
        context = {"title": "Account Register", "form": form}
    return render(request, 'register.jinja', context, using='jinja2')


def account_login(request):
    if request.method == 'POST':
        # check if account is deactivated
        if CustomUser.objects.filter(username=request.POST["username"]):
            user = CustomUser.objects.get(username=request.POST["username"])
            if not user.is_active:
                form = AuthenticationForm()
                messages.error(request, "Sorry, this account is not activated and can not be authenticated!.")
                return render(request, 'login.jinja', {'form': form, 'title': 'Login'}, using='jinja2')

        # check creds
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                user.reset_failed_login_attempts()
                if 'next' in request.GET:
                    return HttpResponseRedirect(request.GET["next"])
                return redirect(reverse('profile'))

        else:
            # if the user account exists --> increase the "failed_login_attempts"
            try:
                user = CustomUser.objects.get(
                    username=request.POST["username"])
                user.increment_failed_login_attempts()
                if user.failed_login_attempts == 10:
                    messages.error(request, "Due to multiple bad login attempts, we have deactivated your account...")
                    messages.error(request, "To re-activate your account you have to provide the valid security answers for your account.")
                    return redirect(reverse('account_recovery'))

            except ObjectDoesNotExist:
                pass
    else:
        form = AuthenticationForm()
    return render(request, 'login.jinja', {'form': form, 'title': 'Login'}, using='jinja2')


def account_recovery(request):
    if request.method == 'POST':
        # check if form is valid and user exists in the database
        user = CustomUser.objects.filter(username=request.POST['username'])
        if user.exists():
            # transfer from QuerySet to CustomUser object
            user = user.get()
            # Create a separate instance of the CustomUser object for checking the security question answers because we can not use the
            # "user" variable while there is `user.save()`
            user_for_checking = CustomUser.objects.get(pk=user.pk)

            form = SecurityQuestionsForm(request.POST, instance=user_for_checking)
            if form.is_valid():         
                if user_for_checking.check_security_answers(form.cleaned_data['security_q1'], form.cleaned_data['security_q2'], form.cleaned_data['security_q3']):
                    # User's security question answers are correct
                    # re-activate user account
                    user.is_active = True
                    user.save()
                    # generate a uid and password reset token to allow the user to change his password
                    uid = urlsafe_b64encode(force_bytes(user.pk)).decode()
                    token = default_token_generator.make_token(user)
                    return HttpResponseRedirect("/accounts/password_reset/" + uid + "/" + token + "/")
                else:
                    # User's security question answers are incorrect
                    messages.error(request, 'Incorrect security answers!.')
            else:
                errors = form.errors.as_data()
                for field, error_list in errors.items():
                    for error in error_list:
                        messages.error(request, error.message)
        else:
            messages.error(request, 'Invalid username.')

    form = SecurityQuestionsForm()
    context = {
    'title' : 'Account Recovery',
    'form' : form,
    }
    return render(request, 'account-recovery.jinja', context, using='jinja2')


@login_required
def profile(request):
    if request.method == 'POST':
        user = CustomUser.objects.get(id=request.user.id)
        form = UserProfileForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your profile has been updated successfully.')
            # returning to the function will render the profile page again with the updates accquired
            return redirect('profile')
    else:
        user = CustomUser.objects.get(id=request.user.id)
        form = UserProfileForm(instance=user)
    context = {
        'form': form,
        'title': 'My Profile',
        'user': user,
    }
    return render(request, 'my-profile.jinja', context, using="jinja2")


@login_required
def reset_security_questions(request):
    user = request.user
    form = SecurityQuestionsForm(request.POST or None)
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        if authenticate(username=user.username, password=current_password):
            if form.is_valid():
                user.security_q1 = sha3_512(form.cleaned_data['security_q1'].encode('utf-8')).hexdigest()
                user.security_q2 = sha3_512(form.cleaned_data['security_q2'].encode('utf-8')).hexdigest()
                user.security_q3 = sha3_512(form.cleaned_data['security_q3'].encode('utf-8')).hexdigest()
                user.save()
                messages.success(
                    request, 'Security questions updated successfully.')
        else:
            messages.error(request, 'Incorrect Password.')
    context = {
        'form': form,
        'title': 'Update Security Questions',
     }
    return render(request, 'reset-security-questions.jinja', context, using="jinja2")


@login_required
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        user = authenticate(username=request.user.username, password=current_password)
        if user is not None:
            # generate a uid and password reset token to allow the user to change his password
            uid = urlsafe_b64encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            return HttpResponseRedirect("/accounts/password_reset/" + uid + "/" + token + "/")
        else:
            messages.error(request, "Incorrect Password...!")

    return redirect(reverse('profile'))


@login_required
def delete_account(request):
    user = request.user
    if request.method == 'POST':
        current_password = request.POST.get('password')
        if authenticate(username=user.username, password=current_password):
            user.delete()
            messages.success(request, 'Your Account deleted successfully!')
            return HttpResponseRedirect('/accounts/logout/')
        else:
            messages.error(request, 'Incorrect Password.')

    return render(request, 'delete-account.jinja', {'title': 'DELETE ACCOUNT'}, using="jinja2")