from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name="index"),
    path('about/', views.about_us, name="about_us"),
    path('contact/', views.contact, name="contact"),
    # Accounts
    path('accounts/admin/', admin.site.urls),
    path('accounts/login/', views.auth_login, name="auth_login"),
    path('accounts/logout/', views.MyLogoutView.as_view(), name='logout'),
]