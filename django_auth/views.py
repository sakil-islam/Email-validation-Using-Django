from django.db import models
from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from django.contrib.auth.models import User
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django_auth import models
from django.contrib.auth.mixins import LoginRequiredMixin
from rest_framework.views import APIView
from datetime import timezone
from django.shortcuts import render
from rest_framework.parsers import DataAndFiles, JSONParser
from .models import Input_data
from .serializers import Input_dataSerializer
from rest_framework import status
from rest_framework import serializers
from rest_framework.response import Response


# Create your views here.


# create register page
class RegistrationView(View):
    def get(self, request):
        return render(request, 'auth/register.html')

    def post(self, request):
        context = {

            'data': request.POST,
            'has_error': False
        }

        email = request.POST.get('email')
        username = request.POST.get('username')
        full_name = request.POST.get('name')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        if len(password) < 6:
            messages.add_message(request, messages.ERROR,
                                 'passwords should be atleast 6 characters long')
            context['has_error'] = True
        if password != password2:
            messages.add_message(request, messages.ERROR,
                                 'passwords dont match')
            context['has_error'] = True
        try:
            if User.objects.get(email=email):
                messages.add_message(request, messages.ERROR, 'Email is taken')
                context['has_error'] = True

        except Exception as identifier:
            pass

        try:
            if User.objects.get(username=username):
                messages.add_message(
                    request, messages.ERROR, 'Username is taken')
                context['has_error'] = True

        except Exception as identifier:
            pass
        if context['has_error']:
            return render(request, 'auth/register.html', context, status=400)

        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.first_name = full_name
        user.last_name = full_name
        user.is_active = True
        user.save()

        messages.add_message(request, messages.SUCCESS,
                             'Account created successfully')

        return redirect('login')

# create login page


class LoginView(View):
    def get(self, request):
        return render(request, 'auth/login.html')

    def post(self, request):
        context = {
            'data': request.POST,
            'has_error': False
        }
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username == '':
            messages.add_message(request, messages.ERROR,
                                 'Username is required')
            context['has_error'] = True
        if password == '':
            messages.add_message(request, messages.ERROR,
                                 'Password is required')
            context['has_error'] = True
        user = authenticate(request, username=username, password=password)

        if not user and not context['has_error']:
            messages.add_message(request, messages.ERROR, 'Invalid login')
            context['has_error'] = True

        if context['has_error']:
            return render(request, 'auth/login.html', status=401, context=context)
        login(request, user)
        return redirect('home')

# create home page view all section in home page


class HomeView(LoginRequiredMixin, APIView):
    def get(self, request):
        state = False
        return render(request, 'home.html', {'state': state})

    def post(self, request):
        result = False
        state = True
        data = ''
        if 'submit' in request.POST:
            input_text = request.POST['value_input']
            search_text = request.POST['search_input']
            input_list = input_text.split(",")
            input_list.sort(reverse=True)
            myModel = models.Input_data()
            myModel.input_values = input_list
            myModel.save()
            if search_text in input_list:
                result = True

        elif 'data_find' in request.POST:
            start = request.POST['start_timestamp']
            end = request.POST['end_timestamp']
            users = models.Input_data.objects.filter(
                timestamp__range=(start, end))

            serial = Input_dataSerializer(users, many=True)

            return Response({"status": "success", "user_id": request.user.id, "payloads": serial.data}, status=status.HTTP_200_OK)
        return render(request, 'home.html', {'result': result, 'state': state, 'data': data})


# logout successfully and redirect to login page
class LogoutView(View):
    def get(self, request):
        logout(request)
        messages.add_message(request, messages.SUCCESS, 'Logout successfully')
        return redirect('login')
