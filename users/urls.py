from django.urls import path
from . import views
urlpatterns = [
    path('signup/', views.SignUpView.as_view()),
    path('login/', views.LoginView.as_view()),
    path('logout/', views.LogoutView.as_view()),
    path('profil_update/', views.UpdatePofileView.as_view()),
    path('profil/', views.ProfileView.as_view()),
    path('password_update/', views.ChangePasswordView.as_view()),
    path('login_refresh/', views.LoginRefreshView.as_view()),
    ]