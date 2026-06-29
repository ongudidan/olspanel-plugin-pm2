from django.urls import path
from . import views

urlpatterns = [
    path('gui/', views.gui_view, name='pm2_gui'),
    path('install/', views.install_pm2_view, name='pm2_install'),
    path('add/', views.add_app_view, name='pm2_add'),
    path('create/', views.create_app_view, name='pm2_create'),
    path('action/<int:app_id>/', views.action_view, name='pm2_action'),
    path('env/<int:app_id>/', views.save_env_view, name='pm2_env'),
    path('logs/<str:app_name>/', views.logs_view, name='pm2_logs'),
]
