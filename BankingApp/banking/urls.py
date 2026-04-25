from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='index'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('deposit/', views.deposit_view, name='deposit'),
    path('withdraw/', views.withdraw_view, name='withdraw'),
    path('transactions/', views.transactions_view, name='transactions'),

    # V11 (CWE-639) IDOR — unauthenticated, any account_id accepted
    path('api/transactions/<int:account_id>/', views.public_transactions_api, name='public_transactions'),

    # V10 (CWE-943) NoSQL Injection endpoint
    path('api/filter/', views.transaction_filter_api, name='transaction_filter'),

    # V8/V9 (CWE-89 / CVE-2021-35042) SQL Injection in search
    path('admin-search/', views.account_search_view, name='account_search'),
]
