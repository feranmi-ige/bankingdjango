from django.contrib import admin
from .models import Account

# V15: Admin interface exposed with default credentials admin/admin123
# No IP restriction, no MFA, accessible at /admin/
@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    list_display = ['user', 'account_number', 'balance', 'created_at']
    search_fields = ['account_number', 'user__username']
    list_per_page = 50
