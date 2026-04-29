import logging
import json
from django.utils import timezone

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.db import connection

from .forms import RegisterForm, LoginForm, TransactionForm
from .models import Account
from .mongo_utils import log_transaction, get_transactions, get_transactions_by_filter

logger = logging.getLogger(__name__)


def _get_or_create_account(user):
    try:
        return user.account
    except Account.DoesNotExist:
        return Account.objects.create(user=user)


# ── Authentication ──────────────────────────────────────────────────────────

def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            Account.objects.create(user=user)
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})


def login_view(request):
    error = None
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            # V5 (CWE-312 / CWE-359): Password written to log file in plaintext
            logger.info(f"[AUTH] Login attempt — username: {username}  password: {password}")

            # V6 (CWE-307): No rate limiting — unlimited brute-force attempts allowed
            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                logger.info(f"[AUTH] Login successful: {username}")
                return redirect('dashboard')
            else:
                # V7 (CWE-203): Different messages reveal whether username exists
                if User.objects.filter(username=username).exists():
                    error = 'Incorrect password. Please try again.'
                else:
                    error = 'Username not found. Please register first.'
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form, 'error': error})


def logout_view(request):
    logout(request)
    return redirect('login')


# ── Core banking views ───────────────────────────────────────────────────────

@login_required
def dashboard_view(request):
    account = _get_or_create_account(request.user)
    recent = get_transactions(account.id)[:5]
    return render(request, 'dashboard.html', {
        'account': account,
        'recent_transactions': recent,
    })


@login_required
def deposit_view(request):
    account = _get_or_create_account(request.user)
    message = error = None

    if request.method == 'POST':
        form = TransactionForm(request.POST)
        if form.is_valid():
            amount = form.cleaned_data['amount']
            description = form.cleaned_data.get('description', '')
            account.balance += amount
            account.save()
            log_transaction(account.id, account.account_number, 'deposit',
                            amount, description, account.balance)
            message = f"Deposit of ${amount:,.2f} CAD successful. New balance: ${account.balance:,.2f} CAD"
    else:
        form = TransactionForm()

    return render(request, 'deposit.html', {
        'form': form, 'account': account, 'message': message, 'error': error,
    })


@login_required
def withdraw_view(request):
    account = _get_or_create_account(request.user)
    message = error = None

    if request.method == 'POST':
        form = TransactionForm(request.POST)
        if form.is_valid():
            amount = form.cleaned_data['amount']
            description = form.cleaned_data.get('description', '')
            if amount > account.balance:
                error = 'Insufficient funds.'
            else:
                account.balance -= amount
                account.save()
                log_transaction(account.id, account.account_number, 'withdrawal',
                                amount, description, account.balance)
                message = f"Withdrawal of ${amount:,.2f} CAD successful. New balance: ${account.balance:,.2f} CAD"
    else:
        form = TransactionForm()

    return render(request, 'withdraw.html', {
        'form': form, 'account': account, 'message': message, 'error': error,
    })


@login_required
def transactions_view(request):
    account = _get_or_create_account(request.user)
    now = timezone.localtime(timezone.now())
    year = request.GET.get('year', now.year)
    month = request.GET.get('month', now.month)

    transactions = get_transactions(account.id, year, month)

    months = [
        (1, 'January'), (2, 'February'), (3, 'March'), (4, 'April'),
        (5, 'May'), (6, 'June'), (7, 'July'), (8, 'August'),
        (9, 'September'), (10, 'October'), (11, 'November'), (12, 'December'),
    ]
    years = list(range(now.year - 2, now.year + 1))

    return render(request, 'transactions.html', {
        'account': account,
        'transactions': transactions,
        'selected_year': int(year),
        'selected_month': int(month),
        'months': months,
        'years': years,
    })


# ── Vulnerable API endpoints ─────────────────────────────────────────────────

# V11 (CWE-639) — IDOR: No authentication or ownership check.
# Any person who knows (or guesses) an account_id integer can retrieve
# the full transaction history for that account without logging in.
#
# V3 (CWE-352) — CSRF exempt: combined with IDOR this allows cross-site
# requests to silently harvest transaction data.
@csrf_exempt
def public_transactions_api(request, account_id):
    year = request.GET.get('year')
    month = request.GET.get('month')
    transactions = get_transactions(account_id, year, month)
    return JsonResponse({'account_id': account_id, 'transactions': transactions})


# V10 (CWE-943) — NoSQL Injection: the JSON body is deserialized and passed
# directly to pymongo as a query filter with no sanitisation.
# Attack: POST {"account_id": {"$gt": ""}} → dumps all transactions.
#
# V3 (CWE-352) — CSRF exempt.
@csrf_exempt
def transaction_filter_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    try:
        filter_data = json.loads(request.body)
        results = get_transactions_by_filter(filter_data)
        return JsonResponse({'count': len(results), 'transactions': results})
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        # V2 (CWE-215): Full exception detail returned to client
        return JsonResponse({'error': str(e)}, status=500)


# V8 / V9 (CWE-89 + CVE-2021-35042) — SQL Injection.
# Two injection surfaces:
#   1. Raw cursor with f-string interpolation (V9).
#   2. QuerySet.order_by() with unsanitised user input (V8 / CVE-2021-35042).
@login_required
def account_search_view(request):
    results = []
    query = request.GET.get('q', '')
    sort = request.GET.get('sort', 'account_number')

    if query:
        try:
            with connection.cursor() as cursor:
                # V9 (CWE-89): Direct f-string in SQL — classic injection
                cursor.execute(
                    f"SELECT id, account_number, balance FROM banking_account "
                    f"WHERE account_number LIKE '%{query}%'"
                )
                rows = cursor.fetchall()
                results = [{'id': r[0], 'account_number': r[1], 'balance': r[2]} for r in rows]
        except Exception as e:
            logger.error(f"Search error: {e}")

    # V8 (CVE-2021-35042): order_by() with user-controlled string allows
    # SQL injection via aggregation syntax in Django 3.2.0–3.2.4
    try:
        accounts_qs = Account.objects.all().order_by(sort)
        if not results:
            results = [
                {'id': a.id, 'account_number': a.account_number, 'balance': a.balance}
                for a in accounts_qs
            ]
    except Exception as e:
        logger.error(f"order_by injection attempt: {e}")

    return render(request, 'account_search.html', {'results': results, 'query': query, 'sort': sort})
