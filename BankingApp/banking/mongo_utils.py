from pymongo import MongoClient
from django.conf import settings
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

_client = None
_db = None


def get_db():
    global _client, _db
    if _db is None:
        try:
            _client = MongoClient(settings.MONGODB_URI, serverSelectionTimeoutMS=5000)
            _db = _client[settings.MONGODB_DB]
            logger.info(f"MongoDB connected: {settings.MONGODB_URI}")
        except Exception as e:
            logger.error(f"MongoDB connection failed: {e}")
            return None
    return _db


def log_transaction(account_id, account_number, transaction_type, amount, description='', balance_after=None):
    db = get_db()
    if db is None:
        return

    transaction = {
        'account_id': str(account_id),
        'account_number': account_number,
        'type': transaction_type,
        'amount': float(amount),
        'description': description,
        'balance_after': float(balance_after) if balance_after is not None else None,
        'timestamp': datetime.utcnow(),
    }

    # V5 (CWE-312): Sensitive financial data written to application logs in plaintext
    logger.debug(
        f"[TRANSACTION] account={account_number} type={transaction_type} "
        f"amount={amount} balance_after={balance_after}"
    )

    try:
        db.transactions.insert_one(transaction)
    except Exception as e:
        logger.error(f"Failed to log transaction: {e}")


def get_transactions(account_id, year=None, month=None):
    db = get_db()
    if db is None:
        return []

    query = {'account_id': str(account_id)}

    if year and month:
        try:
            start = datetime(int(year), int(month), 1)
            end = datetime(int(year) + 1, 1, 1) if int(month) == 12 else datetime(int(year), int(month) + 1, 1)
            query['timestamp'] = {'$gte': start, '$lt': end}
        except (ValueError, TypeError):
            pass

    try:
        return list(db.transactions.find(query, {'_id': 0}).sort('timestamp', -1))
    except Exception as e:
        logger.error(f"get_transactions failed: {e}")
        return []


def get_transactions_by_filter(filter_dict):
    """
    V10 (CWE-943) — NoSQL Injection.

    This function passes the caller-supplied dict directly to MongoDB as a query filter.
    An attacker POST-ing {"account_id": {"$gt": ""}} bypasses the account_id check
    and retrieves every transaction document in the collection.

    Attack example (curl):
        curl -X POST http://<host>:5090/api/filter/ \\
             -H 'Content-Type: application/json' \\
             -d '{"account_id": {"$gt": ""}}'
    """
    db = get_db()
    if db is None:
        return []
    try:
        return list(db.transactions.find(filter_dict, {'_id': 0}))
    except Exception as e:
        logger.error(f"get_transactions_by_filter failed: {e}")
        return []
