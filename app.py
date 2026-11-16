import os
import re
from datetime import date, datetime
from decimal import Decimal
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, get_jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
import bcrypt
import mysql.connector
from mysql.connector import IntegrityError, errorcode
from db import get_connection
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

# ══════════════════════════════════════════════════════
#  JWT HARDENING (VULN-10 ADVANCED: Algorithm Confusion & Key Strength)
# ══════════════════════════════════════════════════════
_jwt_secret = os.environ.get("JWT_SECRET_KEY")
if not _jwt_secret:
    raise ValueError("JWT_SECRET_KEY environment variable is not set. Refusing to start.")
if len(_jwt_secret) < 32:
    raise ValueError("JWT_SECRET_KEY must be at least 32 characters long to withstand brute-force attacks.")

app.config["JWT_SECRET_KEY"] = _jwt_secret
app.config["JWT_ALGORITHM"] = "HS256"
# Explicitly whitelist decode algorithms to strictly reject alg='none' or algorithm confusion
app.config["JWT_DECODE_ALGORITHMS"] = ["HS256"]

jwt = JWTManager(app)

# ══════════════════════════════════════════════════════
#  TOKEN REVOCATION / BLACKLIST & DUMMY HASH FOR TIMING PROTECTION
# ══════════════════════════════════════════════════════
_BLACKLISTED_JTIS = set()

# Precompute a constant dummy bcrypt hash with cost factor 12 to eliminate Timing Attack side-channels
DUMMY_BCRYPT_HASH = bcrypt.hashpw(b"chainsync_timing_attack_mitigation_secret", bcrypt.gensalt(12)).decode('utf-8')

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    """Fail-closed token revocation checker."""
    try:
        jti = jwt_payload.get("jti")
        if not jti:
            return True  # Fail-closed: missing jti is rejected
        if jti in _BLACKLISTED_JTIS:
            return True
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM token_blacklist WHERE jti=%s", (jti,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row:
            _BLACKLISTED_JTIS.add(jti)
            return True
        return False
    except Exception as e:
        app.logger.warning("Token revocation check exception (fail-closed): %s", str(e))
        return True  # Fail-closed

def init_blacklist_table():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS token_blacklist (
                jti VARCHAR(64) PRIMARY KEY,
                RevokedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        cursor.execute("SELECT jti FROM token_blacklist")
        for row in cursor.fetchall():
            _BLACKLISTED_JTIS.add(row[0])
        cursor.close()
        conn.close()
    except Exception as e:
        app.logger.warning("Could not sync token_blacklist on startup: %s", str(e))

init_blacklist_table()

# ══════════════════════════════════════════════════════
#  RATE LIMITING & CORS
# ══════════════════════════════════════════════════════
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

# Enforce strict CORS whitelist: never allow wildcard '*'
raw_origins = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
)
CORS_ORIGINS = [
    origin.strip()
    for origin in raw_origins.split(",")
    if origin.strip() and origin.strip() != "*"
]
CORS(app, resources={r"/api/*": {"origins": CORS_ORIGINS, "supports_credentials": True}})

# ══════════════════════════════════════════════════════
#  GLOBAL ERROR HANDLERS — always return JSON, never HTML or DB internals
#  (A10:2025 - Mishandling of Exceptional Conditions)
# ══════════════════════════════════════════════════════

@app.errorhandler(mysql.connector.Error)
def handle_mysql_error(e):
    app.logger.error("Database error intercepted: %s", str(e))
    # Never leak table names, query fragments or column names to client
    return jsonify({'error': 'Database operation failed', 'code': 500}), 500

@app.errorhandler(HTTPException)
def handle_http_error(e):
    return jsonify({'error': e.description, 'code': e.code}), e.code

@app.errorhandler(KeyError)
def handle_key_error(e):
    field = e.args[0] if e.args else 'unknown'
    return jsonify({'error': f'Missing required field: {field}', 'code': 400}), 400

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    if isinstance(e, HTTPException):
        return handle_http_error(e)
    app.logger.exception("Unhandled exception")
    return jsonify({'error': 'Internal server error', 'code': 500}), 500

# ══════════════════════════════════════════════════════
#  JWT — every /api/* route requires a valid token,
#  except the two login endpoints below
# ══════════════════════════════════════════════════════

PUBLIC_PATHS = {"/api/auth/login", "/api/auth/customer-login"}

@app.before_request
def require_jwt():
    """Fail-closed authentication filter for all API routes (OWASP A10:2025)."""
    if request.method == "OPTIONS":          # CORS preflight
        return None
    if not request.path.startswith("/api/"):
        return None
    if request.path in PUBLIC_PATHS:
        return None
    try:
        verify_jwt_in_request()
    except Exception as e:
        app.logger.warning("JWT verification failed (fail-closed): %s", str(e))
        return jsonify({"error": "Unauthorized: Token thiếu, hết hạn hoặc không hợp lệ", "code": 401}), 401
    return None

def admin_required():
    """Fail-closed admin authorization check (OWASP A10:2025).
    Any exception or missing/invalid claims strictly yields 403 Forbidden.
    """
    try:
        claims = get_jwt()
        if not claims or claims.get("role") != "admin":
            return jsonify({"error": "Forbidden: Yêu cầu quyền admin", "code": 403}), 403
    except Exception as e:
        app.logger.warning("Admin authorization exception (fail-closed): %s", str(e))
        return jsonify({"error": "Forbidden: Quyền truy cập bị từ chối", "code": 403}), 403
    return None


# ══════════════════════════════════════════════════════
#  B2B RBAC + SERIALIZATION + INVENTORY LEDGER HELPERS
# ══════════════════════════════════════════════════════

ORG_ROLES = ('org_manager', 'org_staff')
ORG_ALL_ROLES = ('org_manager', 'org_staff', 'customer')


def role_required(*roles):
    """Fail-closed role check for B2B endpoints."""
    try:
        claims = get_jwt()
        if not claims or claims.get('role') not in roles:
            return jsonify({"error": "Forbidden: Bạn không có quyền thực hiện thao tác này", "code": 403}), 403
    except Exception as e:
        app.logger.warning("Role authorization exception (fail-closed): %s", str(e))
        return jsonify({"error": "Forbidden: Quyền truy cập bị từ chối", "code": 403}), 403
    return None


def current_identity():
    """Username (JWT subject) truncated to the audit column width."""
    return str(get_jwt().get('sub') or 'system').strip()[:50]


def json_safe(value):
    """Recursively convert Decimal/date/datetime for JSON responses."""
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return value


def parse_iso_date(value, field_name='ngày'):
    text = str(value or '').strip()
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', text):
        raise ValueError(f'{field_name} không hợp lệ (YYYY-MM-DD)')
    return text


def write_inventory_transaction(cursor, inventory_id, product_id, warehouse_id, tx_type,
                                qty_change, qty_before, qty_after, ref_type=None,
                                ref_id=None, notes=None, performed_by=None):
    """Append one row to the inventory ledger (every stock mutation must call this)."""
    txn_id = next_entity_id(cursor, 'TXN', 'TXN')
    cursor.execute("""
        INSERT INTO inventory_transactions
            (TransactionID, InventoryID, ProductID, WarehouseID, TransactionType,
             QuantityChange, QuantityBefore, QuantityAfter, ReferenceType, ReferenceID,
             Notes, PerformedBy)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (txn_id, inventory_id, product_id, warehouse_id, tx_type, qty_change,
          qty_before, qty_after, ref_type, ref_id, notes, performed_by))
    return txn_id


def lock_or_create_inventory(cursor, product_id, warehouse_id):
    """Lock the inventory row, creating a zero-quantity row when missing."""
    cursor.execute("""
        SELECT InventoryID, QuantityAvailable
        FROM inventory WHERE ProductID=%s AND WarehouseID=%s FOR UPDATE
    """, (product_id, warehouse_id))
    row = cursor.fetchone()
    if row:
        return row
    inventory_id = next_entity_id(cursor, 'INV', 'INV')
    cursor.execute("""
        INSERT INTO inventory (InventoryID, QuantityAvailable, ProductID, WarehouseID)
        VALUES (%s, 0, %s, %s)
    """, (inventory_id, product_id, warehouse_id))
    return {'InventoryID': inventory_id, 'QuantityAvailable': 0}


def stock_in(cursor, product_id, warehouse_id, quantity, tx_type, ref_type, ref_id,
             notes, performed_by):
    """Increase stock + adjustment history + ledger in one consistent step."""
    quantity = int(quantity)
    if quantity <= 0:
        raise ValueError('Số lượng nhập kho phải lớn hơn 0')
    inventory = lock_or_create_inventory(cursor, product_id, warehouse_id)
    before = int(inventory['QuantityAvailable'] or 0)
    after = before + quantity
    cursor.execute(
        "UPDATE inventory SET QuantityAvailable=%s WHERE InventoryID=%s",
        (after, inventory['InventoryID']),
    )
    adjustment_id = write_inventory_adjustment(
        cursor, inventory['InventoryID'], before, after, 'Nhập thêm'
    )
    txn_id = write_inventory_transaction(
        cursor, inventory['InventoryID'], product_id, warehouse_id, tx_type,
        quantity, before, after, ref_type, ref_id, notes, performed_by,
    )
    return {
        'InventoryID': inventory['InventoryID'],
        'OldQuantity': before,
        'NewQuantity': after,
        'AdjustmentID': adjustment_id,
        'TransactionID': txn_id,
    }


# ══════════════════════════════════════════════════════
#  MASS ASSIGNMENT DEFENSE (OWASP API3:2023)
# ══════════════════════════════════════════════════════

def extract_whitelisted_fields(data: dict, allowed_fields: set, reject_extra: bool = True) -> tuple:
    """
    OWASP API3:2023 - Broken Object Property Level Authorization (Mass Assignment Defense).
    Extracts only whitelisted fields from incoming JSON payload.
    If reject_extra is True and any unexpected field is present, returns an error message.
    """
    if not isinstance(data, dict):
        return {}, "Dữ liệu payload phải là JSON object"
    
    extra_fields = set(data.keys()) - allowed_fields
    if extra_fields and reject_extra:
        return {}, f"Phát hiện trường không được phép (Mass Assignment): {', '.join(sorted(extra_fields))}"
    
    clean = {k: data[k] for k in allowed_fields if k in data}
    return clean, None


# ══════════════════════════════════════════════════════
#  ORDER ID SEQUENCE (server-side, race-condition safe)
# ══════════════════════════════════════════════════════

def next_order_id(cursor):
    """
    Sinh OrderID tuần tự (ORD001, ORD002, ...) an toàn khi có nhiều request
    đồng thời. UPDATE lấy row lock trên order_id_sequence.id=1, buộc các
    transaction khác phải chờ; LAST_INSERT_ID(expr) gắn với connection hiện tại.
    Phải gọi trong cùng transaction với INSERT orders để rollback nhất quán.
    """
    cursor.execute(
        "UPDATE order_id_sequence SET next_value = LAST_INSERT_ID(next_value + 1) WHERE id = 1"
    )
    if cursor.rowcount != 1:
        raise RuntimeError("order_id_sequence chưa được khởi tạo (thiếu dòng id=1)")
    cursor.execute("SELECT LAST_INSERT_ID() AS n")
    return "ORD%03d" % cursor.fetchone()["n"]

def next_entity_id(cursor, entity, prefix):
    """Sinh mã chứng từ tuần tự bằng row lock trên entity_id_sequence."""
    cursor.execute(
        "INSERT IGNORE INTO entity_id_sequence (entity, next_value) VALUES (%s, 0)",
        (entity,),
    )
    cursor.execute(
        "UPDATE entity_id_sequence SET next_value = LAST_INSERT_ID(next_value + 1) WHERE entity = %s",
        (entity,),
    )
    cursor.execute("SELECT LAST_INSERT_ID() AS n")
    return "%s%03d" % (prefix, int(cursor.fetchone()["n"]))

def lock_inventory_for_product(cursor, product_id):
    """Khóa dòng tồn kho ưu tiên kho W001, sau đó kho còn nhiều hàng nhất."""
    cursor.execute(
        """
        SELECT InventoryID, QuantityAvailable, WarehouseID
        FROM inventory
        WHERE ProductID=%s
        ORDER BY (WarehouseID='W001') DESC, QuantityAvailable DESC
        FOR UPDATE
        """,
        (product_id,),
    )
    rows = cursor.fetchall()
    return rows[0] if rows else None

def write_inventory_adjustment(cursor, inventory_id, old_qty, new_qty, reason):
    adjustment_id = next_entity_id(cursor, 'ADJ', 'ADJ')
    cursor.execute(
        """
        INSERT INTO inventory_adjustments
            (AdjustmentID, InventoryID, OldQuantity, NewQuantity, Reason)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (adjustment_id, inventory_id, old_qty, new_qty, reason),
    )
    return adjustment_id

SUPPLIER_ALLOWED_UPDATE  = {'SupplierName', 'ContactNumber', 'Location', 'TaxCode', 'Email', 'Rating', 'OnTimeRate', 'SupplierID'}
PRODUCT_ALLOWED_UPDATE   = {'ProductName', 'Category', 'UnitPrice', 'SupplierID', 'Unit', 'Origin', 'ProductID'}
WAREHOUSE_ALLOWED_UPDATE = {'WarehouseName', 'Location', 'Capacity', 'ProvinceCode', 'WarehouseID'}
INVENTORY_ALLOWED_UPDATE = {'QuantityAvailable', 'ProductID', 'WarehouseID', 'InventoryID'}
CUSTOMER_ALLOWED_UPDATE  = {'CustomerName', 'ContactNumber', 'Address', 'TaxCode', 'CustomerType', 'CustomerID'}
ORDER_ALLOWED_UPDATE     = {'OrderDate', 'Bill', 'CustomerID', 'ProductID', 'Quantity', 'InvoiceNumber', 'VatRate', 'VatAmount', 'PaymentMethod', 'OrderID'}
ORDER_ALLOWED_CREATE     = {'OrderID', 'OrderDate', 'Bill', 'CustomerID', 'ProductID', 'Quantity', 'InvoiceNumber', 'VatRate', 'VatAmount', 'PaymentMethod', 'Status'}
PR_ALLOWED_CREATE        = {'ProductID', 'Quantity', 'RequestedBy'}
PO_ALLOWED_CREATE        = {'PRID', 'SupplierID', 'ProductID', 'Quantity', 'UnitPrice', 'OrderDate'}
RETURN_ALLOWED_CREATE    = {'OriginalOrderID', 'Quantity', 'Reason'}
ADJUST_REASONS           = {'Kiểm kê', 'Hàng hỏng', 'Nhập thêm', 'Xuất kho'}


# ══════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def auth_login():
    d = request.get_json(silent=True) or {}
    username = (d.get('username') or '').strip()
    password = d.get('password') or ''
    if not username or not password:
        return jsonify({'error': 'Thiếu username hoặc password', 'code': 400}), 400
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM user WHERE Username=%s", (username,))
        u = cursor.fetchone()
        cursor.close()

        # Side-Channel Timing Attack mitigation:
        # Always run bcrypt comparison with dummy hash even if user doesn't exist
        target_hash = u['PasswordHash'].encode('utf-8') if (u and u.get('PasswordHash')) else DUMMY_BCRYPT_HASH.encode('utf-8')
        password_valid = bcrypt.checkpw(password.encode('utf-8'), target_hash)

        if not u or not password_valid:
            return jsonify({'error': 'Sai tên đăng nhập hoặc mật khẩu', 'code': 401}), 401
        if (u.get('Status') or 'Active') != 'Active':
            return jsonify({'error': 'Tài khoản đã bị vô hiệu hóa', 'code': 403}), 403

        org = None
        if u.get('OrganizationID'):
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT OrganizationID, OrganizationCode, OrganizationName FROM organizations WHERE OrganizationID=%s",
                (u['OrganizationID'],),
            )
            org = cursor.fetchone()
            cursor.close()

        token = create_access_token(
            identity=u['Username'],
            additional_claims={
                'role': u['Role'],
                'customer_id': u.get('CustomerID'),
                'organization_id': u.get('OrganizationID'),
                'full_name': u.get('FullName'),
            }
        )
        return jsonify({
            'access_token': token,
            'role': u['Role'],
            'customer_id': u.get('CustomerID'),
            'organization_id': u.get('OrganizationID'),
            'full_name': u.get('FullName'),
            'organization': org,
        })
    finally:
        conn.close()

@app.route('/api/auth/me', methods=['GET'])
@limiter.limit("60 per minute")
def auth_me():
    """Current profile + organization resolved from the database (not just claims)."""
    claims = get_jwt()
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT u.UserID, u.Username, u.Role, u.CustomerID, u.OrganizationID,
                   u.FullName, u.Position, u.Email, u.Status, u.CreatedAt,
                   o.OrganizationCode, o.OrganizationName, o.TaxCode,
                   o.Representative, o.Status AS OrganizationStatus
            FROM user u
            LEFT JOIN organizations o ON o.OrganizationID = u.OrganizationID
            WHERE u.Username=%s
        """, (claims.get('sub'),))
        profile = cursor.fetchone()
        if not profile:
            return jsonify({'error': 'Không tìm thấy tài khoản', 'code': 404}), 404
        return jsonify(json_safe(profile))
    finally:
        cursor.close()
        conn.close()

@app.route('/api/auth/customer-login', methods=['POST'])
@limiter.limit("5 per minute")
def auth_customer_login():
    d = request.get_json(silent=True) or {}
    customer_id = (d.get('customer_id') or '').strip()
    password = d.get('password') or ''
    if not customer_id or not password:
        return jsonify({'error': 'Thiếu mã khách hàng hoặc mật khẩu', 'code': 400}), 400
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM user WHERE CustomerID=%s AND Role='customer'", (customer_id,))
        u = cursor.fetchone()

        # Side-Channel Timing Attack mitigation:
        # Always run bcrypt comparison with dummy hash even if user doesn't exist
        target_hash = u['PasswordHash'].encode('utf-8') if (u and u.get('PasswordHash')) else DUMMY_BCRYPT_HASH.encode('utf-8')
        password_valid = bcrypt.checkpw(password.encode('utf-8'), target_hash)

        if not u or not password_valid:
            cursor.close()
            return jsonify({'error': 'Mã khách hàng hoặc mật khẩu không đúng', 'code': 401}), 401
        cursor.execute("SELECT * FROM customer WHERE CustomerID=%s", (u['CustomerID'],))
        cust = cursor.fetchone()
        cursor.close()
        token = create_access_token(
            identity=u['Username'],
            additional_claims={'role': 'customer', 'customer_id': u['CustomerID']}
        )
        return jsonify({'access_token': token, 'customer': cust})
    finally:
        conn.close()

@app.route('/api/auth/logout', methods=['POST'])
@limiter.limit("10 per minute")
def auth_logout():
    """Revoke current JWT by adding its unique jti to blacklist."""
    try:
        jwt_data = get_jwt()
        jti = jwt_data.get("jti")
        if not jti:
            return jsonify({'error': 'Token không hợp lệ hoặc thiếu jti', 'code': 400}), 400
        _BLACKLISTED_JTIS.add(jti)
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT IGNORE INTO token_blacklist (jti) VALUES (%s)", (jti,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'message': 'Đăng xuất thành công. Token đã được thu hồi an toàn.'})
    except Exception as e:
        app.logger.error("Logout exception: %s", str(e))
        return jsonify({'error': 'Lỗi xử lý đăng xuất', 'code': 500}), 500

# ══════════════════════════════════════════════════════
#  ORGANIZATIONS & MEMBERS (B2B)
# ══════════════════════════════════════════════════════

ORG_FIELDS = {'OrganizationCode', 'OrganizationName', 'TaxCode', 'OrganizationType',
              'Address', 'Representative', 'RepresentativePhone', 'RepresentativeEmail', 'Status'}
ORG_TYPES = {'OrganizationCustomer', 'Supplier', 'Central'}


def user_id_by_username(cursor, username):
    cursor.execute("SELECT UserID FROM user WHERE Username=%s", (username,))
    row = cursor.fetchone()
    return row['UserID'] if row else None


def find_org_customer_id(cursor, organization_id):
    cursor.execute(
        "SELECT CustomerID FROM customer WHERE OrganizationID=%s LIMIT 1",
        (organization_id,),
    )
    row = cursor.fetchone()
    return row['CustomerID'] if row else None


@app.route('/api/organizations', methods=['GET'])
@limiter.limit("30 per minute")
def get_organizations():
    err = admin_required()
    if err: return err
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT o.*,
               (SELECT c.CustomerID FROM customer c WHERE c.OrganizationID=o.OrganizationID LIMIT 1) AS CustomerID,
               (SELECT COUNT(*) FROM user u WHERE u.OrganizationID=o.OrganizationID) AS MemberCount,
               (SELECT COUNT(*) FROM customer_purchase_requests r WHERE r.OrganizationID=o.OrganizationID) AS CPRCount
        FROM organizations o
        ORDER BY o.OrganizationID
    """)
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(json_safe(data))


@app.route('/api/organizations', methods=['POST'])
@limiter.limit("10 per minute")
def add_organization():
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, ORG_FIELDS | {'OrganizationID', 'CustomerID'})
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400

    name = str(clean.get('OrganizationName') or '').strip()
    if not name:
        return jsonify({'error': 'Thiếu OrganizationName', 'code': 400}), 400
    org_type = clean.get('OrganizationType') or 'OrganizationCustomer'
    if org_type not in ORG_TYPES:
        return jsonify({'error': 'OrganizationType không hợp lệ', 'code': 400}), 400
    status = clean.get('Status') or 'Active'
    if status not in ('Active', 'Inactive'):
        return jsonify({'error': 'Status không hợp lệ', 'code': 400}), 400
    customer_id = str(clean.get('CustomerID') or '').strip() or None

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        org_id = str(clean.get('OrganizationID') or '').strip() or next_entity_id(cursor, 'ORG', 'ORG')
        org_code = str(clean.get('OrganizationCode') or org_id).strip()[:20]
        cursor.execute("""
            INSERT INTO organizations
                (OrganizationID, OrganizationCode, OrganizationName, TaxCode, OrganizationType,
                 Address, Representative, RepresentativePhone, RepresentativeEmail, Status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (org_id, org_code, name, clean.get('TaxCode'), org_type, clean.get('Address'),
              clean.get('Representative'), clean.get('RepresentativePhone'),
              clean.get('RepresentativeEmail'), status))
        if customer_id:
            cursor.execute("SELECT CustomerID FROM customer WHERE CustomerID=%s FOR UPDATE", (customer_id,))
            if not cursor.fetchone():
                conn.rollback()
                return jsonify({'error': 'Không tìm thấy customer để liên kết', 'code': 404}), 404
            cursor.execute("""
                UPDATE customer SET OrganizationID=%s, CustomerType='Business' WHERE CustomerID=%s
            """, (org_id, customer_id))
        conn.commit()
        return jsonify({'message': 'Đã tạo tổ chức', 'OrganizationID': org_id}), 201
    except IntegrityError as e:
        if conn: conn.rollback()
        if e.errno == errorcode.ER_DUP_ENTRY:
            return jsonify({'error': 'Mã tổ chức, mã số thuế hoặc liên kết customer đã tồn tại', 'code': 409}), 409
        raise
    except Exception:
        if conn: conn.rollback()
        raise
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/organizations/me', methods=['GET'])
@limiter.limit("30 per minute")
def get_my_organization():
    err = role_required(*ORG_ROLES)
    if err: return err
    org_id = get_jwt().get('organization_id')
    if not org_id:
        return jsonify({'error': 'Tài khoản chưa thuộc tổ chức nào', 'code': 403}), 403
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT o.*,
               (SELECT c.CustomerID FROM customer c WHERE c.OrganizationID=o.OrganizationID LIMIT 1) AS CustomerID,
               (SELECT COUNT(*) FROM user u WHERE u.OrganizationID=o.OrganizationID) AS MemberCount
        FROM organizations o WHERE o.OrganizationID=%s
    """, (org_id,))
    org = cursor.fetchone()
    cursor.close(); conn.close()
    if not org:
        return jsonify({'error': 'Không tìm thấy tổ chức', 'code': 404}), 404
    return jsonify(json_safe(org))


@app.route('/api/organizations/<oid>', methods=['PUT'])
@limiter.limit("10 per minute")
def update_organization(oid):
    claims = get_jwt()
    role = claims.get('role')
    if role == 'admin':
        allowed = ORG_FIELDS
    elif role == 'org_manager' and claims.get('organization_id') == oid:
        allowed = {'Address', 'Representative', 'RepresentativePhone', 'RepresentativeEmail'}
    else:
        return jsonify({'error': 'Forbidden: Không có quyền sửa tổ chức này', 'code': 403}), 403

    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, allowed)
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    if not clean:
        return jsonify({'error': 'Không có trường hợp lệ để cập nhật', 'code': 400}), 400
    if 'OrganizationType' in clean and clean['OrganizationType'] not in ORG_TYPES:
        return jsonify({'error': 'OrganizationType không hợp lệ', 'code': 400}), 400
    if 'Status' in clean and clean['Status'] not in ('Active', 'Inactive'):
        return jsonify({'error': 'Status không hợp lệ', 'code': 400}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM organizations WHERE OrganizationID=%s FOR UPDATE", (oid,))
        if not cursor.fetchone():
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy tổ chức', 'code': 404}), 404
        sets, params = [], []
        for field in ('OrganizationCode', 'OrganizationName', 'TaxCode', 'OrganizationType',
                      'Address', 'Representative', 'RepresentativePhone', 'RepresentativeEmail', 'Status'):
            if field in clean:
                sets.append(f"{field}=%s")
                params.append(clean[field])
        params.append(oid)
        cursor.execute(f"UPDATE organizations SET {', '.join(sets)} WHERE OrganizationID=%s", tuple(params))
        conn.commit()
        return jsonify({'message': 'Đã cập nhật tổ chức'})
    except IntegrityError as e:
        conn.rollback()
        if e.errno == errorcode.ER_DUP_ENTRY:
            return jsonify({'error': 'Mã tổ chức hoặc mã số thuế đã tồn tại', 'code': 409}), 409
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close(); conn.close()


@app.route('/api/organizations/members', methods=['GET'])
@limiter.limit("30 per minute")
def get_org_members():
    err = role_required(*ORG_ROLES)
    if err: return err
    org_id = get_jwt().get('organization_id')
    if not org_id:
        return jsonify({'error': 'Tài khoản chưa thuộc tổ chức nào', 'code': 403}), 403
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT UserID, Username, Role, FullName, Position, Email, Status, CreatedAt
        FROM user WHERE OrganizationID=%s ORDER BY UserID
    """, (org_id,))
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(json_safe(data))


@app.route('/api/organizations/members', methods=['POST'])
@limiter.limit("10 per minute")
def add_org_member():
    err = role_required('org_manager')
    if err: return err
    claims = get_jwt()
    org_id = claims.get('organization_id')
    if not org_id:
        return jsonify({'error': 'Tài khoản chưa thuộc tổ chức nào', 'code': 403}), 403

    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(
        d, {'Username', 'Password', 'FullName', 'Position', 'Email'}
    )
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    username = str(clean.get('Username') or '').strip()
    password = str(clean.get('Password') or '')
    full_name = str(clean.get('FullName') or '').strip()
    if not username or not password or not full_name:
        return jsonify({'error': 'Thiếu Username, Password hoặc FullName', 'code': 400}), 400
    if not re.fullmatch(r'[A-Za-z0-9._-]{3,50}', username):
        return jsonify({'error': 'Username chỉ gồm chữ, số, ., _, - (3-50 ký tự)', 'code': 400}), 400
    if len(password) < 8:
        return jsonify({'error': 'Mật khẩu phải có ít nhất 8 ký tự', 'code': 400}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT Status FROM organizations WHERE OrganizationID=%s", (org_id,))
        org = cursor.fetchone()
        if not org or org['Status'] != 'Active':
            return jsonify({'error': 'Tổ chức không tồn tại hoặc đã ngừng hoạt động', 'code': 409}), 409
        cursor.execute("SELECT 1 FROM user WHERE Username=%s", (username,))
        if cursor.fetchone():
            return jsonify({'error': 'Username đã tồn tại', 'code': 409}), 409
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')
        cursor.execute("""
            INSERT INTO user (Username, PasswordHash, Role, OrganizationID, FullName, Position, Email, Status)
            VALUES (%s, %s, 'org_staff', %s, %s, %s, %s, 'Active')
        """, (username, password_hash, org_id, full_name, clean.get('Position'), clean.get('Email')))
        conn.commit()
        return jsonify({'message': 'Đã thêm thành viên', 'Username': username, 'Role': 'org_staff'}), 201
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close(); conn.close()


@app.route('/api/organizations/members/<username>', methods=['PUT'])
@limiter.limit("10 per minute")
def update_org_member(username):
    err = role_required('org_manager')
    if err: return err
    claims = get_jwt()
    org_id = claims.get('organization_id')
    if not org_id:
        return jsonify({'error': 'Tài khoản chưa thuộc tổ chức nào', 'code': 403}), 403

    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(
        d, {'FullName', 'Position', 'Email', 'Status', 'Password'}
    )
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    if not clean:
        return jsonify({'error': 'Không có trường hợp lệ để cập nhật', 'code': 400}), 400
    if 'Status' in clean and clean['Status'] not in ('Active', 'Inactive'):
        return jsonify({'error': 'Status không hợp lệ', 'code': 400}), 400
    if username == claims.get('sub') and clean.get('Status') == 'Inactive':
        return jsonify({'error': 'Không thể tự vô hiệu hóa tài khoản của chính mình', 'code': 400}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT UserID FROM user WHERE Username=%s AND OrganizationID=%s FOR UPDATE
        """, (username, org_id))
        if not cursor.fetchone():
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy thành viên trong tổ chức', 'code': 404}), 404
        sets, params = [], []
        for field in ('FullName', 'Position', 'Email', 'Status'):
            if field in clean:
                sets.append(f"{field}=%s")
                params.append(clean[field])
        if clean.get('Password'):
            if len(str(clean['Password'])) < 8:
                conn.rollback()
                return jsonify({'error': 'Mật khẩu phải có ít nhất 8 ký tự', 'code': 400}), 400
            sets.append("PasswordHash=%s")
            params.append(bcrypt.hashpw(str(clean['Password']).encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8'))
        params.extend([username, org_id])
        cursor.execute(f"UPDATE user SET {', '.join(sets)} WHERE Username=%s AND OrganizationID=%s", tuple(params))
        conn.commit()
        return jsonify({'message': 'Đã cập nhật thành viên'})
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close(); conn.close()


# ══════════════════════════════════════════════════════
#  CUSTOMER PURCHASE REQUESTS (CPR → SO)
# ══════════════════════════════════════════════════════

def cpr_visibility_filter(claims, alias='r'):
    """Return (SQL fragment, params) enforcing CPR visibility by role."""
    role = claims.get('role')
    if role == 'admin':
        return None, ()
    if role in ORG_ROLES:
        return f"{alias}.OrganizationID=%s", (claims.get('organization_id'),)
    return f"{alias}.CustomerID=%s", (claims.get('customer_id'),)


def load_cpr_items(cursor, cprid):
    cursor.execute("""
        SELECT i.CPRID, i.LineNo, i.ProductID, i.Quantity, i.UnitPrice,
               p.ProductName, p.Unit, p.Category
        FROM customer_purchase_request_items i
        JOIN product p ON p.ProductID=i.ProductID
        WHERE i.CPRID=%s ORDER BY i.LineNo
    """, (cprid,))
    return cursor.fetchall()


@app.route('/api/customer-purchase-requests', methods=['GET'])
@limiter.limit("30 per minute")
def get_customer_purchase_requests():
    claims = get_jwt()
    if claims.get('role') not in ('admin',) + ORG_ALL_ROLES:
        return jsonify({'error': 'Forbidden: Không có quyền xem yêu cầu mua', 'code': 403}), 403
    where, params = cpr_visibility_filter(claims)
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    sql = """
        SELECT r.*, o.OrganizationName, c.CustomerName,
               (SELECT COUNT(*) FROM customer_purchase_request_items i WHERE i.CPRID=r.CPRID) AS ItemCount,
               (SELECT COALESCE(SUM(i.Quantity),0) FROM customer_purchase_request_items i WHERE i.CPRID=r.CPRID) AS TotalQuantity
        FROM customer_purchase_requests r
        JOIN organizations o ON o.OrganizationID=r.OrganizationID
        JOIN customer c ON c.CustomerID=r.CustomerID
    """
    if where:
        sql += " WHERE " + where
    sql += " ORDER BY r.CreatedAt DESC, r.CPRID DESC"
    cursor.execute(sql, params)
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(json_safe(data))


@app.route('/api/customer-purchase-requests', methods=['POST'])
@limiter.limit("10 per minute")
def add_customer_purchase_request():
    claims = get_jwt()
    role = claims.get('role')
    if role not in ORG_ALL_ROLES:
        return jsonify({'error': 'Forbidden: Quyền tạo yêu cầu mua thuộc tài khoản tổ chức/khách hàng', 'code': 403}), 403

    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, {'Note', 'Items', 'ProductID', 'Quantity'})
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    note = str(clean.get('Note') or '').strip()[:500] or None

    raw_items = clean.get('Items')
    if raw_items is None:
        raw_items = [{'ProductID': clean.get('ProductID'), 'Quantity': clean.get('Quantity')}]
    if not isinstance(raw_items, list) or not raw_items or len(raw_items) > 50:
        return jsonify({'error': 'Items phải là danh sách 1-50 dòng hàng', 'code': 400}), 400

    items = []
    seen_products = set()
    for line_no, entry in enumerate(raw_items, start=1):
        if not isinstance(entry, dict):
            return jsonify({'error': f'Dòng hàng {line_no} không hợp lệ', 'code': 400}), 400
        product_id = str(entry.get('ProductID') or '').strip()
        try:
            quantity = int(entry.get('Quantity'))
        except (TypeError, ValueError):
            return jsonify({'error': f'Quantity không hợp lệ ở dòng {line_no}', 'code': 400}), 400
        if not product_id:
            return jsonify({'error': f'Thiếu ProductID ở dòng {line_no}', 'code': 400}), 400
        if quantity < 1:
            return jsonify({'error': f'Quantity phải lớn hơn 0 ở dòng {line_no}', 'code': 400}), 400
        if product_id in seen_products:
            return jsonify({'error': f'Sản phẩm {product_id} bị lặp trong yêu cầu', 'code': 400}), 400
        seen_products.add(product_id)
        items.append({'ProductID': product_id, 'Quantity': quantity})

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)

        if role in ORG_ROLES:
            organization_id = claims.get('organization_id')
            if not organization_id:
                conn.rollback()
                return jsonify({'error': 'Tài khoản chưa thuộc tổ chức nào', 'code': 403}), 403
            customer_id = find_org_customer_id(cursor, organization_id)
            if not customer_id:
                conn.rollback()
                return jsonify({'error': 'Tổ chức chưa liên kết hồ sơ khách hàng', 'code': 409}), 409
        else:
            customer_id = claims.get('customer_id')
            cursor.execute("SELECT OrganizationID FROM customer WHERE CustomerID=%s", (customer_id,))
            cust = cursor.fetchone()
            if not cust:
                conn.rollback()
                return jsonify({'error': 'Không tìm thấy hồ sơ khách hàng', 'code': 404}), 404
            organization_id = cust.get('OrganizationID')
            if not organization_id:
                conn.rollback()
                return jsonify({'error': 'Tài khoản khách hàng chưa thuộc tổ chức doanh nghiệp', 'code': 409}), 409

        total_estimated = 0.0
        prepared = []
        for item in items:
            cursor.execute("SELECT UnitPrice FROM product WHERE ProductID=%s", (item['ProductID'],))
            product = cursor.fetchone()
            if not product:
                conn.rollback()
                return jsonify({'error': f'Sản phẩm {item["ProductID"]} không tồn tại', 'code': 400}), 400
            unit_price = float(product['UnitPrice'] or 0)
            total_estimated += unit_price * item['Quantity']
            prepared.append((item['ProductID'], item['Quantity'], unit_price))

        cprid = next_entity_id(cursor, 'CPR', 'CPR')
        requested_by_user_id = user_id_by_username(cursor, claims.get('sub'))
        requested_by_name = str(claims.get('full_name') or claims.get('sub') or '')[:100]
        cursor.execute("""
            INSERT INTO customer_purchase_requests
                (CPRID, OrganizationID, CustomerID, RequestedByUserID, RequestedByName,
                 Status, Note, TotalEstimated)
            VALUES (%s, %s, %s, %s, %s, 'Submitted', %s, %s)
        """, (cprid, organization_id, customer_id, requested_by_user_id,
              requested_by_name, note, round(total_estimated, 2)))
        for line_no, (product_id, quantity, unit_price) in enumerate(prepared, start=1):
            cursor.execute("""
                INSERT INTO customer_purchase_request_items
                    (CPRID, LineNo, ProductID, Quantity, UnitPrice)
                VALUES (%s, %s, %s, %s, %s)
            """, (cprid, line_no, product_id, quantity, unit_price))
        conn.commit()
        return jsonify({
            'message': 'Đã gửi yêu cầu mua hàng',
            'CPRID': cprid,
            'TotalEstimated': round(total_estimated, 2),
            'ItemCount': len(prepared),
        }), 201
    except Exception:
        if conn: conn.rollback()
        raise
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/customer-purchase-requests/<cprid>', methods=['GET'])
@limiter.limit("30 per minute")
def get_customer_purchase_request(cprid):
    claims = get_jwt()
    if claims.get('role') not in ('admin',) + ORG_ALL_ROLES:
        return jsonify({'error': 'Forbidden: Không có quyền xem yêu cầu mua', 'code': 403}), 403
    where, params = cpr_visibility_filter(claims)
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    sql = """
        SELECT r.*, o.OrganizationName, o.OrganizationCode, c.CustomerName,
               c.ContactNumber, c.Address
        FROM customer_purchase_requests r
        JOIN organizations o ON o.OrganizationID=r.OrganizationID
        JOIN customer c ON c.CustomerID=r.CustomerID
        WHERE r.CPRID=%s
    """
    if where:
        sql += " AND " + where
    cursor.execute(sql, (cprid,) + tuple(params))
    cpr = cursor.fetchone()
    if not cpr:
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy yêu cầu mua', 'code': 404}), 404
    cpr['Items'] = load_cpr_items(cursor, cprid)
    cursor.execute("SELECT OrderID, Status, ProductID, Quantity FROM orders WHERE SourceCPRID=%s", (cprid,))
    cpr['ConvertedOrders'] = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(json_safe(cpr))


@app.route('/api/customer-purchase-requests/<cprid>/status', methods=['PATCH'])
@limiter.limit("20 per minute")
def update_customer_purchase_request_status(cprid):
    claims = get_jwt()
    role = claims.get('role')
    if role not in ('admin', 'org_manager', 'customer'):
        return jsonify({'error': 'Forbidden: Không có quyền cập nhật yêu cầu mua', 'code': 403}), 403
    d = request.get_json(silent=True) or {}
    extra_fields = set(d.keys()) - {'Status', 'RejectReason'}
    if extra_fields:
        return jsonify({'error': f'Phát hiện trường không được phép (Mass Assignment): {", ".join(sorted(extra_fields))}', 'code': 400}), 400
    new_status = d.get('Status')
    if new_status not in ('Approved', 'Rejected', 'Cancelled'):
        return jsonify({'error': 'Trạng thái không hợp lệ (Approved/Rejected/Cancelled)', 'code': 400}), 400

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM customer_purchase_requests WHERE CPRID=%s FOR UPDATE", (cprid,))
        cpr = cursor.fetchone()
        if not cpr:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy yêu cầu mua', 'code': 404}), 404

        if role != 'admin':
            owns = (role == 'org_manager' and claims.get('organization_id') == cpr['OrganizationID']) or \
                   (role == 'customer' and claims.get('customer_id') == cpr['CustomerID'])
            if not owns:
                conn.rollback()
                return jsonify({'error': 'Forbidden: Không có quyền trên yêu cầu mua này', 'code': 403}), 403
            if new_status != 'Cancelled':
                conn.rollback()
                return jsonify({'error': 'Forbidden: Chỉ quản lý tổ chức/khách hàng được hủy yêu cầu', 'code': 403}), 403

        if cpr['Status'] == new_status:
            conn.commit()
            return jsonify({'message': f'Yêu cầu mua đã ở trạng thái {new_status}'})
        if cpr['Status'] in ('Converted', 'Rejected', 'Cancelled'):
            conn.rollback()
            return jsonify({'error': f'Yêu cầu mua đã ở trạng thái cuối ({cpr["Status"]})', 'code': 409}), 409
        if new_status == 'Cancelled' and cpr['Status'] not in ('Draft', 'Submitted'):
            conn.rollback()
            return jsonify({'error': 'Chỉ có thể hủy yêu cầu đang chờ duyệt', 'code': 409}), 409
        if new_status in ('Approved', 'Rejected') and cpr['Status'] != 'Submitted':
            conn.rollback()
            return jsonify({'error': 'Chỉ có thể duyệt yêu cầu đã gửi', 'code': 409}), 409

        reject_reason = str(d.get('RejectReason') or '').strip()[:255] or None
        if new_status == 'Rejected' and not reject_reason:
            conn.rollback()
            return jsonify({'error': 'Cần nhập RejectReason khi từ chối', 'code': 400}), 400
        if new_status == 'Approved':
            cursor.execute("""
                UPDATE customer_purchase_requests
                SET Status='Approved', ApprovedByName=%s, ApprovedAt=NOW(), RejectReason=NULL
                WHERE CPRID=%s
            """, (current_identity(), cprid))
        elif new_status == 'Rejected':
            cursor.execute("""
                UPDATE customer_purchase_requests SET Status='Rejected', RejectReason=%s WHERE CPRID=%s
            """, (reject_reason, cprid))
        else:
            cursor.execute("UPDATE customer_purchase_requests SET Status='Cancelled' WHERE CPRID=%s", (cprid,))
        conn.commit()
        return jsonify({'message': f'Đã cập nhật yêu cầu mua sang {new_status}', 'CPRID': cprid})
    except Exception:
        if conn: conn.rollback()
        raise
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/customer-purchase-requests/<cprid>/convert', methods=['POST'])
@limiter.limit("10 per minute")
def convert_customer_purchase_request(cprid):
    err = admin_required()
    if err: return err

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM customer_purchase_requests WHERE CPRID=%s FOR UPDATE", (cprid,))
        cpr = cursor.fetchone()
        if not cpr:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy yêu cầu mua', 'code': 404}), 404
        if cpr['Status'] == 'Converted':
            conn.rollback()
            return jsonify({'error': 'Yêu cầu mua đã được chuyển thành đơn bán trước đó', 'code': 409}), 409
        if cpr['Status'] != 'Approved':
            conn.rollback()
            return jsonify({'error': f'Chỉ chuyển yêu cầu đã duyệt (hiện tại: {cpr["Status"]})', 'code': 409}), 409

        items = load_cpr_items(cursor, cprid)
        if not items:
            conn.rollback()
            return jsonify({'error': 'Yêu cầu mua không có dòng hàng', 'code': 409}), 409

        created_by_user_id = user_id_by_username(cursor, get_jwt().get('sub'))
        order_ids = []
        for item in items:
            order_id = next_order_id(cursor)
            quantity = int(item['Quantity'])
            unit_price = float(item['UnitPrice'] or 0)
            bill = round(unit_price * quantity, 2)
            vat_rate = 10
            vat_amount = round(bill * vat_rate / 100, 2)
            cursor.execute("""
                INSERT INTO orders
                    (OrderID, OrderDate, Bill, CustomerID, ProductID, Quantity, Status,
                     InvoiceNumber, VatRate, VatAmount, PaymentMethod,
                     OrganizationID, SourceCPRID, CreatedByUserID)
                VALUES (%s, CURDATE(), %s, %s, %s, %s, 'Pending',
                        NULL, %s, %s, 'Chuyển khoản', %s, %s, %s)
            """, (order_id, bill, cpr['CustomerID'], item['ProductID'], quantity,
                  vat_rate, vat_amount, cpr['OrganizationID'], cprid, created_by_user_id))
            order_ids.append(order_id)

        cursor.execute("""
            UPDATE customer_purchase_requests SET Status='Converted', ConvertedAt=NOW() WHERE CPRID=%s
        """, (cprid,))
        conn.commit()
        return jsonify({
            'message': 'Đã chuyển yêu cầu mua thành đơn bán',
            'CPRID': cprid,
            'OrderIDs': order_ids,
        }), 201
    except IntegrityError:
        if conn: conn.rollback()
        return jsonify({'error': 'Yêu cầu mua đã được chuyển thành đơn bán trước đó', 'code': 409}), 409
    except Exception:
        if conn: conn.rollback()
        raise
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# ══════════════════════════════════════════════════════
#  SUPPLIER
# ══════════════════════════════════════════════════════

@app.route('/api/suppliers', methods=['GET'])
@limiter.limit("30 per minute")
def get_suppliers():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM supplier ORDER BY SupplierID")
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/suppliers', methods=['POST'])
@limiter.limit("10 per minute")
def add_supplier():
    err = admin_required();
    if err: return err
    d = request.get_json(silent=True) or {}
    try:
        rating = int(d.get('Rating', 5))
        on_time_rate = float(d.get('OnTimeRate', 100))
    except (TypeError, ValueError):
        return jsonify({'error': 'Rating hoặc OnTimeRate không hợp lệ', 'code': 400}), 400
    if rating < 1 or rating > 5:
        return jsonify({'error': 'Rating phải trong khoảng 1-5', 'code': 400}), 400
    if on_time_rate < 0 or on_time_rate > 100:
        return jsonify({'error': 'OnTimeRate phải trong khoảng 0-100', 'code': 400}), 400
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO supplier (SupplierID, SupplierName, ContactNumber, Location, TaxCode, Email, Rating, OnTimeRate)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (d['SupplierID'], d['SupplierName'], d['ContactNumber'], d['Location'], d.get('TaxCode'), d.get('Email'), rating, on_time_rate))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Supplier added'}), 201

@app.route('/api/suppliers/<sid>', methods=['PUT'])
@limiter.limit("10 per minute")
def update_supplier(sid):
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, SUPPLIER_ALLOWED_UPDATE)
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    if 'SupplierID' in clean and clean['SupplierID'] != sid:
        return jsonify({'error': 'Không được phép thay đổi mã SupplierID', 'code': 400}), 400
    for req_field in ('SupplierName', 'ContactNumber', 'Location'):
        if not clean.get(req_field):
            return jsonify({'error': f'Thiếu trường bắt buộc: {req_field}', 'code': 400}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT Rating, OnTimeRate FROM supplier WHERE SupplierID=%s", (sid,))
    existing = cursor.fetchone()
    if not existing:
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy nhà cung cấp', 'code': 404}), 404
    try:
        rating = int(clean.get('Rating', existing['Rating']))
        on_time_rate = float(clean.get('OnTimeRate', existing['OnTimeRate']))
    except (TypeError, ValueError):
        cursor.close(); conn.close()
        return jsonify({'error': 'Rating hoặc OnTimeRate không hợp lệ', 'code': 400}), 400
    if rating < 1 or rating > 5:
        cursor.close(); conn.close()
        return jsonify({'error': 'Rating phải trong khoảng 1-5', 'code': 400}), 400
    if on_time_rate < 0 or on_time_rate > 100:
        cursor.close(); conn.close()
        return jsonify({'error': 'OnTimeRate phải trong khoảng 0-100', 'code': 400}), 400
    cursor.execute("""
        UPDATE supplier SET SupplierName=%s, ContactNumber=%s, Location=%s, TaxCode=%s, Email=%s, Rating=%s, OnTimeRate=%s
        WHERE SupplierID=%s
    """, (clean['SupplierName'], clean['ContactNumber'], clean['Location'], clean.get('TaxCode'), clean.get('Email'), rating, on_time_rate, sid))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Supplier updated'})

@app.route('/api/suppliers/<sid>', methods=['DELETE'])
@limiter.limit("10 per minute")
def delete_supplier(sid):
    err = admin_required();
    if err: return err
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM supplier WHERE SupplierID=%s", (sid,))
    if cursor.rowcount == 0:
        conn.rollback(); cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy nhà cung cấp', 'code': 404}), 404
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Supplier deleted'})


# ══════════════════════════════════════════════════════
#  PRODUCT
# ══════════════════════════════════════════════════════

@app.route('/api/products', methods=['GET'])
@limiter.limit("30 per minute")
def get_products():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM product ORDER BY ProductID")
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/products', methods=['POST'])
@limiter.limit("10 per minute")
def add_product():
    err = admin_required();
    if err: return err
    d = request.json
    try:
        unit_price = float(d.get('UnitPrice', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'UnitPrice không hợp lệ', 'code': 400}), 400
    if unit_price < 0:
        return jsonify({'error': 'UnitPrice không được âm', 'code': 400}), 400
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO product (ProductID, ProductName, Category, UnitPrice, SupplierID, Unit, Origin)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (d['ProductID'], d['ProductName'], d['Category'], unit_price, d['SupplierID'], d.get('Unit', 'Cái'), d.get('Origin', 'Việt Nam')))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Product added'}), 201

@app.route('/api/products/<pid>', methods=['PUT'])
@limiter.limit("10 per minute")
def update_product(pid):
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, PRODUCT_ALLOWED_UPDATE)
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    if 'ProductID' in clean and clean['ProductID'] != pid:
        return jsonify({'error': 'Không được phép thay đổi mã ProductID', 'code': 400}), 400
    for req_field in ('ProductName', 'Category', 'UnitPrice', 'SupplierID'):
        if clean.get(req_field) is None or str(clean.get(req_field)).strip() == '':
            return jsonify({'error': f'Thiếu trường bắt buộc: {req_field}', 'code': 400}), 400

    try:
        unit_price = float(clean.get('UnitPrice', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'UnitPrice không hợp lệ', 'code': 400}), 400
    if unit_price < 0:
        return jsonify({'error': 'UnitPrice không được âm', 'code': 400}), 400
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM product WHERE ProductID=%s", (pid,))
    if not cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy sản phẩm', 'code': 404}), 404
    cursor.execute("""
        UPDATE product SET ProductName=%s, Category=%s, UnitPrice=%s, SupplierID=%s, Unit=%s, Origin=%s
        WHERE ProductID=%s
    """, (clean['ProductName'], clean['Category'], unit_price, clean['SupplierID'], clean.get('Unit', 'Cái'), clean.get('Origin', 'Việt Nam'), pid))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Product updated'})

@app.route('/api/products/<pid>', methods=['DELETE'])
@limiter.limit("10 per minute")
def delete_product(pid):
    err = admin_required();
    if err: return err
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM product WHERE ProductID=%s", (pid,))
    if cursor.rowcount == 0:
        conn.rollback(); cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy sản phẩm', 'code': 404}), 404
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Product deleted'})


# ══════════════════════════════════════════════════════
#  WAREHOUSE
# ══════════════════════════════════════════════════════

@app.route('/api/warehouses', methods=['GET'])
@limiter.limit("30 per minute")
def get_warehouses():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM warehouse ORDER BY WarehouseID")
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/warehouses', methods=['POST'])
@limiter.limit("10 per minute")
def add_warehouse():
    err = admin_required();
    if err: return err
    d = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO warehouse (WarehouseID, WarehouseName, Location, Capacity, ProvinceCode)
        VALUES (%s, %s, %s, %s, %s)
    """, (d['WarehouseID'], d['WarehouseName'], d['Location'], d['Capacity'], d.get('ProvinceCode')))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Warehouse added'}), 201

@app.route('/api/warehouses/<wid>', methods=['PUT'])
@limiter.limit("10 per minute")
def update_warehouse(wid):
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, WAREHOUSE_ALLOWED_UPDATE)
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    if 'WarehouseID' in clean and clean['WarehouseID'] != wid:
        return jsonify({'error': 'Không được phép thay đổi mã WarehouseID', 'code': 400}), 400
    for req_field in ('WarehouseName', 'Location', 'Capacity'):
        if clean.get(req_field) is None or str(clean.get(req_field)).strip() == '':
            return jsonify({'error': f'Thiếu trường bắt buộc: {req_field}', 'code': 400}), 400

    try:
        capacity = int(clean.get('Capacity', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'Capacity không hợp lệ', 'code': 400}), 400
    if capacity < 0:
        return jsonify({'error': 'Capacity không được âm', 'code': 400}), 400

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM warehouse WHERE WarehouseID=%s", (wid,))
    if not cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy kho hàng', 'code': 404}), 404
    cursor.execute("""
        UPDATE warehouse SET WarehouseName=%s, Location=%s, Capacity=%s, ProvinceCode=%s
        WHERE WarehouseID=%s
    """, (clean['WarehouseName'], clean['Location'], capacity, clean.get('ProvinceCode'), wid))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Warehouse updated'})

@app.route('/api/warehouses/<wid>', methods=['DELETE'])
@limiter.limit("10 per minute")
def delete_warehouse(wid):
    err = admin_required();
    if err: return err
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM warehouse WHERE WarehouseID=%s", (wid,))
    if cursor.rowcount == 0:
        conn.rollback(); cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy kho hàng', 'code': 404}), 404
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Warehouse deleted'})


# ══════════════════════════════════════════════════════
#  INVENTORY
# ══════════════════════════════════════════════════════

@app.route('/api/inventory', methods=['GET'])
@limiter.limit("30 per minute")
def get_inventory():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM inventory ORDER BY InventoryID")
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/inventory', methods=['POST'])
@limiter.limit("10 per minute")
def add_inventory():
    err = admin_required();
    if err: return err
    d = request.json
    try:
        qty = int(d.get('QuantityAvailable', 0) if d.get('QuantityAvailable') is not None else 0)
    except (TypeError, ValueError):
        return jsonify({'error': 'Số lượng tồn kho không hợp lệ', 'code': 400}), 400
    if qty < 0:
        return jsonify({'error': 'Số lượng tồn kho không được âm (>= 0)', 'code': 400}), 400
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO inventory (InventoryID, QuantityAvailable, ProductID, WarehouseID)
        VALUES (%s, %s, %s, %s)
    """, (d['InventoryID'], qty, d['ProductID'], d['WarehouseID']))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Inventory added'}), 201

@app.route('/api/inventory/<iid>', methods=['PUT'])
@limiter.limit("10 per minute")
def update_inventory(iid):
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, INVENTORY_ALLOWED_UPDATE)
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    if 'InventoryID' in clean and clean['InventoryID'] != iid:
        return jsonify({'error': 'Không được phép thay đổi mã InventoryID', 'code': 400}), 400
    for req_field in ('ProductID', 'WarehouseID'):
        if not clean.get(req_field):
            return jsonify({'error': f'Thiếu trường bắt buộc: {req_field}', 'code': 400}), 400

    try:
        qty = int(clean.get('QuantityAvailable', 0) if clean.get('QuantityAvailable') is not None else 0)
    except (TypeError, ValueError):
        return jsonify({'error': 'Số lượng tồn kho không hợp lệ', 'code': 400}), 400
    if qty < 0:
        return jsonify({'error': 'Số lượng tồn kho không được âm (>= 0)', 'code': 400}), 400
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM inventory WHERE InventoryID=%s", (iid,))
    if not cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy bản ghi tồn kho', 'code': 404}), 404
    cursor.execute("""
        UPDATE inventory SET QuantityAvailable=%s, ProductID=%s, WarehouseID=%s
        WHERE InventoryID=%s
    """, (qty, clean['ProductID'], clean['WarehouseID'], iid))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Inventory updated'})

@app.route('/api/inventory/<iid>', methods=['DELETE'])
@limiter.limit("10 per minute")
def delete_inventory(iid):
    err = admin_required();
    if err: return err
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM inventory WHERE InventoryID=%s", (iid,))
    if cursor.rowcount == 0:
        conn.rollback(); cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy bản ghi tồn kho', 'code': 404}), 404
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Inventory deleted'})

@app.route('/api/inventory/adjust', methods=['POST'])
@limiter.limit("20 per minute")
def adjust_inventory():
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, {'InventoryID', 'NewQuantity', 'Reason'})
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    inventory_id = str(clean.get('InventoryID') or '').strip()
    reason = str(clean.get('Reason') or '').strip()
    if not inventory_id or not reason:
        return jsonify({'error': 'Thiếu InventoryID hoặc Reason', 'code': 400}), 400
    if reason not in ADJUST_REASONS:
        return jsonify({'error': 'Lý do điều chỉnh không hợp lệ', 'code': 400}), 400
    try:
        new_quantity = int(clean.get('NewQuantity'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Số lượng mới không hợp lệ', 'code': 400}), 400
    if new_quantity < 0:
        return jsonify({'error': 'Số lượng mới không được âm', 'code': 400}), 400

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT InventoryID, QuantityAvailable, ProductID, WarehouseID FROM inventory WHERE InventoryID=%s FOR UPDATE",
            (inventory_id,),
        )
        row = cursor.fetchone()
        if not row:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy bản ghi tồn kho', 'code': 404}), 404
        old_quantity = int(row['QuantityAvailable'] or 0)
        cursor.execute(
            "UPDATE inventory SET QuantityAvailable=%s WHERE InventoryID=%s",
            (new_quantity, inventory_id),
        )
        adjustment_id = write_inventory_adjustment(
            cursor, inventory_id, old_quantity, new_quantity, reason
        )
        write_inventory_transaction(
            cursor, inventory_id, row['ProductID'], row['WarehouseID'],
            'ManualAdjustment', new_quantity - old_quantity, old_quantity,
            new_quantity, 'Adjustment', adjustment_id, reason, current_identity(),
        )
        conn.commit()
        return jsonify({
            'message': 'Điều chỉnh tồn kho thành công',
            'AdjustmentID': adjustment_id,
            'OldQuantity': old_quantity,
            'NewQuantity': new_quantity,
        })
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/api/inventory/transactions', methods=['GET'])
@limiter.limit("60 per minute")
def get_inventory_transactions():
    err = admin_required()
    if err: return err
    args = request.args
    filters = []
    params = []
    for field, column in (
        ('product_id', 't.ProductID'),
        ('warehouse_id', 't.WarehouseID'),
        ('transaction_type', 't.TransactionType'),
        ('reference_id', 't.ReferenceID'),
    ):
        value = str(args.get(field) or '').strip()
        if value:
            filters.append(f"{column}=%s")
            params.append(value)
    try:
        limit = min(max(int(args.get('limit', 100)), 1), 500)
    except (TypeError, ValueError):
        return jsonify({'error': 'limit không hợp lệ', 'code': 400}), 400

    where_clause = (' WHERE ' + ' AND '.join(filters)) if filters else ''
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(f"""
        SELECT t.*, p.ProductName, p.Unit, w.WarehouseName
        FROM inventory_transactions t
        LEFT JOIN product p ON p.ProductID = t.ProductID
        LEFT JOIN warehouse w ON w.WarehouseID = t.WarehouseID
        {where_clause}
        ORDER BY t.CreatedAt DESC, t.TransactionID DESC
        LIMIT {limit}
    """, tuple(params))
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(json_safe(data))


# ══════════════════════════════════════════════════════
#  CUSTOMER
# ══════════════════════════════════════════════════════

@app.route('/api/customers', methods=['GET'])
@limiter.limit("30 per minute")
def get_customers():
    err = admin_required();
    if err: return err
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM customer ORDER BY CustomerID")
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/customers', methods=['POST'])
@limiter.limit("10 per minute")
def add_customer():
    err = admin_required();
    if err: return err
    d = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO customer (CustomerID, CustomerName, ContactNumber, Address, TaxCode, CustomerType)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (d['CustomerID'], d['CustomerName'], d['ContactNumber'], d['Address'], d.get('TaxCode'), d.get('CustomerType', 'Individual')))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Customer added'}), 201

@app.route('/api/customers/<cid>', methods=['PUT'])
@limiter.limit("10 per minute")
def update_customer(cid):
    claims = get_jwt()
    role = claims.get("role")
    d = request.get_json(silent=True) or {}

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM customer WHERE CustomerID=%s", (cid,))
        current = cursor.fetchone()
        if not current:
            return jsonify({'error': 'Không tìm thấy khách hàng', 'code': 404}), 404

        if role == "admin":
            clean, err_msg = extract_whitelisted_fields(d, CUSTOMER_ALLOWED_UPDATE)
            if err_msg:
                return jsonify({'error': err_msg, 'code': 400}), 400
            if 'CustomerID' in clean and clean['CustomerID'] != cid:
                return jsonify({'error': 'Không được phép thay đổi mã CustomerID', 'code': 400}), 400
            for req_field in ('CustomerName', 'ContactNumber', 'Address'):
                if not clean.get(req_field):
                    return jsonify({'error': f'Thiếu trường bắt buộc: {req_field}', 'code': 400}), 400
            customer_name = clean['CustomerName']
            contact_number = clean['ContactNumber']
            address = clean['Address']
            tax_code = clean.get('TaxCode')
            customer_type = clean.get('CustomerType', 'Individual')
            if customer_type not in ('Business', 'Individual'):
                return jsonify({'error': 'CustomerType không hợp lệ', 'code': 400}), 400
        else:
            # Khách hàng chỉ được tự sửa SĐT và Địa chỉ của chính mình
            if not claims.get('customer_id') or claims.get('customer_id') != cid:
                return jsonify({'error': 'Forbidden: Không có quyền sửa hồ sơ khách hàng khác', 'code': 403}), 403
            clean, err_msg = extract_whitelisted_fields(d, {'ContactNumber', 'Address'})
            if err_msg:
                return jsonify({'error': err_msg, 'code': 400}), 400
            for req_field in ('ContactNumber', 'Address'):
                if not str(clean.get(req_field) or '').strip():
                    return jsonify({'error': f'Thiếu trường bắt buộc: {req_field}', 'code': 400}), 400
            customer_name = current['CustomerName']
            contact_number = clean['ContactNumber']
            address = clean['Address']
            tax_code = current.get('TaxCode')
            customer_type = current.get('CustomerType', 'Individual')

        cursor.execute("""
            UPDATE customer SET CustomerName=%s, ContactNumber=%s, Address=%s, TaxCode=%s, CustomerType=%s
            WHERE CustomerID=%s
        """, (customer_name, contact_number, address, tax_code, customer_type, cid))
        conn.commit()
        return jsonify({'message': 'Customer updated'})
    except Exception as e:
        conn.rollback()
        app.logger.error("CUSTOMER UPDATE FAILED | CustomerID=%s | %s: %s", cid, type(e).__name__, e, exc_info=True)
        raise
    finally:
        cursor.close()
        conn.close()

@app.route('/api/customers/<cid>', methods=['DELETE'])
@limiter.limit("10 per minute")
def delete_customer(cid):
    err = admin_required();
    if err: return err
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM customer WHERE CustomerID=%s", (cid,))
    if cursor.rowcount == 0:
        conn.rollback(); cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy khách hàng', 'code': 404}), 404
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Customer deleted'})


# ══════════════════════════════════════════════════════
#  ORDERS (now includes ProductID)
# ══════════════════════════════════════════════════════

@app.route('/api/orders', methods=['GET'])
@limiter.limit("30 per minute")
def get_orders():
    claims = get_jwt()
    role = claims.get("role")
    cid  = claims.get("customer_id")
    org_id = claims.get("organization_id")
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    base_sql = """
        SELECT o.*, c.CustomerName, org.OrganizationName
        FROM orders o
        LEFT JOIN customer c ON c.CustomerID = o.CustomerID
        LEFT JOIN organizations org ON org.OrganizationID = o.OrganizationID
    """
    if role == "admin":
        cursor.execute(base_sql + " ORDER BY o.OrderDate DESC, o.OrderID DESC")
    elif role in ORG_ROLES:
        if not org_id:
            cursor.close(); conn.close()
            return jsonify({'error': 'Tài khoản chưa thuộc tổ chức nào', 'code': 403}), 403
        cursor.execute(
            base_sql + " WHERE o.OrganizationID=%s ORDER BY o.OrderDate DESC, o.OrderID DESC",
            (org_id,)
        )
    else:
        # Customers only see their own orders (VULN-02 fix)
        cursor.execute(
            base_sql + " WHERE o.CustomerID=%s ORDER BY o.OrderDate DESC, o.OrderID DESC",
            (cid,)
        )
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(json_safe(data))

@app.route('/api/orders', methods=['POST'])
@limiter.limit("10 per minute")
def add_order():
    claims = get_jwt()
    role = claims.get("role")
    cid = claims.get("customer_id")
    org_id = claims.get("organization_id")
    raw_d = request.get_json(silent=True) or {}

    clean, err_msg = extract_whitelisted_fields(raw_d, ORDER_ALLOWED_CREATE)
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400

    for req_field in ('OrderDate', 'ProductID'):
        if not clean.get(req_field):
            return jsonify({'error': f'Thiếu trường bắt buộc: {req_field}', 'code': 400}), 400

    # Parameter Pollution & Privilege Escalation Mitigation:
    # Server-side authorization check (CWE-602): enforce identity from JWT claims
    if role == "admin":
        customer_id = clean.get('CustomerID')
        if not customer_id:
            return jsonify({'error': 'Thiếu mã khách hàng', 'code': 400}), 400
        order_status = 'Pending'
        invoice_number = clean.get('InvoiceNumber')
        try:
            vat_rate = float(clean.get('VatRate') if clean.get('VatRate') is not None else 10)
        except (TypeError, ValueError):
            return jsonify({'error': 'VatRate không hợp lệ', 'code': 400}), 400
        if vat_rate < 0 or vat_rate > 100:
            return jsonify({'error': 'VatRate phải trong khoảng 0-100', 'code': 400}), 400
        order_organization_id = None
    elif role in ORG_ROLES:
        if not org_id:
            return jsonify({'error': 'Tài khoản chưa thuộc tổ chức nào', 'code': 403}), 403
        customer_id = None  # resolved from OrganizationID inside transaction
        order_status = 'Pending'
        invoice_number = None
        vat_rate = 10
        order_organization_id = org_id
    else:
        if not cid:
            return jsonify({'error': 'Forbidden: Yêu cầu đăng nhập tài khoản khách hàng', 'code': 403}), 403
        customer_id = cid
        # Khách hàng không được tự đặt Status/Invoice/VAT — server ép giá trị an toàn
        order_status = 'Pending'
        invoice_number = None
        vat_rate = 10
        order_organization_id = None

    try:
        qty = int(clean.get('Quantity') or 1)
    except (TypeError, ValueError):
        return jsonify({'error': 'Số lượng không hợp lệ', 'code': 400}), 400
    if qty < 1:
        return jsonify({'error': 'Số lượng phải lớn hơn 0', 'code': 400}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    order_id = None
    try:
        if role in ORG_ROLES:
            customer_id = find_org_customer_id(cursor, order_organization_id)
            if not customer_id:
                return jsonify({'error': 'Tổ chức chưa liên kết hồ sơ khách hàng', 'code': 409}), 409
        else:
            cursor.execute("SELECT OrganizationID FROM customer WHERE CustomerID=%s", (customer_id,))
            customer_row = cursor.fetchone()
            if not customer_row:
                cursor.close(); conn.close()
                return jsonify({'error': 'Không tìm thấy khách hàng', 'code': 404}), 404
            order_organization_id = customer_row.get('OrganizationID')

        cursor.execute("SELECT UnitPrice FROM product WHERE ProductID=%s", (clean['ProductID'],))
        prod = cursor.fetchone()
        if not prod:
            return jsonify({'error': 'Sản phẩm không tồn tại', 'code': 400}), 400

        # Calculate or validate bill securely
        if role != "admin":
            # Customer/org cannot tamper with Bill — calculated server-side from catalog price
            bill = round(float(prod['UnitPrice']) * qty, 2)
        else:
            try:
                bill = float(clean.get('Bill') if clean.get('Bill') is not None else float(prod['UnitPrice']) * qty)
            except (TypeError, ValueError):
                return jsonify({'error': 'Bill không hợp lệ', 'code': 400}), 400
            if bill < 0:
                return jsonify({'error': 'Bill không được âm', 'code': 400}), 400

        # VatAmount luôn được tính ở server, không tin giá trị từ client
        vat_amount = round(bill * vat_rate / 100, 2)

        # OrderID do server sinh; customer không bao giờ kiểm soát khóa chính.
        # Admin có thể truyền OrderID thủ công (form quản trị), ngược lại sinh tự động.
        client_order_id = (clean.get('OrderID') or '').strip() if role == "admin" else None
        order_id = client_order_id or next_order_id(cursor)

        created_by_user_id = user_id_by_username(cursor, claims.get('sub'))
        cursor.execute("""
            INSERT INTO orders (OrderID, OrderDate, Bill, CustomerID, ProductID, Quantity, Status,
                                InvoiceNumber, VatRate, VatAmount, PaymentMethod,
                                OrganizationID, CreatedByUserID)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (order_id, clean['OrderDate'], bill, customer_id, clean['ProductID'], qty, order_status,
              invoice_number, vat_rate, vat_amount, clean.get('PaymentMethod') or 'Tiền mặt',
              order_organization_id, created_by_user_id))

        # Admin nhập tay ORD<số>: đẩy sequence vượt qua ID đó để tránh đụng sau này
        if client_order_id:
            match = re.fullmatch(r'ORD(\d+)', client_order_id)
            if match:
                cursor.execute(
                    "UPDATE order_id_sequence SET next_value = GREATEST(next_value, %s) WHERE id = 1",
                    (int(match.group(1)) + 1,),
                )

        conn.commit()
        return jsonify({'message': 'Order added', 'OrderID': order_id}), 201

    except IntegrityError as e:
        conn.rollback()
        app.logger.warning(
            "ORDER CONFLICT | OrderID=%s | CustomerID=%s | ProductID=%s | Quantity=%s | Role=%s | errno=%s | %s",
            order_id, customer_id, clean.get('ProductID'), qty, role, e.errno, e.msg,
        )
        print(
            f"[ORDER INTEGRITY ERROR] OrderID={order_id} CustomerID={customer_id} "
            f"ProductID={clean.get('ProductID')} Quantity={qty} Role={role} -> {e.errno}: {e.msg}",
            flush=True
        )
        if e.errno == errorcode.ER_DUP_ENTRY:
            return jsonify({
                'error': 'Mã đơn hàng đã tồn tại. Vui lòng thử lại.',
                'code': 400,
                'error_code': 'DUPLICATE_ORDER_ID'
            }), 400
        return jsonify({
            'error': 'Dữ liệu đơn hàng không hợp lệ.',
            'code': 400,
            'error_code': 'INVALID_ORDER_DATA'
        }), 400

    except mysql.connector.Error as e:
        conn.rollback()
        app.logger.error(
            "ORDER DB ERROR | OrderID=%s | CustomerID=%s | ProductID=%s | Quantity=%s | Role=%s | %s: %s",
            order_id, customer_id, clean.get('ProductID'), qty, role, type(e).__name__, e,
            exc_info=True
        )
        print(
            f"[ORDER DB ERROR] OrderID={order_id} CustomerID={customer_id} "
            f"ProductID={clean.get('ProductID')} Quantity={qty} Role={role} -> {type(e).__name__}: {e}",
            flush=True
        )
        return jsonify({'error': 'Lỗi hệ thống. Vui lòng thử lại.', 'code': 500}), 500

    except Exception as e:
        conn.rollback()
        app.logger.exception("ORDER UNEXPECTED ERROR | %s", e)
        return jsonify({'error': 'Lỗi hệ thống. Vui lòng thử lại.', 'code': 500}), 500

    finally:
        cursor.close()
        conn.close()

@app.route('/api/orders/<oid>', methods=['PUT'])
@limiter.limit("10 per minute")
def update_order(oid):
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}

    # Mass Assignment Protection: Status is strictly forbidden via PUT /orders/<oid>
    if 'Status' in d:
        return jsonify({
            'error': 'Trường Status không được phép cập nhật qua API này. Vui lòng sử dụng quy trình duyệt đơn.',
            'code': 400
        }), 400

    clean, err_msg = extract_whitelisted_fields(d, ORDER_ALLOWED_UPDATE)
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    if 'OrderID' in clean and clean['OrderID'] != oid:
        return jsonify({'error': 'Không được phép thay đổi mã OrderID', 'code': 400}), 400

    for req_field in ('OrderDate', 'CustomerID', 'ProductID', 'Quantity'):
        if not clean.get(req_field):
            return jsonify({'error': f'Thiếu trường bắt buộc: {req_field}', 'code': 400}), 400

    try:
        qty = int(clean.get('Quantity', 1) or 1)
    except (TypeError, ValueError):
        return jsonify({'error': 'Số lượng không hợp lệ', 'code': 400}), 400
    if qty < 1:
        return jsonify({'error': 'Số lượng phải lớn hơn 0', 'code': 400}), 400

    # Business Logic Guard: Check existing order and status
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT Status FROM orders WHERE OrderID=%s", (oid,))
    existing = cursor.fetchone()
    if not existing:
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy đơn hàng', 'code': 404}), 404

    # Business logic flaw patch: Cannot update orders in final state (Accepted/Rejected)
    current_status = existing.get('Status', 'Pending')
    if current_status in ('Accepted', 'Rejected'):
        cursor.close(); conn.close()
        return jsonify({
            'error': f'Không thể sửa đơn hàng đã ở trạng thái {current_status}. Chỉ cho phép cập nhật khi đơn hàng đang ở trạng thái Pending.',
            'code': 400
        }), 400

    cursor.execute("SELECT UnitPrice FROM product WHERE ProductID=%s", (clean['ProductID'],))
    prod = cursor.fetchone()
    if not prod:
        cursor.close(); conn.close()
        return jsonify({'error': 'Sản phẩm không tồn tại', 'code': 400}), 400

    try:
        bill = float(clean.get('Bill') if clean.get('Bill') is not None else float(prod['UnitPrice']) * qty)
    except (TypeError, ValueError):
        cursor.close(); conn.close()
        return jsonify({'error': 'Bill không hợp lệ', 'code': 400}), 400
    if bill < 0:
        cursor.close(); conn.close()
        return jsonify({'error': 'Bill không được âm', 'code': 400}), 400

    vat_rate = clean.get('VatRate', 10)
    vat_amount = clean.get('VatAmount', round(bill * vat_rate / 100))

    cursor.execute("""
        UPDATE orders SET OrderDate=%s, Bill=%s, CustomerID=%s, ProductID=%s, Quantity=%s, Status='Pending', InvoiceNumber=%s, VatRate=%s, VatAmount=%s, PaymentMethod=%s
        WHERE OrderID=%s
    """, (clean['OrderDate'], bill, clean['CustomerID'], clean['ProductID'], qty, clean.get('InvoiceNumber'), vat_rate, vat_amount, clean.get('PaymentMethod', 'Tiền mặt'), oid))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Order updated'})

@app.route('/api/orders/<oid>', methods=['DELETE'])
@limiter.limit("10 per minute")
def delete_order(oid):
    err = admin_required();
    if err: return err
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT Status FROM orders WHERE OrderID=%s", (oid,))
    row = cursor.fetchone()
    if not row:
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy đơn hàng', 'code': 404}), 404
    if row['Status'] != 'Pending':
        cursor.close(); conn.close()
        return jsonify({'error': 'Chỉ có thể xóa đơn hàng đang chờ duyệt (Pending)', 'code': 409}), 409
    cursor.execute("DELETE FROM orders WHERE OrderID=%s", (oid,))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Order deleted'})

@app.route('/api/orders/<oid>/status', methods=['PATCH'])
@limiter.limit("10 per minute")
def update_order_status(oid):
    claims = get_jwt()
    role = claims.get("role")
    cid = claims.get("customer_id")
    org_id = claims.get("organization_id")
    d = request.get_json(silent=True) or {}

    # Mass Assignment Whitelist check for PATCH
    allowed_patch_fields = {'Status'}
    extra_fields = set(d.keys()) - allowed_patch_fields
    if extra_fields:
        return jsonify({
            'error': f'Phát hiện trường không được phép (Mass Assignment): {", ".join(sorted(extra_fields))}',
            'code': 400
        }), 400

    new_status = d.get('Status')
    if new_status not in ('Accepted', 'Pending', 'Processing', 'Completed', 'Rejected', 'Cancelled'):
        return jsonify({'error': 'Trạng thái không hợp lệ (Pending/Accepted/Processing/Completed/Rejected/Cancelled)', 'code': 400}), 400

    # Phân quyền: khách hàng/tổ chức chỉ được hủy đơn của chính mình
    if role not in ('admin', 'customer', 'org_manager', 'org_staff'):
        return jsonify({'error': 'Forbidden: Không có quyền thao tác đơn hàng', 'code': 403}), 403
    if role != "admin" and new_status != "Cancelled":
        return jsonify({'error': 'Forbidden: Chỉ quản trị viên được duyệt/chuyển trạng thái đơn hàng', 'code': 403}), 403

    conn = get_connection()
    cursor = None
    try:
        # TOCTOU & Race Condition Prevention: Start explicit transaction
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)

        # Row-level locking on the target order
        cursor.execute(
            "SELECT ProductID, CustomerID, OrganizationID, Status, Quantity FROM orders WHERE OrderID=%s FOR UPDATE",
            (oid,)
        )
        order = cursor.fetchone()
        if not order:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy đơn hàng', 'code': 404}), 404

        if role == 'customer' and (not cid or order.get('CustomerID') != cid):
            conn.rollback()
            return jsonify({'error': 'Forbidden: Không có quyền thao tác trên đơn hàng này', 'code': 403}), 403
        if role in ORG_ROLES and (not org_id or order.get('OrganizationID') != org_id):
            conn.rollback()
            return jsonify({'error': 'Forbidden: Không có quyền thao tác trên đơn hàng này', 'code': 403}), 403

        # Idempotent check: trạng thái đã đúng yêu cầu thì không xử lý lại
        if new_status == order['Status']:
            conn.commit()
            return jsonify({'message': f'Đơn hàng đã ở trạng thái {new_status}'})

        allowed_transitions = {
            'Pending': {'Accepted', 'Rejected', 'Cancelled'},
            'Accepted': {'Processing', 'Completed'},
            'Processing': {'Completed'},
            'Rejected': set(),
            'Cancelled': set(),
            'Completed': set(),
        }
        if new_status not in allowed_transitions.get(order['Status'], set()):
            conn.rollback()
            return jsonify({
                'error': f'Không thể chuyển đơn từ {order["Status"]} sang {new_status}',
                'code': 409,
            }), 409

        # Chuyển sang Accepted: trừ đúng Quantity đơn vị tồn kho với Row-Level Locking (SELECT ... FOR UPDATE)
        if new_status == 'Accepted':
            cursor.execute(
                "SELECT InventoryID, QuantityAvailable, WarehouseID FROM inventory WHERE ProductID=%s ORDER BY QuantityAvailable DESC FOR UPDATE",
                (order['ProductID'],)
            )
            rows = cursor.fetchall()
            need = int(order.get('Quantity') or 1)
            total_available = sum(r['QuantityAvailable'] for r in rows)
            if total_available < need:
                conn.rollback()
                return jsonify({'error': f'Sản phẩm không đủ tồn kho (Còn {total_available}, yêu cầu {need})', 'code': 409}), 409

            performed_by = current_identity()
            for r in rows:
                take = min(r['QuantityAvailable'], need)
                if take > 0:
                    cursor.execute(
                        "UPDATE inventory SET QuantityAvailable = QuantityAvailable - %s WHERE InventoryID = %s AND QuantityAvailable >= %s",
                        (take, r['InventoryID'], take)
                    )
                    if cursor.rowcount == 0:
                        conn.rollback()
                        return jsonify({'error': 'Xung đột dữ liệu tồn kho. Vui lòng thử lại.', 'code': 409}), 409
                    qty_after = int(r['QuantityAvailable']) - take
                    write_inventory_transaction(
                        cursor, r['InventoryID'], order['ProductID'], r['WarehouseID'],
                        'SalesIssue', -take, int(r['QuantityAvailable']), qty_after,
                        'Order', oid, f'Xuất kho cho đơn {oid}', performed_by,
                    )
                    need -= take
                if need == 0:
                    break

            if need > 0:
                conn.rollback()
                return jsonify({'error': 'Sản phẩm đã hết hàng', 'code': 409}), 409

        cursor.execute("UPDATE orders SET Status=%s WHERE OrderID=%s", (new_status, oid))
        conn.commit()
        return jsonify({'message': 'Order status updated', 'OrderID': oid, 'Status': new_status})
    except Exception as e:
        if conn:
            conn.rollback()
        app.logger.error("Error updating order status (TOCTOU guard): %s", str(e))
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ══════════════════════════════════════════════════════
#  PURCHASE REQUISITIONS
# ══════════════════════════════════════════════════════

@app.route('/api/purchase-requisitions', methods=['GET'])
@limiter.limit("30 per minute")
def get_purchase_requisitions():
    err = admin_required()
    if err: return err
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT pr.*,
               (SELECT COUNT(*) FROM purchase_requisition_items i WHERE i.PRID=pr.PRID) AS ItemCount
        FROM purchase_requisitions pr
        ORDER BY pr.CreatedAt DESC, pr.PRID DESC
    """)
    data = cursor.fetchall()
    for row in data:
        cursor.execute("""
            SELECT i.LineNo, i.ProductID, i.Quantity, p.ProductName, p.Unit, p.UnitPrice
            FROM purchase_requisition_items i
            JOIN product p ON p.ProductID=i.ProductID
            WHERE i.PRID=%s ORDER BY i.LineNo
        """, (row['PRID'],))
        row['Items'] = cursor.fetchall()
        if row.get('ProductID'):
            row.setdefault('LegacyProductID', row['ProductID'])
    cursor.close(); conn.close()
    return jsonify(json_safe(data))


@app.route('/api/purchase-requisitions', methods=['POST'])
@limiter.limit("10 per minute")
def add_purchase_requisition():
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(
        d, {'Items', 'ProductID', 'Quantity', 'Reason', 'WarehouseID', 'RequestedBy'}
    )
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400

    raw_items = clean.get('Items')
    if raw_items is None:
        raw_items = [{'ProductID': clean.get('ProductID'), 'Quantity': clean.get('Quantity')}]
    if not isinstance(raw_items, list) or not raw_items or len(raw_items) > 50:
        return jsonify({'error': 'Items phải là danh sách 1-50 dòng hàng', 'code': 400}), 400

    items = []
    seen_products = set()
    for line_no, entry in enumerate(raw_items, start=1):
        if not isinstance(entry, dict):
            return jsonify({'error': f'Dòng hàng {line_no} không hợp lệ', 'code': 400}), 400
        product_id = str(entry.get('ProductID') or '').strip()
        try:
            quantity = int(entry.get('Quantity'))
        except (TypeError, ValueError):
            return jsonify({'error': f'Quantity không hợp lệ ở dòng {line_no}', 'code': 400}), 400
        if not product_id:
            return jsonify({'error': f'Thiếu ProductID ở dòng {line_no}', 'code': 400}), 400
        if quantity < 1:
            return jsonify({'error': f'Quantity phải lớn hơn 0 ở dòng {line_no}', 'code': 400}), 400
        if product_id in seen_products:
            return jsonify({'error': f'Sản phẩm {product_id} bị lặp trong yêu cầu', 'code': 400}), 400
        seen_products.add(product_id)
        items.append((product_id, quantity))

    warehouse_id = str(clean.get('WarehouseID') or '').strip() or None
    reason = str(clean.get('Reason') or '').strip()[:255] or None
    requested_by = str(clean.get('RequestedBy') or get_jwt().get('sub') or 'admin').strip()[:50]

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        if warehouse_id:
            cursor.execute("SELECT 1 FROM warehouse WHERE WarehouseID=%s", (warehouse_id,))
            if not cursor.fetchone():
                conn.rollback()
                return jsonify({'error': 'Kho không tồn tại', 'code': 400}), 400
        for product_id, _ in items:
            cursor.execute("SELECT 1 FROM product WHERE ProductID=%s", (product_id,))
            if not cursor.fetchone():
                conn.rollback()
                return jsonify({'error': f'Sản phẩm {product_id} không tồn tại', 'code': 400}), 400

        prid = next_entity_id(cursor, 'PR', 'PR')
        first_product, first_quantity = items[0]
        cursor.execute("""
            INSERT INTO purchase_requisitions
                (PRID, ProductID, Quantity, RequestedBy, Status, Reason, WarehouseID, CreatedByUserID)
            VALUES (%s, %s, %s, %s, 'Pending_Approval', %s, %s, %s)
        """, (prid, first_product, first_quantity, requested_by, reason, warehouse_id,
              user_id_by_username(cursor, get_jwt().get('sub'))))
        for line_no, (product_id, quantity) in enumerate(items, start=1):
            cursor.execute("""
                INSERT INTO purchase_requisition_items (PRID, LineNo, ProductID, Quantity)
                VALUES (%s, %s, %s, %s)
            """, (prid, line_no, product_id, quantity))
        conn.commit()
        return jsonify({
            'message': 'Đã tạo yêu cầu mua hàng',
            'PRID': prid,
            'ItemCount': len(items),
        }), 201
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/purchase-requisitions/<prid>/status', methods=['PATCH'])
@limiter.limit("20 per minute")
def update_purchase_requisition_status(prid):
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    extra_fields = set(d.keys()) - {'Status'}
    if extra_fields:
        return jsonify({'error': f'Phát hiện trường không được phép (Mass Assignment): {", ".join(sorted(extra_fields))}', 'code': 400}), 400
    new_status = d.get('Status')
    if new_status not in ('Approved', 'Rejected', 'Cancelled'):
        return jsonify({'error': 'Trạng thái không hợp lệ (Approved/Rejected/Cancelled)', 'code': 400}), 400

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT Status FROM purchase_requisitions WHERE PRID=%s FOR UPDATE", (prid,))
        row = cursor.fetchone()
        if not row:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy yêu cầu mua hàng', 'code': 404}), 404
        if row['Status'] == new_status:
            conn.commit()
            return jsonify({'message': f'Yêu cầu mua đã ở trạng thái {new_status}'})
        if row['Status'] not in ('Pending_Approval', 'Draft'):
            conn.rollback()
            return jsonify({'error': f'Không thể duyệt yêu cầu ở trạng thái {row["Status"]}', 'code': 409}), 409
        if new_status == 'Approved':
            cursor.execute("""
                UPDATE purchase_requisitions
                SET Status='Approved', ApprovedBy=%s, ApprovedAt=NOW()
                WHERE PRID=%s
            """, (current_identity(), prid))
        else:
            cursor.execute("UPDATE purchase_requisitions SET Status=%s WHERE PRID=%s", (new_status, prid))
        conn.commit()
        return jsonify({'message': 'Cập nhật trạng thái yêu cầu mua hàng thành công', 'PRID': prid, 'Status': new_status})
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ══════════════════════════════════════════════════════
#  PURCHASE ORDERS
# ══════════════════════════════════════════════════════

@app.route('/api/purchase-orders', methods=['GET'])
@limiter.limit("30 per minute")
def get_purchase_orders():
    err = admin_required()
    if err: return err
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT po.*, s.SupplierName, p.ProductName, p.Unit, pr.RequestedBy,
               (SELECT COUNT(*) FROM purchase_order_items i WHERE i.POID=po.POID) AS ItemCount,
               (SELECT COALESCE(SUM(i.Quantity),0) FROM purchase_order_items i WHERE i.POID=po.POID) AS TotalQuantity,
               (SELECT COALESCE(SUM(i.ReceivedQuantity),0) FROM purchase_order_items i WHERE i.POID=po.POID) AS ReceivedQuantity
        FROM purchase_orders po
        JOIN supplier s ON s.SupplierID = po.SupplierID
        LEFT JOIN product p ON p.ProductID = po.ProductID
        LEFT JOIN purchase_requisitions pr ON pr.PRID = po.PRID
        ORDER BY po.OrderDate DESC, po.POID DESC
    """)
    data = cursor.fetchall()
    for row in data:
        cursor.execute("""
            SELECT i.LineNo, i.ProductID, i.Quantity, i.UnitPrice, i.LineTotal, i.ReceivedQuantity,
                   p.ProductName, p.Unit
            FROM purchase_order_items i
            JOIN product p ON p.ProductID=i.ProductID
            WHERE i.POID=%s ORDER BY i.LineNo
        """, (row['POID'],))
        row['Items'] = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(json_safe(data))


@app.route('/api/purchase-orders', methods=['POST'])
@limiter.limit("10 per minute")
def add_purchase_order():
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(
        d, {'PRID', 'SupplierID', 'ProductID', 'Quantity', 'UnitPrice', 'OrderDate',
            'ExpectedDate', 'WarehouseID', 'TaxAmount', 'ShippingFee', 'Notes', 'Items'}
    )
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400

    supplier_id = str(clean.get('SupplierID') or '').strip()
    if not supplier_id:
        return jsonify({'error': 'Thiếu trường bắt buộc: SupplierID', 'code': 400}), 400
    try:
        order_date = parse_iso_date(clean.get('OrderDate') or date.today().isoformat(), 'OrderDate')
        expected_date = parse_iso_date(clean.get('ExpectedDate'), 'ExpectedDate') if clean.get('ExpectedDate') else None
    except ValueError as e:
        return jsonify({'error': str(e), 'code': 400}), 400
    warehouse_id = str(clean.get('WarehouseID') or '').strip() or None
    try:
        tax_amount = float(clean.get('TaxAmount') or 0)
        shipping_fee = float(clean.get('ShippingFee') or 0)
    except (TypeError, ValueError):
        return jsonify({'error': 'TaxAmount/ShippingFee không hợp lệ', 'code': 400}), 400
    if tax_amount < 0 or shipping_fee < 0:
        return jsonify({'error': 'TaxAmount/ShippingFee không được âm', 'code': 400}), 400
    notes = str(clean.get('Notes') or '').strip()[:255] or None

    prid = str(clean.get('PRID') or '').strip()
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT 1 FROM supplier WHERE SupplierID=%s", (supplier_id,))
        if not cursor.fetchone():
            conn.rollback()
            return jsonify({'error': 'Nhà cung cấp không tồn tại', 'code': 400}), 400
        if warehouse_id:
            cursor.execute("SELECT 1 FROM warehouse WHERE WarehouseID=%s", (warehouse_id,))
            if not cursor.fetchone():
                conn.rollback()
                return jsonify({'error': 'Kho không tồn tại', 'code': 400}), 400

        pr = None
        lines = []
        if prid:
            cursor.execute("""
                SELECT PRID, ProductID, Quantity, Status
                FROM purchase_requisitions WHERE PRID=%s FOR UPDATE
            """, (prid,))
            pr = cursor.fetchone()
            if not pr:
                conn.rollback()
                return jsonify({'error': 'Không tìm thấy yêu cầu mua hàng', 'code': 404}), 404
            if pr['Status'] != 'Approved':
                conn.rollback()
                return jsonify({'error': 'Chỉ có thể tạo đơn mua từ yêu cầu đã duyệt', 'code': 409}), 409
            cursor.execute("""
                SELECT POID FROM purchase_orders
                WHERE PRID=%s AND Status <> 'Cancelled' LIMIT 1
            """, (prid,))
            if cursor.fetchone():
                conn.rollback()
                return jsonify({'error': 'Yêu cầu mua hàng này đã có đơn mua', 'code': 409}), 409

            cursor.execute("""
                SELECT i.ProductID, i.Quantity, p.UnitPrice
                FROM purchase_requisition_items i
                JOIN product p ON p.ProductID=i.ProductID
                WHERE i.PRID=%s ORDER BY i.LineNo
            """, (prid,))
            lines = [
                {'ProductID': r['ProductID'], 'Quantity': int(r['Quantity']), 'UnitPrice': float(r['UnitPrice'] or 0)}
                for r in cursor.fetchall()
            ]
            if not lines and pr.get('ProductID') and pr.get('Quantity'):
                cursor.execute("SELECT UnitPrice FROM product WHERE ProductID=%s", (pr['ProductID'],))
                prod = cursor.fetchone()
                lines = [{'ProductID': pr['ProductID'], 'Quantity': int(pr['Quantity']),
                          'UnitPrice': float((prod or {}).get('UnitPrice') or 0)}]
            if not lines:
                conn.rollback()
                return jsonify({'error': 'Yêu cầu mua không có dòng hàng', 'code': 409}), 409
        else:
            raw_items = clean.get('Items')
            if raw_items is None:
                raw_items = [{'ProductID': clean.get('ProductID'), 'Quantity': clean.get('Quantity'),
                              'UnitPrice': clean.get('UnitPrice')}]
            if not isinstance(raw_items, list) or not raw_items or len(raw_items) > 50:
                conn.rollback()
                return jsonify({'error': 'Items phải là danh sách 1-50 dòng hàng', 'code': 400}), 400
            seen_products = set()
            for line_no, entry in enumerate(raw_items, start=1):
                if not isinstance(entry, dict):
                    conn.rollback()
                    return jsonify({'error': f'Dòng hàng {line_no} không hợp lệ', 'code': 400}), 400
                product_id = str(entry.get('ProductID') or '').strip()
                if not product_id:
                    conn.rollback()
                    return jsonify({'error': f'Thiếu ProductID ở dòng {line_no}', 'code': 400}), 400
                if product_id in seen_products:
                    conn.rollback()
                    return jsonify({'error': f'Sản phẩm {product_id} bị lặp trong đơn mua', 'code': 400}), 400
                seen_products.add(product_id)
                try:
                    quantity = int(entry.get('Quantity'))
                except (TypeError, ValueError):
                    conn.rollback()
                    return jsonify({'error': f'Quantity không hợp lệ ở dòng {line_no}', 'code': 400}), 400
                if quantity < 1:
                    conn.rollback()
                    return jsonify({'error': f'Quantity phải lớn hơn 0 ở dòng {line_no}', 'code': 400}), 400
                cursor.execute("SELECT UnitPrice FROM product WHERE ProductID=%s", (product_id,))
                prod = cursor.fetchone()
                if not prod:
                    conn.rollback()
                    return jsonify({'error': f'Sản phẩm {product_id} không tồn tại', 'code': 400}), 400
                raw_price = entry.get('UnitPrice')
                try:
                    unit_price = float(raw_price) if raw_price not in (None, '') else float(prod['UnitPrice'] or 0)
                except (TypeError, ValueError):
                    conn.rollback()
                    return jsonify({'error': f'UnitPrice không hợp lệ ở dòng {line_no}', 'code': 400}), 400
                if unit_price < 0:
                    conn.rollback()
                    return jsonify({'error': f'UnitPrice không được âm ở dòng {line_no}', 'code': 400}), 400
                lines.append({'ProductID': product_id, 'Quantity': quantity, 'UnitPrice': unit_price})

        subtotal = round(sum(line['Quantity'] * line['UnitPrice'] for line in lines), 2)
        first = lines[0]
        poid = next_entity_id(cursor, 'PO', 'PO')
        cursor.execute("""
            INSERT INTO purchase_orders
                (POID, PRID, SupplierID, ProductID, Quantity, UnitPrice, TotalAmount, Status,
                 OrderDate, ExpectedDate, WarehouseID, TaxAmount, ShippingFee, Notes, CreatedByUserID)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'Ordered', %s, %s, %s, %s, %s, %s, %s)
        """, (poid, prid or None, supplier_id, first['ProductID'], first['Quantity'],
              first['UnitPrice'], subtotal, order_date, expected_date, warehouse_id,
              tax_amount, shipping_fee, notes, user_id_by_username(cursor, get_jwt().get('sub'))))
        for line_no, line in enumerate(lines, start=1):
            line_total = round(line['Quantity'] * line['UnitPrice'], 2)
            cursor.execute("""
                INSERT INTO purchase_order_items
                    (POID, LineNo, ProductID, Quantity, UnitPrice, LineTotal, ReceivedQuantity)
                VALUES (%s, %s, %s, %s, %s, %s, 0)
            """, (poid, line_no, line['ProductID'], line['Quantity'], line['UnitPrice'], line_total))
        if prid:
            cursor.execute("UPDATE purchase_requisitions SET Status='Converted' WHERE PRID=%s", (prid,))
        conn.commit()
        return jsonify({
            'message': 'Đã tạo đơn mua hàng',
            'POID': poid,
            'TotalAmount': subtotal,
            'ItemCount': len(lines),
            'GrandTotal': round(subtotal + tax_amount + shipping_fee, 2),
        }), 201
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/purchase-orders/<poid>/receipts', methods=['GET'])
@limiter.limit("30 per minute")
def get_purchase_order_receipts(poid):
    err = admin_required()
    if err: return err
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT POID FROM purchase_orders WHERE POID=%s", (poid,))
    if not cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy đơn mua hàng', 'code': 404}), 404
    cursor.execute("""
        SELECT g.*, w.WarehouseName
        FROM goods_receipt_notes g
        JOIN warehouse w ON w.WarehouseID=g.WarehouseID
        WHERE g.POID=%s ORDER BY g.ReceivedAt DESC, g.GRNID DESC
    """, (poid,))
    receipts = cursor.fetchall()
    for receipt in receipts:
        cursor.execute("""
            SELECT i.LineNo, i.ProductID, i.QuantityReceived, p.ProductName, p.Unit
            FROM goods_receipt_items i
            JOIN product p ON p.ProductID=i.ProductID
            WHERE i.GRNID=%s ORDER BY i.LineNo
        """, (receipt['GRNID'],))
        receipt['Items'] = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(json_safe(receipts))


@app.route('/api/purchase-orders/<poid>/receipts', methods=['POST'])
@limiter.limit("10 per minute")
def create_goods_receipt(poid):
    """Create a GRN: stock in received quantities, update PO line/header status."""
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, {'WarehouseID', 'Notes', 'Items'})
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    requested_warehouse = str(clean.get('WarehouseID') or '').strip() or None
    notes = str(clean.get('Notes') or '').strip()[:255] or None
    raw_items = clean.get('Items')
    if raw_items is not None and (not isinstance(raw_items, list) or not raw_items):
        return jsonify({'error': 'Items phải là danh sách dòng hàng nhận', 'code': 400}), 400

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM purchase_orders WHERE POID=%s FOR UPDATE", (poid,))
        po = cursor.fetchone()
        if not po:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy đơn mua hàng', 'code': 404}), 404
        if po['Status'] in ('Received', 'Completed'):
            conn.rollback()
            return jsonify({'error': 'Đơn mua đã nhận đủ hàng', 'code': 409}), 409
        if po['Status'] in ('Cancelled', 'Draft'):
            conn.rollback()
            return jsonify({'error': f'Không thể nhận hàng cho đơn ở trạng thái {po["Status"]}', 'code': 409}), 409

        cursor.execute("""
            SELECT LineNo, ProductID, Quantity, ReceivedQuantity
            FROM purchase_order_items WHERE POID=%s ORDER BY LineNo FOR UPDATE
        """, (poid,))
        po_lines = cursor.fetchall()
        if not po_lines:
            conn.rollback()
            return jsonify({'error': 'Đơn mua không có dòng hàng để nhận', 'code': 409}), 409

        remaining_by_product = {
            line['ProductID']: int(line['Quantity']) - int(line['ReceivedQuantity'] or 0)
            for line in po_lines
        }
        remaining_by_product = {k: v for k, v in remaining_by_product.items() if v > 0}
        if not remaining_by_product:
            conn.rollback()
            return jsonify({'error': 'Đơn mua đã nhận đủ hàng', 'code': 409}), 409

        if raw_items is None:
            receive_lines = [{'ProductID': k, 'QuantityReceived': v} for k, v in remaining_by_product.items()]
        else:
            receive_lines = []
            seen = set()
            for idx, entry in enumerate(raw_items, start=1):
                if not isinstance(entry, dict):
                    conn.rollback()
                    return jsonify({'error': f'Dòng nhận {idx} không hợp lệ', 'code': 400}), 400
                product_id = str(entry.get('ProductID') or '').strip()
                if not product_id:
                    conn.rollback()
                    return jsonify({'error': f'Thiếu ProductID ở dòng {idx}', 'code': 400}), 400
                if product_id in seen:
                    conn.rollback()
                    return jsonify({'error': f'Sản phẩm {product_id} bị lặp', 'code': 400}), 400
                seen.add(product_id)
                if product_id not in remaining_by_product:
                    conn.rollback()
                    return jsonify({'error': f'Sản phẩm {product_id} không thuộc đơn hoặc đã nhận đủ', 'code': 400}), 400
                try:
                    qty_received = int(entry.get('QuantityReceived'))
                except (TypeError, ValueError):
                    conn.rollback()
                    return jsonify({'error': f'QuantityReceived không hợp lệ ở dòng {idx}', 'code': 400}), 400
                if qty_received < 1 or qty_received > remaining_by_product[product_id]:
                    conn.rollback()
                    return jsonify({
                        'error': f'Số lượng nhận của {product_id} phải trong khoảng 1-{remaining_by_product[product_id]}',
                        'code': 400,
                    }), 400
                receive_lines.append({'ProductID': product_id, 'QuantityReceived': qty_received})

        warehouse_id = requested_warehouse or po.get('WarehouseID')
        if not warehouse_id:
            cursor.execute("""
                SELECT WarehouseID FROM inventory WHERE ProductID=%s
                ORDER BY (WarehouseID='W001') DESC, QuantityAvailable DESC LIMIT 1
            """, (receive_lines[0]['ProductID'],))
            row = cursor.fetchone()
            warehouse_id = row['WarehouseID'] if row else None
        if not warehouse_id:
            conn.rollback()
            return jsonify({'error': 'Không xác định được kho nhận hàng', 'code': 409}), 409
        cursor.execute("SELECT 1 FROM warehouse WHERE WarehouseID=%s", (warehouse_id,))
        if not cursor.fetchone():
            conn.rollback()
            return jsonify({'error': 'Kho nhận hàng không tồn tại', 'code': 400}), 400

        grnid = next_entity_id(cursor, 'GRN', 'GRN')
        performed_by = current_identity()
        cursor.execute("""
            INSERT INTO goods_receipt_notes (GRNID, POID, WarehouseID, ReceivedBy, ReceivedAt, Notes, Status)
            VALUES (%s, %s, %s, %s, NOW(), %s, 'Posted')
        """, (grnid, poid, warehouse_id, performed_by, notes))
        stock_results = []
        for line_no, line in enumerate(receive_lines, start=1):
            cursor.execute("""
                INSERT INTO goods_receipt_items (GRNID, LineNo, ProductID, QuantityReceived)
                VALUES (%s, %s, %s, %s)
            """, (grnid, line_no, line['ProductID'], line['QuantityReceived']))
            cursor.execute("""
                UPDATE purchase_order_items
                SET ReceivedQuantity = ReceivedQuantity + %s
                WHERE POID=%s AND ProductID=%s
            """, (line['QuantityReceived'], poid, line['ProductID']))
            result = stock_in(
                cursor, line['ProductID'], warehouse_id, line['QuantityReceived'],
                'GoodsReceipt', 'GRN', grnid,
                f'Nhận hàng theo GRN {grnid} cho PO {poid}', performed_by,
            )
            result['ProductID'] = line['ProductID']
            result['QuantityReceived'] = line['QuantityReceived']
            stock_results.append(result)

        cursor.execute("""
            SELECT COALESCE(SUM(Quantity),0) AS TotalQty, COALESCE(SUM(ReceivedQuantity),0) AS ReceivedQty
            FROM purchase_order_items WHERE POID=%s
        """, (poid,))
        totals = cursor.fetchone()
        new_status = 'Received' if int(totals['ReceivedQty']) >= int(totals['TotalQty']) else 'Partially_Received'
        cursor.execute("UPDATE purchase_orders SET Status=%s WHERE POID=%s", (new_status, poid))
        conn.commit()
        return jsonify({
            'message': 'Đã tạo phiếu nhận hàng',
            'GRNID': grnid,
            'POID': poid,
            'Status': new_status,
            'WarehouseID': warehouse_id,
            'Lines': json_safe(stock_results),
        }), 201
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/api/purchase-orders/<poid>/receive', methods=['PATCH'])
@limiter.limit("10 per minute")
def receive_purchase_order(poid):
    """Legacy endpoint: receive every remaining line into one GRN (kept for old UI)."""
    err = admin_required()
    if err: return err
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM purchase_orders WHERE POID=%s FOR UPDATE", (poid,))
        po = cursor.fetchone()
        if not po:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy đơn mua hàng', 'code': 404}), 404
        if po['Status'] == 'Received':
            conn.commit()
            return jsonify({'message': 'Đơn mua hàng đã được nhập kho trước đó', 'POID': poid})
        if po['Status'] in ('Cancelled', 'Draft'):
            conn.rollback()
            return jsonify({'error': f'Không thể nhận đơn mua ở trạng thái {po["Status"]}', 'code': 409}), 409

        cursor.execute("""
            SELECT LineNo, ProductID, Quantity, ReceivedQuantity
            FROM purchase_order_items WHERE POID=%s ORDER BY LineNo FOR UPDATE
        """, (poid,))
        po_lines = cursor.fetchall()
        remaining = [
            (line['ProductID'], int(line['Quantity']) - int(line['ReceivedQuantity'] or 0))
            for line in po_lines
        ]
        remaining = [(pid, qty) for pid, qty in remaining if qty > 0]
        if not remaining:
            cursor.execute("UPDATE purchase_orders SET Status='Received' WHERE POID=%s", (poid,))
            conn.commit()
            return jsonify({'message': 'Đơn mua hàng đã được nhập kho trước đó', 'POID': poid})

        warehouse_id = po.get('WarehouseID')
        if not warehouse_id:
            inventory = lock_inventory_for_product(cursor, remaining[0][0])
            if not inventory:
                conn.rollback()
                return jsonify({'error': 'Sản phẩm chưa có bản ghi tồn kho. Vui lòng chỉ định WarehouseID.', 'code': 409}), 409
            warehouse_id = inventory['WarehouseID']

        grnid = next_entity_id(cursor, 'GRN', 'GRN')
        performed_by = current_identity()
        cursor.execute("""
            INSERT INTO goods_receipt_notes (GRNID, POID, WarehouseID, ReceivedBy, ReceivedAt, Notes, Status)
            VALUES (%s, %s, %s, %s, NOW(), %s, 'Posted')
        """, (grnid, poid, warehouse_id, performed_by, 'Legacy receive endpoint'))
        first_result = None
        for line_no, (product_id, qty) in enumerate(remaining, start=1):
            cursor.execute("""
                INSERT INTO goods_receipt_items (GRNID, LineNo, ProductID, QuantityReceived)
                VALUES (%s, %s, %s, %s)
            """, (grnid, line_no, product_id, qty))
            cursor.execute("""
                UPDATE purchase_order_items
                SET ReceivedQuantity = Quantity
                WHERE POID=%s AND ProductID=%s
            """, (poid, product_id))
            result = stock_in(
                cursor, product_id, warehouse_id, qty, 'GoodsReceipt', 'GRN', grnid,
                f'Nhận hàng theo GRN {grnid} cho PO {poid}', performed_by,
            )
            if first_result is None:
                first_result = result
        cursor.execute("UPDATE purchase_orders SET Status='Received' WHERE POID=%s", (poid,))
        conn.commit()
        return jsonify({
            'message': 'Nhập kho thành công',
            'POID': poid,
            'GRNID': grnid,
            'InventoryID': first_result['InventoryID'],
            'OldQuantity': first_result['OldQuantity'],
            'NewQuantity': first_result['NewQuantity'],
            'AdjustmentID': first_result['AdjustmentID'],
        })
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/api/purchase-orders/<poid>/status', methods=['PATCH'])
@limiter.limit("20 per minute")
def update_purchase_order_status(poid):
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    extra_fields = set(d.keys()) - {'Status'}
    if extra_fields:
        return jsonify({'error': f'Phát hiện trường không được phép (Mass Assignment): {", ".join(sorted(extra_fields))}', 'code': 400}), 400
    new_status = d.get('Status')
    if new_status not in ('Sent', 'Completed', 'Cancelled'):
        return jsonify({'error': 'Trạng thái không hợp lệ (Sent/Completed/Cancelled)', 'code': 400}), 400

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM purchase_orders WHERE POID=%s FOR UPDATE", (poid,))
        po = cursor.fetchone()
        if not po:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy đơn mua hàng', 'code': 404}), 404
        if po['Status'] == new_status:
            conn.commit()
            return jsonify({'message': f'Đơn mua đã ở trạng thái {new_status}'})

        if new_status == 'Sent':
            if po['Status'] != 'Ordered':
                conn.rollback()
                return jsonify({'error': 'Chỉ có thể gửi đơn đang ở trạng thái Ordered', 'code': 409}), 409
            cursor.execute("UPDATE purchase_orders SET Status='Sent', SentAt=NOW() WHERE POID=%s", (poid,))
        elif new_status == 'Completed':
            if po['Status'] != 'Received':
                conn.rollback()
                return jsonify({'error': 'Chỉ có thể hoàn tất đơn đã nhận đủ hàng', 'code': 409}), 409
            cursor.execute("UPDATE purchase_orders SET Status='Completed', CompletedAt=NOW() WHERE POID=%s", (poid,))
        else:
            cursor.execute("""
                SELECT COALESCE(SUM(ReceivedQuantity),0) AS ReceivedQty
                FROM purchase_order_items WHERE POID=%s
            """, (poid,))
            if int(cursor.fetchone()['ReceivedQty'] or 0) > 0:
                conn.rollback()
                return jsonify({'error': 'Không thể hủy đơn đã phát sinh nhập kho', 'code': 409}), 409
            if po['Status'] not in ('Draft', 'Ordered', 'Sent'):
                conn.rollback()
                return jsonify({'error': f'Không thể hủy đơn ở trạng thái {po["Status"]}', 'code': 409}), 409
            cursor.execute("UPDATE purchase_orders SET Status='Cancelled' WHERE POID=%s", (poid,))
        conn.commit()
        return jsonify({'message': 'Đã cập nhật đơn mua hàng', 'POID': poid, 'Status': new_status})
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ══════════════════════════════════════════════════════
#  RETURN ORDERS
# ══════════════════════════════════════════════════════

@app.route('/api/returns', methods=['GET'])
@limiter.limit("30 per minute")
def get_returns():
    claims = get_jwt()
    role = claims.get('role')
    cid = claims.get('customer_id')
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    base_sql = """
        SELECT r.*, o.CustomerID, c.CustomerName, p.ProductName, p.Unit
        FROM return_orders r
        JOIN orders o ON o.OrderID = r.OriginalOrderID
        LEFT JOIN customer c ON c.CustomerID = o.CustomerID
        LEFT JOIN product p ON p.ProductID = r.ProductID
    """
    if role == 'admin':
        cursor.execute(base_sql + " ORDER BY r.CreatedAt DESC, r.ReturnID DESC")
    elif role in ORG_ROLES:
        org_id = claims.get('organization_id')
        cursor.execute(
            base_sql + " WHERE r.OrganizationID=%s OR o.OrganizationID=%s ORDER BY r.CreatedAt DESC, r.ReturnID DESC",
            (org_id, org_id),
        )
    else:
        cursor.execute(base_sql + " WHERE o.CustomerID=%s ORDER BY r.CreatedAt DESC, r.ReturnID DESC", (cid,))
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(json_safe(data))

@app.route('/api/returns', methods=['POST'])
@limiter.limit("10 per minute")
def add_return_order():
    claims = get_jwt()
    role = claims.get('role')
    cid = claims.get('customer_id')
    org_id = claims.get('organization_id')
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, RETURN_ALLOWED_CREATE)
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    order_id = str(clean.get('OriginalOrderID') or '').strip()
    reason = str(clean.get('Reason') or '').strip()
    if not order_id or not reason:
        return jsonify({'error': 'Thiếu OriginalOrderID hoặc Reason', 'code': 400}), 400
    if len(reason) > 255:
        return jsonify({'error': 'Lý do trả hàng tối đa 255 ký tự', 'code': 400}), 400
    try:
        quantity = int(clean.get('Quantity'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Số lượng trả hàng không hợp lệ', 'code': 400}), 400
    if quantity < 1:
        return jsonify({'error': 'Số lượng trả hàng phải lớn hơn 0', 'code': 400}), 400
    if role not in ('admin', 'customer') + ORG_ROLES:
        return jsonify({'error': 'Forbidden: Không có quyền tạo yêu cầu trả hàng', 'code': 403}), 403

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT OrderID, CustomerID, OrganizationID, ProductID, Quantity, Status
            FROM orders WHERE OrderID=%s FOR UPDATE
        """, (order_id,))
        order = cursor.fetchone()
        if not order:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy đơn hàng gốc', 'code': 404}), 404
        if role == 'customer' and (not cid or order['CustomerID'] != cid):
            conn.rollback()
            return jsonify({'error': 'Forbidden: Không có quyền trả đơn hàng này', 'code': 403}), 403
        if role in ORG_ROLES and (not org_id or order['OrganizationID'] != org_id):
            conn.rollback()
            return jsonify({'error': 'Forbidden: Không có quyền trả đơn hàng này', 'code': 403}), 403
        if order['Status'] not in ('Accepted', 'Processing', 'Completed'):
            conn.rollback()
            return jsonify({'error': 'Chỉ có thể yêu cầu trả hàng cho đơn đã duyệt hoặc đã giao', 'code': 409}), 409
        if quantity > int(order['Quantity']):
            conn.rollback()
            return jsonify({'error': f'Số lượng trả vượt quá số lượng đơn ({order["Quantity"]})', 'code': 400}), 400

        cursor.execute("""
            SELECT Quantity FROM return_orders
            WHERE OriginalOrderID=%s AND Status IN ('Pending','Approved','Received') FOR UPDATE
        """, (order_id,))
        used = sum(int(r['Quantity']) for r in cursor.fetchall())
        if used + quantity > int(order['Quantity']):
            conn.rollback()
            return jsonify({'error': f'Đã có {used} sản phẩm được yêu cầu trả cho đơn này', 'code': 409}), 409

        return_id = next_entity_id(cursor, 'RTN', 'RTN')
        cursor.execute("""
            INSERT INTO return_orders
                (ReturnID, OriginalOrderID, ProductID, Quantity, Reason, Status, RefundAmount, OrganizationID)
            VALUES (%s, %s, %s, %s, %s, 'Pending', 0, %s)
        """, (return_id, order_id, order['ProductID'], quantity, reason, order.get('OrganizationID')))
        conn.commit()
        return jsonify({'message': 'Đã tạo yêu cầu trả hàng', 'ReturnID': return_id}), 201
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/returns/<rid>/status', methods=['PATCH'])
@limiter.limit("20 per minute")
def update_return_status(rid):
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    extra_fields = set(d.keys()) - {'Status'}
    if extra_fields:
        return jsonify({'error': f'Phát hiện trường không được phép (Mass Assignment): {", ".join(sorted(extra_fields))}', 'code': 400}), 400
    new_status = d.get('Status')
    if new_status not in ('Approved', 'Rejected'):
        return jsonify({'error': 'Trạng thái không hợp lệ (Approved/Rejected)', 'code': 400}), 400

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM return_orders WHERE ReturnID=%s FOR UPDATE", (rid,))
        ret = cursor.fetchone()
        if not ret:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy yêu cầu trả hàng', 'code': 404}), 404
        if ret['Status'] != 'Pending':
            if ret['Status'] == new_status:
                conn.commit()
                return jsonify({'message': f'Yêu cầu trả hàng đã ở trạng thái {new_status}'})
            conn.rollback()
            return jsonify({'error': f'Yêu cầu trả hàng đã được xử lý ({ret["Status"]})', 'code': 409}), 409

        refund_amount = 0.0
        refund_status = 'Rejected' if new_status == 'Rejected' else 'Pending'
        if new_status == 'Approved':
            cursor.execute("""
                SELECT OrderID, ProductID, Quantity, Bill, Status
                FROM orders WHERE OrderID=%s FOR UPDATE
            """, (ret['OriginalOrderID'],))
            order = cursor.fetchone()
            if not order:
                conn.rollback()
                return jsonify({'error': 'Không tìm thấy đơn hàng gốc', 'code': 404}), 404
            cursor.execute("""
                SELECT Quantity FROM return_orders
                WHERE OriginalOrderID=%s AND Status='Approved' FOR UPDATE
            """, (ret['OriginalOrderID'],))
            approved_so_far = sum(int(r['Quantity']) for r in cursor.fetchall())
            if approved_so_far + int(ret['Quantity']) > int(order['Quantity']):
                conn.rollback()
                return jsonify({'error': 'Tổng số lượng trả vượt quá số lượng đơn hàng', 'code': 409}), 409
            if int(order['Quantity']) > 0:
                refund_amount = round(
                    (float(order['Bill']) / int(order['Quantity'])) * int(ret['Quantity']), 2
                )

        cursor.execute("""
            UPDATE return_orders
            SET Status=%s, RefundAmount=%s, RefundStatus=%s, ReviewedBy=%s, ReviewedAt=NOW()
            WHERE ReturnID=%s
        """, (new_status, refund_amount, refund_status, current_identity(), rid))
        conn.commit()
        return jsonify({
            'message': 'Đã duyệt yêu cầu trả hàng' if new_status == 'Approved' else 'Đã từ chối yêu cầu trả hàng',
            'ReturnID': rid,
            'RefundAmount': refund_amount,
            'Note': 'Hàng chỉ được nhập kho khi xác nhận đã nhận hàng trả.',
        })
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/returns/<rid>/receive', methods=['POST'])
@limiter.limit("20 per minute")
def receive_return_order(rid):
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, {'WarehouseID'})
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    warehouse_id = str(clean.get('WarehouseID') or '').strip()

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM return_orders WHERE ReturnID=%s FOR UPDATE", (rid,))
        ret = cursor.fetchone()
        if not ret:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy yêu cầu trả hàng', 'code': 404}), 404
        if ret['Status'] == 'Received':
            conn.commit()
            return jsonify({'message': 'Hàng trả đã được nhập kho trước đó', 'ReturnID': rid})
        if ret['Status'] != 'Approved':
            conn.rollback()
            return jsonify({'error': 'Chỉ nhận hàng trả đã được duyệt', 'code': 409}), 409
        if not warehouse_id:
            cursor.execute("""
                SELECT WarehouseID FROM inventory_transactions
                WHERE TransactionType='SalesIssue' AND ReferenceType='Order'
                  AND ReferenceID=%s AND ProductID=%s
                ORDER BY CreatedAt DESC, TransactionID DESC LIMIT 1
            """, (ret['OriginalOrderID'], ret['ProductID']))
            origin = cursor.fetchone()
            warehouse_id = origin['WarehouseID'] if origin else 'W001'
        cursor.execute("SELECT 1 FROM warehouse WHERE WarehouseID=%s", (warehouse_id,))
        if not cursor.fetchone():
            conn.rollback()
            return jsonify({'error': 'Kho không tồn tại', 'code': 400}), 400

        result = stock_in(
            cursor, ret['ProductID'], warehouse_id, ret['Quantity'],
            'CustomerReturn', 'Return', rid, f'Hoàn hàng từ đơn {ret["OriginalOrderID"]}',
            current_identity(),
        )
        cursor.execute("""
            UPDATE return_orders
            SET Status='Received', RefundStatus='Completed', ReceivedAt=NOW()
            WHERE ReturnID=%s
        """, (rid,))
        conn.commit()
        return jsonify({
            'message': 'Đã nhập kho hàng trả',
            'ReturnID': rid,
            'Status': 'Received',
            'WarehouseID': warehouse_id,
            **result,
        })
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ══════════════════════════════════════════════════════
#  STOCKTAKE (CYCLE COUNT)
# ══════════════════════════════════════════════════════

@app.route('/api/stocktake-sessions', methods=['GET'])
@limiter.limit("30 per minute")
def get_stocktake_sessions():
    err = admin_required()
    if err: return err
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT s.*, w.WarehouseName,
               (SELECT COUNT(*) FROM stocktake_items i WHERE i.SessionID = s.SessionID) AS ItemCount
        FROM stocktake_sessions s
        JOIN warehouse w ON w.WarehouseID = s.WarehouseID
        ORDER BY s.CreatedAt DESC, s.SessionID DESC
    """)
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(json_safe(data))

@app.route('/api/stocktake-sessions', methods=['POST'])
@limiter.limit("10 per minute")
def create_stocktake_session():
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, {'WarehouseID'})
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    warehouse_id = str(clean.get('WarehouseID') or '').strip()
    if not warehouse_id:
        return jsonify({'error': 'Thiếu WarehouseID', 'code': 400}), 400
    created_by = str(get_jwt().get('sub') or 'admin').strip()[:50]

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT 1 FROM warehouse WHERE WarehouseID=%s", (warehouse_id,))
        if not cursor.fetchone():
            conn.rollback()
            return jsonify({'error': 'Kho không tồn tại', 'code': 400}), 400
        cursor.execute("""
            SELECT InventoryID, ProductID, QuantityAvailable
            FROM inventory WHERE WarehouseID=%s FOR UPDATE
        """, (warehouse_id,))
        rows = cursor.fetchall()
        if not rows:
            conn.rollback()
            return jsonify({'error': 'Kho chưa có bản ghi tồn kho để kiểm kê', 'code': 400}), 400
        session_id = next_entity_id(cursor, 'ST', 'ST')
        cursor.execute("""
            INSERT INTO stocktake_sessions (SessionID, WarehouseID, CreatedBy, Status)
            VALUES (%s, %s, %s, 'Draft')
        """, (session_id, warehouse_id, created_by))
        for row in rows:
            cursor.execute("""
                INSERT INTO stocktake_items
                    (SessionID, ProductID, SystemQuantity, ActualQuantity, Difference)
                VALUES (%s, %s, %s, NULL, NULL)
            """, (session_id, row['ProductID'], int(row['QuantityAvailable'] or 0)))
        conn.commit()
        return jsonify({
            'message': 'Đã tạo phiên kiểm kê',
            'SessionID': session_id,
            'ItemCount': len(rows),
        }), 201
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/stocktake-sessions/<sid>', methods=['GET'])
@limiter.limit("30 per minute")
def get_stocktake_session(sid):
    err = admin_required()
    if err: return err
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT s.*, w.WarehouseName
        FROM stocktake_sessions s
        JOIN warehouse w ON w.WarehouseID = s.WarehouseID
        WHERE s.SessionID=%s
    """, (sid,))
    session = cursor.fetchone()
    if not session:
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy phiên kiểm kê', 'code': 404}), 404
    cursor.execute("""
        SELECT i.*, p.ProductName, p.Unit
        FROM stocktake_items i
        JOIN product p ON p.ProductID = i.ProductID
        WHERE i.SessionID=%s
        ORDER BY p.ProductName
    """, (sid,))
    items = cursor.fetchall()
    session['items'] = items
    cursor.close(); conn.close()
    return jsonify(json_safe(session))

@app.route('/api/stocktake-sessions/<sid>/items', methods=['PATCH'])
@limiter.limit("30 per minute")
def update_stocktake_items(sid):
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    entries = d.get('Items') if isinstance(d.get('Items'), list) else [d]
    if not entries:
        return jsonify({'error': 'Thiếu dữ liệu kiểm kê', 'code': 400}), 400

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT Status FROM stocktake_sessions WHERE SessionID=%s FOR UPDATE", (sid,))
        session = cursor.fetchone()
        if not session:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy phiên kiểm kê', 'code': 404}), 404
        if session['Status'] == 'Completed':
            conn.rollback()
            return jsonify({'error': 'Phiên kiểm kê đã hoàn tất, không thể sửa', 'code': 409}), 409

        updated = 0
        for entry in entries:
            if not isinstance(entry, dict):
                conn.rollback()
                return jsonify({'error': 'Dữ liệu kiểm kê không hợp lệ', 'code': 400}), 400
            product_id = str(entry.get('ProductID') or '').strip()
            if not product_id:
                conn.rollback()
                return jsonify({'error': 'Thiếu ProductID', 'code': 400}), 400
            try:
                actual_quantity = int(entry.get('ActualQuantity'))
            except (TypeError, ValueError):
                conn.rollback()
                return jsonify({'error': f'ActualQuantity không hợp lệ cho {product_id}', 'code': 400}), 400
            if actual_quantity < 0:
                conn.rollback()
                return jsonify({'error': 'Số lượng thực tế không được âm', 'code': 400}), 400
            cursor.execute("""
                UPDATE stocktake_items
                SET ActualQuantity=%s, Difference=%s - SystemQuantity
                WHERE SessionID=%s AND ProductID=%s
            """, (actual_quantity, actual_quantity, sid, product_id))
            if cursor.rowcount == 0:
                conn.rollback()
                return jsonify({'error': f'Sản phẩm {product_id} không thuộc phiên kiểm kê', 'code': 400}), 400
            updated += 1

        if session['Status'] == 'Draft':
            cursor.execute("UPDATE stocktake_sessions SET Status='In_Progress' WHERE SessionID=%s", (sid,))
        conn.commit()
        return jsonify({'message': 'Đã cập nhật số lượng thực tế', 'Updated': updated})
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/stocktake-sessions/<sid>/complete', methods=['PATCH'])
@limiter.limit("10 per minute")
def complete_stocktake_session(sid):
    err = admin_required()
    if err: return err
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM stocktake_sessions WHERE SessionID=%s FOR UPDATE", (sid,))
        session = cursor.fetchone()
        if not session:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy phiên kiểm kê', 'code': 404}), 404
        if session['Status'] == 'Completed':
            conn.commit()
            return jsonify({'message': 'Phiên kiểm kê đã hoàn tất trước đó', 'SessionID': sid, 'AdjustedCount': 0})

        cursor.execute("""
            SELECT * FROM stocktake_items WHERE SessionID=%s FOR UPDATE
        """, (sid,))
        items = cursor.fetchall()
        if not items:
            conn.rollback()
            return jsonify({'error': 'Phiên kiểm kê không có sản phẩm', 'code': 400}), 400

        adjusted = 0
        skipped = 0
        for item in items:
            actual = item['ActualQuantity']
            if actual is None:
                actual = int(item['SystemQuantity'])
            actual = int(actual)
            if actual == int(item['SystemQuantity']):
                continue
            cursor.execute("""
                SELECT InventoryID, QuantityAvailable
                FROM inventory WHERE ProductID=%s AND WarehouseID=%s FOR UPDATE
            """, (item['ProductID'], session['WarehouseID']))
            inventory = cursor.fetchone()
            if not inventory:
                skipped += 1
                continue
            old_quantity = int(inventory['QuantityAvailable'] or 0)
            cursor.execute("""
                UPDATE inventory SET QuantityAvailable=%s WHERE InventoryID=%s
            """, (actual, inventory['InventoryID']))
            write_inventory_adjustment(
                cursor, inventory['InventoryID'], old_quantity, actual, 'Kiểm kê'
            )
            write_inventory_transaction(
                cursor, inventory['InventoryID'], item['ProductID'], session['WarehouseID'],
                'StocktakeAdjustment', actual - old_quantity, old_quantity, actual,
                'Stocktake', sid, 'Điều chỉnh theo kiểm kê', current_identity(),
            )
            adjusted += 1

        cursor.execute("""
            UPDATE stocktake_sessions
            SET Status='Completed', CompletedBy=%s, CompletedAt=NOW()
            WHERE SessionID=%s
        """, (current_identity(), sid))
        conn.commit()
        return jsonify({
            'message': 'Hoàn tất kiểm kê',
            'SessionID': sid,
            'AdjustedCount': adjusted,
            'SkippedCount': skipped,
        })
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ══════════════════════════════════════════════════════
#  DASHBOARD
# ══════════════════════════════════════════════════════

@app.route('/api/dashboard/summary', methods=['GET'])
@limiter.limit("30 per minute")
def get_dashboard_summary():
    err = admin_required()
    if err: return err
    try:
        low_stock_threshold = max(int(request.args.get('low_stock', 50)), 0)
    except (TypeError, ValueError):
        return jsonify({'error': 'low_stock không hợp lệ', 'code': 400}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    def scalar(sql, params=()):
        cursor.execute(sql, params)
        row = cursor.fetchone() or {}
        return list(row.values())[0] if row else 0

    cursor.execute("""
        SELECT
            (SELECT COUNT(*) FROM product) AS ProductCount,
            (SELECT COUNT(*) FROM supplier) AS SupplierCount,
            (SELECT COUNT(*) FROM warehouse) AS WarehouseCount,
            (SELECT COUNT(*) FROM customer) AS CustomerCount,
            (SELECT COUNT(*) FROM organizations WHERE Status='Active') AS OrganizationCount,
            (SELECT COUNT(*) FROM user WHERE Role IN ('org_manager','org_staff') AND Status='Active') AS OrgUserCount,
            (SELECT COALESCE(SUM(QuantityAvailable),0) FROM inventory) AS InventoryUnits,
            (SELECT COUNT(*) FROM inventory WHERE QuantityAvailable < %s) AS LowStockCount
    """, (low_stock_threshold,))
    totals = cursor.fetchone() or {}

    cursor.execute("""
        SELECT COALESCE(SUM(i.QuantityAvailable * p.UnitPrice), 0) AS InventoryValue
        FROM inventory i JOIN product p ON p.ProductID = i.ProductID
    """)
    totals['InventoryValue'] = float((cursor.fetchone() or {}).get('InventoryValue') or 0)

    cursor.execute("""
        SELECT Status, COUNT(*) AS Count FROM orders GROUP BY Status
    """)
    order_status = {r['Status']: int(r['Count']) for r in cursor.fetchall()}
    cursor.execute("""
        SELECT COALESCE(SUM(Bill),0) AS Revenue, COUNT(*) AS TotalOrders
        FROM orders WHERE Status NOT IN ('Cancelled','Rejected')
    """)
    revenue_row = cursor.fetchone() or {}
    cursor.execute("""
        SELECT COALESCE(SUM(Bill),0) AS TodayRevenue, COUNT(*) AS TodayOrders
        FROM orders WHERE OrderDate = CURDATE() AND Status NOT IN ('Cancelled','Rejected')
    """)
    today_row = cursor.fetchone() or {}

    cursor.execute("SELECT Status, COUNT(*) AS Count FROM purchase_orders GROUP BY Status")
    po_status = {r['Status']: int(r['Count']) for r in cursor.fetchall()}
    cursor.execute("SELECT Status, COUNT(*) AS Count FROM purchase_requisitions GROUP BY Status")
    pr_status = {r['Status']: int(r['Count']) for r in cursor.fetchall()}
    cursor.execute("SELECT Status, COUNT(*) AS Count FROM customer_purchase_requests GROUP BY Status")
    cpr_status = {r['Status']: int(r['Count']) for r in cursor.fetchall()}
    cursor.execute("SELECT Status, COUNT(*) AS Count FROM return_orders GROUP BY Status")
    return_status = {r['Status']: int(r['Count']) for r in cursor.fetchall()}

    cursor.execute("""
        SELECT DATE_FORMAT(OrderDate, '%Y-%m') AS Month, COALESCE(SUM(Bill),0) AS Revenue
        FROM orders
        WHERE OrderDate >= DATE_SUB(CURDATE(), INTERVAL 5 MONTH)
          AND Status NOT IN ('Cancelled','Rejected')
        GROUP BY DATE_FORMAT(OrderDate, '%Y-%m')
        ORDER BY Month
    """)
    monthly_revenue = cursor.fetchall()

    cursor.execute("""
        SELECT i.InventoryID, i.ProductID, p.ProductName, p.Unit, i.WarehouseID,
               w.WarehouseName, i.QuantityAvailable
        FROM inventory i
        JOIN product p ON p.ProductID = i.ProductID
        JOIN warehouse w ON w.WarehouseID = i.WarehouseID
        WHERE i.QuantityAvailable < %s
        ORDER BY i.QuantityAvailable ASC
        LIMIT 10
    """, (low_stock_threshold,))
    low_stock_items = cursor.fetchall()

    cursor.execute("""
        SELECT t.TransactionID, t.TransactionType, t.ProductID, p.ProductName,
               t.WarehouseID, t.QuantityChange, t.QuantityAfter, t.ReferenceID,
               t.PerformedBy, t.CreatedAt
        FROM inventory_transactions t
        LEFT JOIN product p ON p.ProductID = t.ProductID
        ORDER BY t.CreatedAt DESC, t.TransactionID DESC
        LIMIT 10
    """)
    recent_transactions = cursor.fetchall()

    # Aggregate value by CATEGORY (never product names) for the ERP dashboard charts
    cursor.execute("""
        SELECT p.Category,
               COALESCE(SUM(i.QuantityAvailable),0) AS Units,
               COALESCE(SUM(i.QuantityAvailable * p.UnitPrice),0) AS Value
        FROM inventory i
        JOIN product p ON p.ProductID = i.ProductID
        GROUP BY p.Category
        ORDER BY Value DESC
    """)
    inventory_by_category = cursor.fetchall()

    cursor.execute("""
        SELECT DATE_FORMAT(t.CreatedAt, '%Y-%m') AS Month,
               COALESCE(SUM(CASE WHEN t.QuantityChange > 0 THEN t.QuantityChange ELSE 0 END),0) AS Inbound,
               COALESCE(SUM(CASE WHEN t.QuantityChange < 0 THEN -t.QuantityChange ELSE 0 END),0) AS Outbound
        FROM inventory_transactions t
        WHERE t.CreatedAt >= DATE_SUB(CURDATE(), INTERVAL 5 MONTH)
        GROUP BY DATE_FORMAT(t.CreatedAt, '%Y-%m')
        ORDER BY Month
    """)
    goods_flow = cursor.fetchall()

    cursor.execute("""
        SELECT s.SupplierID, s.SupplierName,
               COALESCE(SUM(po.TotalAmount),0) AS PurchaseValue,
               COUNT(*) AS OrderCount
        FROM purchase_orders po
        JOIN supplier s ON s.SupplierID = po.SupplierID
        WHERE po.Status <> 'Cancelled'
        GROUP BY s.SupplierID, s.SupplierName
        ORDER BY PurchaseValue DESC
        LIMIT 5
    """)
    top_suppliers = cursor.fetchall()
    cursor.close(); conn.close()

    return jsonify(json_safe({
        'totals': {
            **totals,
            'Revenue': float(revenue_row.get('Revenue') or 0),
            'TotalOrders': int(revenue_row.get('TotalOrders') or 0),
            'TodayRevenue': float(today_row.get('TodayRevenue') or 0),
            'TodayOrders': int(today_row.get('TodayOrders') or 0),
            'PendingPR': pr_status.get('Pending_Approval', 0),
            'PendingCPR': cpr_status.get('Submitted', 0),
            'PendingReturns': return_status.get('Pending', 0),
            'OpenPOs': sum(po_status.get(s, 0) for s in ('Ordered', 'Sent', 'Partially_Received')),
        },
        'ordersByStatus': order_status,
        'purchaseOrdersByStatus': po_status,
        'purchaseRequisitionsByStatus': pr_status,
        'customerRequestsByStatus': cpr_status,
        'returnsByStatus': return_status,
        'monthlyRevenue': monthly_revenue,
        'inventoryByCategory': inventory_by_category,
        'goodsFlow': goods_flow,
        'topSuppliers': top_suppliers,
        'lowStockItems': low_stock_items,
        'recentTransactions': recent_transactions,
        'lowStockThreshold': low_stock_threshold,
    }))


@app.route('/api/dashboard/org', methods=['GET'])
@limiter.limit("30 per minute")
def get_org_dashboard():
    claims = get_jwt()
    role = claims.get('role')
    org_id = claims.get('organization_id')
    if role not in ORG_ROLES or not org_id:
        return jsonify({'error': 'Forbidden: Chỉ tài khoản tổ chức mới truy cập', 'code': 403}), 403

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT o.OrganizationID, o.OrganizationName, o.OrganizationType, o.TaxCode,
               o.Address, o.Representative, o.RepresentativePhone, o.RepresentativeEmail,
               o.Status, o.CreatedAt, c.CustomerID
        FROM organizations o
        LEFT JOIN customer c ON c.OrganizationID = o.OrganizationID
        WHERE o.OrganizationID=%s
    """, (org_id,))
    organization = cursor.fetchone()
    if not organization:
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy tổ chức', 'code': 404}), 404

    cursor.execute("SELECT Status, COUNT(*) AS Count FROM customer_purchase_requests WHERE OrganizationID=%s GROUP BY Status", (org_id,))
    cpr_status = {r['Status']: int(r['Count']) for r in cursor.fetchall()}
    cursor.execute("""
        SELECT Status, COUNT(*) AS Count, COALESCE(SUM(Bill),0) AS Amount
        FROM orders WHERE OrganizationID=%s GROUP BY Status
    """, (org_id,))
    order_rows = cursor.fetchall()
    order_status = {r['Status']: int(r['Count']) for r in order_rows}
    cursor.execute("""
        SELECT COALESCE(SUM(Bill),0) AS Spend, COUNT(*) AS TotalOrders
        FROM orders WHERE OrganizationID=%s AND Status NOT IN ('Cancelled','Rejected')
    """, (org_id,))
    spend_row = cursor.fetchone() or {}
    cursor.execute("SELECT Status, COUNT(*) AS Count FROM return_orders WHERE OrganizationID=%s GROUP BY Status", (org_id,))
    return_status = {r['Status']: int(r['Count']) for r in cursor.fetchall()}
    cursor.execute("SELECT COUNT(*) AS Count FROM user WHERE OrganizationID=%s AND Status='Active'", (org_id,))
    member_count = int((cursor.fetchone() or {}).get('Count') or 0)

    cursor.execute("""
        SELECT CPRID, CreatedAt AS RequestDate, Status, TotalEstimated, Note
        FROM customer_purchase_requests WHERE OrganizationID=%s
        ORDER BY CreatedAt DESC, CPRID DESC LIMIT 5
    """, (org_id,))
    recent_requests = cursor.fetchall()
    cursor.execute("""
        SELECT OrderID, OrderDate, ProductID, Quantity, Bill, Status
        FROM orders WHERE OrganizationID=%s
        ORDER BY OrderDate DESC, OrderID DESC LIMIT 5
    """, (org_id,))
    recent_orders = cursor.fetchall()
    cursor.execute("""
        SELECT ReturnID, OriginalOrderID, ProductID, Quantity, Status, RefundAmount, CreatedAt
        FROM return_orders WHERE OrganizationID=%s
        ORDER BY CreatedAt DESC, ReturnID DESC LIMIT 5
    """, (org_id,))
    recent_returns = cursor.fetchall()
    cursor.close(); conn.close()

    return jsonify(json_safe({
        'organization': organization,
        'totals': {
            'MemberCount': member_count,
            'PendingRequests': cpr_status.get('Submitted', 0),
            'ApprovedRequests': cpr_status.get('Approved', 0),
            'TotalOrders': int(spend_row.get('TotalOrders') or 0),
            'TotalSpend': float(spend_row.get('Spend') or 0),
            'ActiveOrders': sum(order_status.get(s, 0) for s in ('Pending', 'Accepted', 'Processing')),
            'PendingReturns': return_status.get('Pending', 0),
        },
        'requestsByStatus': cpr_status,
        'ordersByStatus': order_status,
        'returnsByStatus': return_status,
        'recentRequests': recent_requests,
        'recentOrders': recent_orders,
        'recentReturns': recent_returns,
    }))


# ══════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    
    

