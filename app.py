import os
import re
from datetime import date
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
        token = create_access_token(
            identity=u['Username'],
            additional_claims={'role': u['Role'], 'customer_id': u.get('CustomerID')}
        )
        return jsonify({'access_token': token, 'role': u['Role'], 'customer_id': u.get('CustomerID')})
    finally:
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
            "SELECT QuantityAvailable FROM inventory WHERE InventoryID=%s FOR UPDATE",
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
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    if role == "admin":
        cursor.execute("SELECT * FROM orders ORDER BY OrderDate DESC, OrderID DESC")
    else:
        # Customers only see their own orders (VULN-02 fix)
        cursor.execute(
            "SELECT * FROM orders WHERE CustomerID=%s ORDER BY OrderDate DESC, OrderID DESC",
            (cid,)
        )
    data = cursor.fetchall()
    for row in data:
        if row.get('OrderDate'):
            row['OrderDate'] = str(row['OrderDate'])
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/orders', methods=['POST'])
@limiter.limit("10 per minute")
def add_order():
    claims = get_jwt()
    role = claims.get("role")
    cid = claims.get("customer_id")
    raw_d = request.get_json(silent=True) or {}

    clean, err_msg = extract_whitelisted_fields(raw_d, ORDER_ALLOWED_CREATE)
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400

    for req_field in ('OrderDate', 'ProductID'):
        if not clean.get(req_field):
            return jsonify({'error': f'Thiếu trường bắt buộc: {req_field}', 'code': 400}), 400

    # Parameter Pollution & Privilege Escalation Mitigation:
    # Server-side authorization check (CWE-602): enforce customer identity from JWT claims
    if role != "admin":
        if not cid:
            return jsonify({'error': 'Forbidden: Yêu cầu đăng nhập tài khoản khách hàng', 'code': 403}), 403
        customer_id = cid
        # Khách hàng không được tự đặt Status/Invoice/VAT — server ép giá trị an toàn
        order_status = 'Pending'
        invoice_number = None
        vat_rate = 10
    else:
        customer_id = clean.get('CustomerID')
        if not customer_id:
            return jsonify({'error': 'Thiếu mã khách hàng', 'code': 400}), 400
        order_status = clean.get('Status') or 'Pending'
        if order_status not in ('Pending', 'Accepted', 'Rejected', 'Cancelled'):
            order_status = 'Pending'
        invoice_number = clean.get('InvoiceNumber')
        try:
            vat_rate = float(clean.get('VatRate') if clean.get('VatRate') is not None else 10)
        except (TypeError, ValueError):
            return jsonify({'error': 'VatRate không hợp lệ', 'code': 400}), 400
        if vat_rate < 0 or vat_rate > 100:
            return jsonify({'error': 'VatRate phải trong khoảng 0-100', 'code': 400}), 400

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
        cursor.execute("SELECT UnitPrice FROM product WHERE ProductID=%s", (clean['ProductID'],))
        prod = cursor.fetchone()
        if not prod:
            return jsonify({'error': 'Sản phẩm không tồn tại', 'code': 400}), 400

        # Calculate or validate bill securely
        if role != "admin":
            # Customer cannot tamper with Bill — calculated server-side from catalog price
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

        cursor.execute("""
            INSERT INTO orders (OrderID, OrderDate, Bill, CustomerID, ProductID, Quantity, Status, InvoiceNumber, VatRate, VatAmount, PaymentMethod)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (order_id, clean['OrderDate'], bill, customer_id, clean['ProductID'], qty, order_status, invoice_number, vat_rate, vat_amount, clean.get('PaymentMethod') or 'Tiền mặt'))

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
    cursor = conn.cursor()
    cursor.execute("DELETE FROM orders WHERE OrderID=%s", (oid,))
    if cursor.rowcount == 0:
        conn.rollback(); cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy đơn hàng', 'code': 404}), 404
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Order deleted'})

@app.route('/api/orders/<oid>/status', methods=['PATCH'])
@limiter.limit("10 per minute")
def update_order_status(oid):
    claims = get_jwt()
    role = claims.get("role")
    cid = claims.get("customer_id")
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
    if new_status not in ('Accepted', 'Pending', 'Rejected', 'Cancelled'):
        return jsonify({'error': 'Trạng thái không hợp lệ (Pending/Accepted/Rejected/Cancelled)', 'code': 400}), 400

    # Phân quyền: khách hàng chỉ được hủy đơn của chính mình
    if role != "admin" and new_status != "Cancelled":
        return jsonify({'error': 'Forbidden: Khách hàng chỉ có thể hủy đơn hàng', 'code': 403}), 403

    conn = get_connection()
    cursor = None
    try:
        # TOCTOU & Race Condition Prevention: Start explicit transaction
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)

        # Row-level locking on the target order
        cursor.execute("SELECT ProductID, CustomerID, Status, Quantity FROM orders WHERE OrderID=%s FOR UPDATE", (oid,))
        order = cursor.fetchone()
        if not order:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy đơn hàng', 'code': 404}), 404

        if role != "admin" and (not cid or order.get('CustomerID') != cid):
            conn.rollback()
            return jsonify({'error': 'Forbidden: Không có quyền thao tác trên đơn hàng này', 'code': 403}), 403

        # Idempotent check: trạng thái đã đúng yêu cầu thì không xử lý lại
        if new_status == order['Status']:
            conn.commit()
            return jsonify({'message': f'Đơn hàng đã ở trạng thái {new_status}'})

        # Chỉ được hủy đơn đang chờ duyệt (chưa trừ tồn kho)
        if new_status == 'Cancelled' and order['Status'] != 'Pending':
            conn.rollback()
            return jsonify({'error': 'Chỉ có thể hủy đơn hàng đang chờ duyệt (Pending)', 'code': 409}), 409

        # Chuyển sang Accepted: trừ đúng Quantity đơn vị tồn kho với Row-Level Locking (SELECT ... FOR UPDATE)
        if new_status == 'Accepted' and order['Status'] != 'Accepted':
            cursor.execute(
                "SELECT InventoryID, QuantityAvailable FROM inventory WHERE ProductID=%s ORDER BY QuantityAvailable DESC FOR UPDATE",
                (order['ProductID'],)
            )
            rows = cursor.fetchall()
            need = int(order.get('Quantity') or 1)
            total_available = sum(r['QuantityAvailable'] for r in rows)
            if total_available < need:
                conn.rollback()
                return jsonify({'error': f'Sản phẩm không đủ tồn kho (Còn {total_available}, yêu cầu {need})', 'code': 409}), 409

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
                    need -= take
                if need == 0:
                    break

            if need > 0:
                conn.rollback()
                return jsonify({'error': 'Sản phẩm đã hết hàng', 'code': 409}), 409

        cursor.execute("UPDATE orders SET Status=%s WHERE OrderID=%s", (new_status, oid))
        conn.commit()
        return jsonify({'message': 'Order status updated'})
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
        SELECT pr.*, p.ProductName, p.UnitPrice, p.Unit
        FROM purchase_requisitions pr
        JOIN product p ON p.ProductID = pr.ProductID
        ORDER BY pr.CreatedAt DESC, pr.PRID DESC
    """)
    data = cursor.fetchall()
    for row in data:
        if row.get('CreatedAt'):
            row['CreatedAt'] = str(row['CreatedAt'])
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/purchase-requisitions', methods=['POST'])
@limiter.limit("10 per minute")
def add_purchase_requisition():
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, PR_ALLOWED_CREATE)
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400
    product_id = str(clean.get('ProductID') or '').strip()
    if not product_id:
        return jsonify({'error': 'Thiếu trường bắt buộc: ProductID', 'code': 400}), 400
    try:
        quantity = int(clean.get('Quantity'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Số lượng không hợp lệ', 'code': 400}), 400
    if quantity < 1:
        return jsonify({'error': 'Số lượng phải lớn hơn 0', 'code': 400}), 400
    requested_by = str(clean.get('RequestedBy') or get_jwt().get('sub') or 'admin').strip()[:50]

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT 1 FROM product WHERE ProductID=%s", (product_id,))
        if not cursor.fetchone():
            conn.rollback()
            return jsonify({'error': 'Sản phẩm không tồn tại', 'code': 400}), 400
        prid = next_entity_id(cursor, 'PR', 'PR')
        cursor.execute("""
            INSERT INTO purchase_requisitions (PRID, ProductID, Quantity, RequestedBy, Status)
            VALUES (%s, %s, %s, %s, 'Pending_Approval')
        """, (prid, product_id, quantity, requested_by))
        conn.commit()
        return jsonify({'message': 'Đã tạo yêu cầu mua hàng', 'PRID': prid}), 201
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
    if new_status not in ('Approved', 'Rejected'):
        return jsonify({'error': 'Trạng thái không hợp lệ (Approved/Rejected)', 'code': 400}), 400

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
        if row['Status'] not in ('Pending_Approval', 'Draft'):
            conn.rollback()
            return jsonify({'error': f'Không thể duyệt yêu cầu ở trạng thái {row["Status"]}', 'code': 409}), 409
        cursor.execute("UPDATE purchase_requisitions SET Status=%s WHERE PRID=%s", (new_status, prid))
        conn.commit()
        return jsonify({'message': 'Cập nhật trạng thái yêu cầu mua hàng thành công'})
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
        SELECT po.*, s.SupplierName, p.ProductName, p.Unit, pr.RequestedBy
        FROM purchase_orders po
        JOIN supplier s ON s.SupplierID = po.SupplierID
        JOIN product p ON p.ProductID = po.ProductID
        LEFT JOIN purchase_requisitions pr ON pr.PRID = po.PRID
        ORDER BY po.OrderDate DESC, po.POID DESC
    """)
    data = cursor.fetchall()
    for row in data:
        if row.get('OrderDate'):
            row['OrderDate'] = str(row['OrderDate'])
        if row.get('CreatedAt'):
            row['CreatedAt'] = str(row['CreatedAt'])
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/purchase-orders', methods=['POST'])
@limiter.limit("10 per minute")
def add_purchase_order():
    err = admin_required()
    if err: return err
    d = request.get_json(silent=True) or {}
    clean, err_msg = extract_whitelisted_fields(d, PO_ALLOWED_CREATE)
    if err_msg:
        return jsonify({'error': err_msg, 'code': 400}), 400

    supplier_id = str(clean.get('SupplierID') or '').strip()
    if not supplier_id:
        return jsonify({'error': 'Thiếu trường bắt buộc: SupplierID', 'code': 400}), 400
    try:
        unit_price = float(clean.get('UnitPrice'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Đơn giá không hợp lệ', 'code': 400}), 400
    if unit_price < 0:
        return jsonify({'error': 'Đơn giá không được âm', 'code': 400}), 400

    order_date = str(clean.get('OrderDate') or date.today().isoformat()).strip()
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', order_date):
        return jsonify({'error': 'OrderDate không hợp lệ (YYYY-MM-DD)', 'code': 400}), 400

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

        if prid:
            cursor.execute("""
                SELECT ProductID, Quantity, Status
                FROM purchase_requisitions WHERE PRID=%s FOR UPDATE
            """, (prid,))
            pr = cursor.fetchone()
            if not pr:
                conn.rollback()
                return jsonify({'error': 'Không tìm thấy yêu cầu mua hàng', 'code': 404}), 404
            if pr['Status'] != 'Approved':
                conn.rollback()
                return jsonify({'error': 'Chỉ có thể tạo đơn mua từ yêu cầu đã duyệt', 'code': 409}), 409
            product_id = pr['ProductID']
            quantity = int(pr['Quantity'])
            cursor.execute("""
                SELECT POID FROM purchase_orders
                WHERE PRID=%s AND Status IN ('Ordered','Received') LIMIT 1
            """, (prid,))
            if cursor.fetchone():
                conn.rollback()
                return jsonify({'error': 'Yêu cầu mua hàng này đã có đơn mua', 'code': 409}), 409
        else:
            product_id = str(clean.get('ProductID') or '').strip()
            if not product_id:
                conn.rollback()
                return jsonify({'error': 'Thiếu trường bắt buộc: ProductID', 'code': 400}), 400
            try:
                quantity = int(clean.get('Quantity'))
            except (TypeError, ValueError):
                conn.rollback()
                return jsonify({'error': 'Số lượng không hợp lệ', 'code': 400}), 400
            if quantity < 1:
                conn.rollback()
                return jsonify({'error': 'Số lượng phải lớn hơn 0', 'code': 400}), 400
            cursor.execute("SELECT 1 FROM product WHERE ProductID=%s", (product_id,))
            if not cursor.fetchone():
                conn.rollback()
                return jsonify({'error': 'Sản phẩm không tồn tại', 'code': 400}), 400

        total_amount = round(quantity * unit_price, 2)
        poid = next_entity_id(cursor, 'PO', 'PO')
        cursor.execute("""
            INSERT INTO purchase_orders
                (POID, PRID, SupplierID, ProductID, Quantity, UnitPrice, TotalAmount, Status, OrderDate)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'Ordered', %s)
        """, (poid, prid or None, supplier_id, product_id, quantity, unit_price, total_amount, order_date))
        conn.commit()
        return jsonify({
            'message': 'Đã tạo đơn mua hàng',
            'POID': poid,
            'TotalAmount': total_amount,
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
        if po['Status'] == 'Cancelled':
            conn.rollback()
            return jsonify({'error': 'Không thể nhận đơn mua đã hủy', 'code': 409}), 409

        inventory = lock_inventory_for_product(cursor, po['ProductID'])
        if not inventory:
            conn.rollback()
            return jsonify({'error': 'Sản phẩm chưa có bản ghi tồn kho. Vui lòng tạo tồn kho trước khi nhận hàng.', 'code': 409}), 409
        old_quantity = int(inventory['QuantityAvailable'] or 0)
        new_quantity = old_quantity + int(po['Quantity'])
        cursor.execute("""
            UPDATE inventory SET QuantityAvailable=%s WHERE InventoryID=%s
        """, (new_quantity, inventory['InventoryID']))
        adjustment_id = write_inventory_adjustment(
            cursor, inventory['InventoryID'], old_quantity, new_quantity, 'Nhập thêm'
        )
        cursor.execute("UPDATE purchase_orders SET Status='Received' WHERE POID=%s", (poid,))
        conn.commit()
        return jsonify({
            'message': 'Nhập kho thành công',
            'POID': poid,
            'InventoryID': inventory['InventoryID'],
            'OldQuantity': old_quantity,
            'NewQuantity': new_quantity,
            'AdjustmentID': adjustment_id,
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
    else:
        cursor.execute(base_sql + " WHERE o.CustomerID=%s ORDER BY r.CreatedAt DESC, r.ReturnID DESC", (cid,))
    data = cursor.fetchall()
    for row in data:
        if row.get('CreatedAt'):
            row['CreatedAt'] = str(row['CreatedAt'])
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/returns', methods=['POST'])
@limiter.limit("10 per minute")
def add_return_order():
    claims = get_jwt()
    role = claims.get('role')
    cid = claims.get('customer_id')
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

    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT OrderID, CustomerID, ProductID, Quantity, Status
            FROM orders WHERE OrderID=%s FOR UPDATE
        """, (order_id,))
        order = cursor.fetchone()
        if not order:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy đơn hàng gốc', 'code': 404}), 404
        if role != 'admin' and (not cid or order['CustomerID'] != cid):
            conn.rollback()
            return jsonify({'error': 'Forbidden: Không có quyền trả đơn hàng này', 'code': 403}), 403
        if order['Status'] != 'Accepted':
            conn.rollback()
            return jsonify({'error': 'Chỉ có thể yêu cầu trả hàng cho đơn đã duyệt', 'code': 409}), 409
        if quantity > int(order['Quantity']):
            conn.rollback()
            return jsonify({'error': f'Số lượng trả vượt quá số lượng đơn ({order["Quantity"]})', 'code': 400}), 400

        cursor.execute("""
            SELECT Quantity FROM return_orders
            WHERE OriginalOrderID=%s AND Status IN ('Pending','Approved') FOR UPDATE
        """, (order_id,))
        used = sum(int(r['Quantity']) for r in cursor.fetchall())
        if used + quantity > int(order['Quantity']):
            conn.rollback()
            return jsonify({'error': f'Đã có {used} sản phẩm được yêu cầu trả cho đơn này', 'code': 409}), 409

        return_id = next_entity_id(cursor, 'RTN', 'RTN')
        cursor.execute("""
            INSERT INTO return_orders
                (ReturnID, OriginalOrderID, ProductID, Quantity, Reason, Status, RefundAmount)
            VALUES (%s, %s, %s, %s, %s, 'Pending', 0)
        """, (return_id, order_id, order['ProductID'], quantity, reason))
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

            inventory = lock_inventory_for_product(cursor, ret['ProductID'])
            if not inventory:
                conn.rollback()
                return jsonify({'error': 'Sản phẩm chưa có bản ghi tồn kho để hoàn hàng', 'code': 409}), 409
            old_quantity = int(inventory['QuantityAvailable'] or 0)
            new_quantity = old_quantity + int(ret['Quantity'])
            cursor.execute("""
                UPDATE inventory SET QuantityAvailable=%s WHERE InventoryID=%s
            """, (new_quantity, inventory['InventoryID']))
            write_inventory_adjustment(
                cursor, inventory['InventoryID'], old_quantity, new_quantity, 'Trả hàng'
            )
            if order['Status'] == 'Accepted' and int(order['Quantity']) > 0:
                refund_amount = round(
                    (float(order['Bill']) / int(order['Quantity'])) * int(ret['Quantity']), 2
                )

        cursor.execute("""
            UPDATE return_orders SET Status=%s, RefundAmount=%s WHERE ReturnID=%s
        """, (new_status, refund_amount, rid))
        conn.commit()
        return jsonify({
            'message': 'Đã duyệt yêu cầu trả hàng' if new_status == 'Approved' else 'Đã từ chối yêu cầu trả hàng',
            'ReturnID': rid,
            'RefundAmount': refund_amount,
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
    for row in data:
        if row.get('CreatedAt'):
            row['CreatedAt'] = str(row['CreatedAt'])
    cursor.close(); conn.close()
    return jsonify(data)

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
    if session.get('CreatedAt'):
        session['CreatedAt'] = str(session['CreatedAt'])
    session['items'] = items
    cursor.close(); conn.close()
    return jsonify(session)

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
            adjusted += 1

        cursor.execute("UPDATE stocktake_sessions SET Status='Completed' WHERE SessionID=%s", (sid,))
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
#  RUN
# ══════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    
    

