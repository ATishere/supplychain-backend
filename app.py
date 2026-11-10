import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, get_jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
import bcrypt
import mysql.connector
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
    "http://localhost:3000,http://127.0.0.1:3000,https://chainsync.vercel.app"
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

SUPPLIER_ALLOWED_UPDATE  = {'SupplierName', 'ContactNumber', 'Location', 'TaxCode', 'Email', 'SupplierID'}
PRODUCT_ALLOWED_UPDATE   = {'ProductName', 'Category', 'UnitPrice', 'SupplierID', 'Unit', 'Origin', 'ProductID'}
WAREHOUSE_ALLOWED_UPDATE = {'WarehouseName', 'Location', 'Capacity', 'ProvinceCode', 'WarehouseID'}
INVENTORY_ALLOWED_UPDATE = {'QuantityAvailable', 'ProductID', 'WarehouseID', 'InventoryID'}
CUSTOMER_ALLOWED_UPDATE  = {'CustomerName', 'ContactNumber', 'Address', 'TaxCode', 'CustomerType', 'CustomerID'}
ORDER_ALLOWED_UPDATE     = {'OrderDate', 'Bill', 'CustomerID', 'ProductID', 'Quantity', 'InvoiceNumber', 'VatRate', 'VatAmount', 'PaymentMethod', 'OrderID'}
ORDER_ALLOWED_CREATE     = {'OrderID', 'OrderDate', 'Bill', 'CustomerID', 'ProductID', 'Quantity', 'InvoiceNumber', 'VatRate', 'VatAmount', 'PaymentMethod', 'Status'}


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
    d = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO supplier (SupplierID, SupplierName, ContactNumber, Location, TaxCode, Email)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (d['SupplierID'], d['SupplierName'], d['ContactNumber'], d['Location'], d.get('TaxCode'), d.get('Email')))
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
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM supplier WHERE SupplierID=%s", (sid,))
    if not cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy nhà cung cấp', 'code': 404}), 404
    cursor.execute("""
        UPDATE supplier SET SupplierName=%s, ContactNumber=%s, Location=%s, TaxCode=%s, Email=%s
        WHERE SupplierID=%s
    """, (clean['SupplierName'], clean['ContactNumber'], clean['Location'], clean.get('TaxCode'), clean.get('Email'), sid))
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

    for req_field in ('OrderID', 'OrderDate', 'ProductID'):
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

        cursor.execute("""
            INSERT INTO orders (OrderID, OrderDate, Bill, CustomerID, ProductID, Quantity, Status, InvoiceNumber, VatRate, VatAmount, PaymentMethod)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (clean['OrderID'], clean['OrderDate'], bill, customer_id, clean['ProductID'], qty, order_status, invoice_number, vat_rate, vat_amount, clean.get('PaymentMethod') or 'Tiền mặt'))
        conn.commit()
        return jsonify({'message': 'Order added'}), 201
    except Exception as e:
        conn.rollback()
        app.logger.error(
            "ORDER INSERT FAILED | OrderID=%s | CustomerID=%s | ProductID=%s | Quantity=%s | Role=%s | %s: %s",
            clean.get('OrderID'), customer_id, clean.get('ProductID'), qty, role, type(e).__name__, e,
            exc_info=True
        )
        print(
            f"[ORDER INSERT ERROR] OrderID={clean.get('OrderID')} CustomerID={customer_id} "
            f"ProductID={clean.get('ProductID')} Quantity={qty} Role={role} -> {type(e).__name__}: {e}",
            flush=True
        )
        return jsonify({'error': 'Không thể tạo đơn hàng. Vui lòng kiểm tra dữ liệu hoặc thử lại.', 'code': 500}), 500
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
#  RUN
# ══════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    
    

