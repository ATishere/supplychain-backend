import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request
from werkzeug.exceptions import HTTPException
import bcrypt
from db import get_connection
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "dev-secret-change-me")
jwt = JWTManager(app)
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
CORS(app, resources={r"/api/*": {"origins": CORS_ORIGINS, "supports_credentials": True}})

# ══════════════════════════════════════════════════════
#  GLOBAL ERROR HANDLERS — always return JSON, never HTML
# ══════════════════════════════════════════════════════

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
    if request.method == "OPTIONS":          # CORS preflight
        return None
    if not request.path.startswith("/api/"):
        return None
    if request.path in PUBLIC_PATHS:
        return None
    verify_jwt_in_request()                  # raises 401 JSON if token missing/invalid
    return None

# ══════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════

@app.route('/api/auth/login', methods=['POST'])
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
        if not u or not bcrypt.checkpw(password.encode('utf-8'), u['PasswordHash'].encode('utf-8')):
            return jsonify({'error': 'Sai tên đăng nhập hoặc mật khẩu', 'code': 401}), 401
        token = create_access_token(
            identity=u['Username'],
            additional_claims={'role': u['Role'], 'customer_id': u.get('CustomerID')}
        )
        return jsonify({'access_token': token, 'role': u['Role'], 'customer_id': u.get('CustomerID')})
    finally:
        conn.close()

@app.route('/api/auth/customer-login', methods=['POST'])
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
        if not u or not bcrypt.checkpw(password.encode('utf-8'), u['PasswordHash'].encode('utf-8')):
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

# ══════════════════════════════════════════════════════
#  SUPPLIER
# ══════════════════════════════════════════════════════

@app.route('/api/suppliers', methods=['GET'])
def get_suppliers():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM supplier ORDER BY SupplierID")
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/suppliers', methods=['POST'])
def add_supplier():
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
def update_supplier(sid):
    d = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM supplier WHERE SupplierID=%s", (sid,))
    if not cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy nhà cung cấp', 'code': 404}), 404
    cursor.execute("""
        UPDATE supplier SET SupplierName=%s, ContactNumber=%s, Location=%s, TaxCode=%s, Email=%s
        WHERE SupplierID=%s
    """, (d['SupplierName'], d['ContactNumber'], d['Location'], d.get('TaxCode'), d.get('Email'), sid))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Supplier updated'})

@app.route('/api/suppliers/<sid>', methods=['DELETE'])
def delete_supplier(sid):
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
def get_products():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM product ORDER BY ProductID")
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/products', methods=['POST'])
def add_product():
    d = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO product (ProductID, ProductName, Category, UnitPrice, SupplierID, Unit, Origin)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (d['ProductID'], d['ProductName'], d['Category'], d['UnitPrice'], d['SupplierID'], d.get('Unit', 'Cái'), d.get('Origin', 'Việt Nam')))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Product added'}), 201

@app.route('/api/products/<pid>', methods=['PUT'])
def update_product(pid):
    d = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM product WHERE ProductID=%s", (pid,))
    if not cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy sản phẩm', 'code': 404}), 404
    cursor.execute("""
        UPDATE product SET ProductName=%s, Category=%s, UnitPrice=%s, SupplierID=%s, Unit=%s, Origin=%s
        WHERE ProductID=%s
    """, (d['ProductName'], d['Category'], d['UnitPrice'], d['SupplierID'], d.get('Unit', 'Cái'), d.get('Origin', 'Việt Nam'), pid))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Product updated'})

@app.route('/api/products/<pid>', methods=['DELETE'])
def delete_product(pid):
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
def get_warehouses():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM warehouse ORDER BY WarehouseID")
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/warehouses', methods=['POST'])
def add_warehouse():
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
def update_warehouse(wid):
    d = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM warehouse WHERE WarehouseID=%s", (wid,))
    if not cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy kho hàng', 'code': 404}), 404
    cursor.execute("""
        UPDATE warehouse SET WarehouseName=%s, Location=%s, Capacity=%s, ProvinceCode=%s
        WHERE WarehouseID=%s
    """, (d['WarehouseName'], d['Location'], d['Capacity'], d.get('ProvinceCode'), wid))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Warehouse updated'})

@app.route('/api/warehouses/<wid>', methods=['DELETE'])
def delete_warehouse(wid):
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
def get_inventory():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM inventory ORDER BY InventoryID")
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/inventory', methods=['POST'])
def add_inventory():
    d = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO inventory (InventoryID, QuantityAvailable, ProductID, WarehouseID)
        VALUES (%s, %s, %s, %s)
    """, (d['InventoryID'], d['QuantityAvailable'], d['ProductID'], d['WarehouseID']))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Inventory added'}), 201

@app.route('/api/inventory/<iid>', methods=['PUT'])
def update_inventory(iid):
    d = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM inventory WHERE InventoryID=%s", (iid,))
    if not cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy bản ghi tồn kho', 'code': 404}), 404
    cursor.execute("""
        UPDATE inventory SET QuantityAvailable=%s, ProductID=%s, WarehouseID=%s
        WHERE InventoryID=%s
    """, (d['QuantityAvailable'], d['ProductID'], d['WarehouseID'], iid))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Inventory updated'})

@app.route('/api/inventory/<iid>', methods=['DELETE'])
def delete_inventory(iid):
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
def get_customers():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM customer ORDER BY CustomerID")
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/customers', methods=['POST'])
def add_customer():
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
def update_customer(cid):
    d = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM customer WHERE CustomerID=%s", (cid,))
    if not cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy khách hàng', 'code': 404}), 404
    cursor.execute("""
        UPDATE customer SET CustomerName=%s, ContactNumber=%s, Address=%s, TaxCode=%s, CustomerType=%s
        WHERE CustomerID=%s
    """, (d['CustomerName'], d['ContactNumber'], d['Address'], d.get('TaxCode'), d.get('CustomerType', 'Individual'), cid))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Customer updated'})

@app.route('/api/customers/<cid>', methods=['DELETE'])
def delete_customer(cid):
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
def get_orders():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM orders ORDER BY OrderDate DESC, OrderID DESC")
    data = cursor.fetchall()
    for row in data:
        if row.get('OrderDate'):
            row['OrderDate'] = str(row['OrderDate'])
    cursor.close(); conn.close()
    return jsonify(data)

@app.route('/api/orders', methods=['POST'])
def add_order():
    d = request.json
    try:
        qty = int(d.get('Quantity', 1) or 1)
    except (TypeError, ValueError):
        return jsonify({'error': 'Số lượng không hợp lệ', 'code': 400}), 400
    if qty < 1:
        return jsonify({'error': 'Số lượng phải lớn hơn 0', 'code': 400}), 400
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO orders (OrderID, OrderDate, Bill, CustomerID, ProductID, Quantity, Status, InvoiceNumber, VatRate, VatAmount, PaymentMethod)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (d['OrderID'], d['OrderDate'], d['Bill'], d['CustomerID'], d['ProductID'], qty, d.get('Status', 'Pending'), d.get('InvoiceNumber'), d.get('VatRate', 10), d.get('VatAmount', 0), d.get('PaymentMethod', 'Tiền mặt')))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Order added'}), 201

@app.route('/api/orders/<oid>', methods=['PUT'])
def update_order(oid):
    d = request.json
    try:
        qty = int(d.get('Quantity', 1) or 1)
    except (TypeError, ValueError):
        return jsonify({'error': 'Số lượng không hợp lệ', 'code': 400}), 400
    if qty < 1:
        return jsonify({'error': 'Số lượng phải lớn hơn 0', 'code': 400}), 400
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM orders WHERE OrderID=%s", (oid,))
    if not cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy đơn hàng', 'code': 404}), 404
    cursor.execute("""
        UPDATE orders SET OrderDate=%s, Bill=%s, CustomerID=%s, ProductID=%s, Quantity=%s, Status=%s, InvoiceNumber=%s, VatRate=%s, VatAmount=%s, PaymentMethod=%s
        WHERE OrderID=%s
    """, (d['OrderDate'], d['Bill'], d['CustomerID'], d['ProductID'], qty, d.get('Status', 'Pending'), d.get('InvoiceNumber'), d.get('VatRate', 10), d.get('VatAmount', 0), d.get('PaymentMethod', 'Tiền mặt'), oid))
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Order updated'})

@app.route('/api/orders/<oid>', methods=['DELETE'])
def delete_order(oid):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM orders WHERE OrderID=%s", (oid,))
    if cursor.rowcount == 0:
        conn.rollback(); cursor.close(); conn.close()
        return jsonify({'error': 'Không tìm thấy đơn hàng', 'code': 404}), 404
    conn.commit(); cursor.close(); conn.close()
    return jsonify({'message': 'Order deleted'})

@app.route('/api/orders/<oid>/status', methods=['PATCH'])
def update_order_status(oid):
    d = request.json
    new_status = d.get('Status')
    if new_status not in ('Accepted', 'Pending', 'Rejected'):
        return jsonify({'error': 'Trạng thái không hợp lệ (Pending/Accepted/Rejected)', 'code': 400}), 400
    conn = get_connection()
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT ProductID, Status, Quantity FROM orders WHERE OrderID=%s FOR UPDATE", (oid,))
        order = cursor.fetchone()
        if not order:
            conn.rollback()
            return jsonify({'error': 'Không tìm thấy đơn hàng', 'code': 404}), 404
        # Chuyển sang Accepted: trừ đúng Quantity đơn vị tồn kho (chỉ trừ 1 lần — nếu đã Accepted rồi thì bỏ qua)
        if new_status == 'Accepted' and order['Status'] != 'Accepted':
            cursor.execute(
                "SELECT InventoryID, QuantityAvailable FROM inventory WHERE ProductID=%s ORDER BY QuantityAvailable DESC FOR UPDATE",
                (order['ProductID'],))
            rows = cursor.fetchall()
            need = int(order.get('Quantity') or 1)
            for r in rows:
                take = min(r['QuantityAvailable'], need)
                if take > 0:
                    cursor.execute("UPDATE inventory SET QuantityAvailable=QuantityAvailable-%s WHERE InventoryID=%s",
                                   (take, r['InventoryID']))
                    need -= take
                if need == 0:
                    break
            if need > 0:
                conn.rollback()
                return jsonify({'error': 'Sản phẩm đã hết hàng', 'code': 409}), 409
        cursor.execute("UPDATE orders SET Status=%s WHERE OrderID=%s", (new_status, oid))
        conn.commit()
        return jsonify({'message': 'Order status updated'})
    except Exception:
        conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        conn.close()

# ══════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    
    

