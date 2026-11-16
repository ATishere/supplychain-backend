"""
Seed dữ liệu demo B2B cho SupplyChain7VN.

Chạy:
    python seed_b2b_demo.py

Đặc điểm:
- Idempotent: chạy lại không nhân đôi chứng từ, không reset mật khẩu đã đổi.
- Không xóa dữ liệu hiện có.
- Tạo: Organization ABC, 2 user tổ chức, CPR, SO, PR, PO, GRN, Return,
  phiên kiểm kê và Inventory Transaction Ledger tương ứng.
"""

import sys
from datetime import date, datetime, timedelta

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import bcrypt
from dotenv import load_dotenv

load_dotenv()
from db import get_connection

DEMO_PASSWORD = "org123456"
TODAY = date.today()


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────
def fetch_one(cur, sql, params=()):
    cur.execute(sql, params)
    return cur.fetchone()


def next_entity(cur, entity, prefix):
    cur.execute(
        "INSERT IGNORE INTO entity_id_sequence (entity, next_value) VALUES (%s, 0)",
        (entity,),
    )
    cur.execute(
        "UPDATE entity_id_sequence SET next_value = LAST_INSERT_ID(next_value + 1) WHERE entity = %s",
        (entity,),
    )
    cur.execute("SELECT LAST_INSERT_ID() AS n")
    return "%s%03d" % (prefix, int(cur.fetchone()["n"]))


def next_order(cur):
    cur.execute(
        "UPDATE order_id_sequence SET next_value = LAST_INSERT_ID(next_value + 1) WHERE id = 1"
    )
    cur.execute("SELECT LAST_INSERT_ID() AS n")
    return "ORD%03d" % int(cur.fetchone()["n"])


def bump_sequence(cur, entity, rows):
    """rows: iterable mã chứng từ đã có, dạng PREFIX + số."""
    max_value = 0
    for value in rows:
        digits = "".join(ch for ch in str(value) if ch.isdigit())
        if digits:
            max_value = max(max_value, int(digits))
    if max_value:
        cur.execute(
            """
            INSERT INTO entity_id_sequence (entity, next_value) VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE next_value = GREATEST(next_value, VALUES(next_value))
            """,
            (entity, max_value),
        )


def add_stock(cur, product_id, warehouse_id, qty, tx_type, ref_type, ref_id,
              notes, performed_by):
    """Cộng tồn kho + ghi ledger + inventory_adjustments (tương thích cũ)."""
    cur.execute(
        """
        SELECT InventoryID, QuantityAvailable
        FROM inventory
        WHERE ProductID=%s AND WarehouseID=%s
        ORDER BY InventoryID
        LIMIT 1
        FOR UPDATE
        """,
        (product_id, warehouse_id),
    )
    row = cur.fetchone()
    if row:
        inventory_id = row["InventoryID"]
        before = int(row["QuantityAvailable"] or 0)
    else:
        inventory_id = next_entity(cur, "INV", "INV")
        before = 0
        cur.execute(
            """
            INSERT INTO inventory (InventoryID, QuantityAvailable, ProductID, WarehouseID)
            VALUES (%s, 0, %s, %s)
            """,
            (inventory_id, product_id, warehouse_id),
        )

    after = before + int(qty)
    cur.execute(
        "UPDATE inventory SET QuantityAvailable=%s WHERE InventoryID=%s",
        (after, inventory_id),
    )

    txn_id = next_entity(cur, "TXN", "TXN")
    cur.execute(
        """
        INSERT INTO inventory_transactions
            (TransactionID, InventoryID, ProductID, WarehouseID, TransactionType,
             QuantityChange, QuantityBefore, QuantityAfter, ReferenceType,
             ReferenceID, Notes, PerformedBy)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (txn_id, inventory_id, product_id, warehouse_id, tx_type, int(qty),
         before, after, ref_type, ref_id, notes, performed_by),
    )

    adjustment_id = next_entity(cur, "ADJ", "ADJ")
    reason = "Nhập thêm" if tx_type in ("GoodsReceipt", "OpeningBalance") else "Trả hàng"
    cur.execute(
        """
        INSERT INTO inventory_adjustments
            (AdjustmentID, InventoryID, OldQuantity, NewQuantity, Reason)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (adjustment_id, inventory_id, before, after, reason),
    )
    return inventory_id, before, after, txn_id


def product_price(cur, product_id):
    row = fetch_one(cur, "SELECT UnitPrice FROM product WHERE ProductID=%s", (product_id,))
    if not row:
        raise RuntimeError(f"Sản phẩm {product_id} không tồn tại")
    return float(row["UnitPrice"])


# ──────────────────────────────────────────────────────────────
# Seed sections
# ──────────────────────────────────────────────────────────────
def seed_organization(cur):
    cur.execute(
        "SELECT * FROM organizations WHERE OrganizationID='ORG001'"
    )
    if not cur.fetchone():
        cur.execute(
            """
            INSERT INTO organizations
                (OrganizationID, OrganizationCode, OrganizationName, TaxCode,
                 OrganizationType, Address, Representative, RepresentativePhone,
                 RepresentativeEmail, Status)
            VALUES
                ('ORG001', 'ABC', 'Công ty TNHH ABC', '0301234567',
                 'OrganizationCustomer', '12 Lê Lợi, Quận 1, TP. Hồ Chí Minh',
                 'Nguyễn Văn An', '0912345678', 'contact@abc.vn', 'Active')
            """
        )
        print("  + Organization ORG001 (Công ty TNHH ABC)")

    cur.execute(
        "SELECT OrganizationID FROM customer WHERE CustomerID='C001'"
    )
    row = cur.fetchone()
    if row and not row.get("OrganizationID"):
        cur.execute(
            """
            UPDATE customer
            SET OrganizationID='ORG001', CustomerName='Công ty TNHH ABC',
                CustomerType='Business', Email='contact@abc.vn',
                Address='12 Lê Lợi, Quận 1, TP. Hồ Chí Minh'
            WHERE CustomerID='C001'
            """
        )
        print("  + Liên kết customer C001 → ORG001")


def seed_users(cur):
    users = [
        ("an.nguyen", "Nguyễn Văn An", "org_manager", "Giám đốc mua hàng", "an.nguyen@abc.vn"),
        ("binh.tran", "Trần Thị Bình", "org_staff", "Chuyên viên mua hàng", "binh.tran@abc.vn"),
    ]
    for username, full_name, role, position, email in users:
        cur.execute("SELECT UserID FROM `user` WHERE Username=%s", (username,))
        if cur.fetchone():
            continue
        password_hash = bcrypt.hashpw(DEMO_PASSWORD.encode(), bcrypt.gensalt(12)).decode()
        cur.execute(
            """
            INSERT INTO `user`
                (Username, PasswordHash, Role, CustomerID, OrganizationID,
                 FullName, Position, Email, Status)
            VALUES (%s, %s, %s, 'C001', 'ORG001', %s, %s, %s, 'Active')
            """,
            (username, password_hash, role, full_name, position, email),
        )
        print(f"  + User {username} ({role})")


def seed_cprs(cur, manager_id):
    specs = [
        {
            "id": "CPR001",
            "status": "Submitted",
            "note": "Bổ sung thiết bị cho dây chuyền sản xuất số 2",
            "items": [("P001", 2), ("P004", 5)],
            "created_at": datetime.combine(TODAY - timedelta(days=3), datetime.min.time()),
        },
        {
            "id": "CPR002",
            "status": "Approved",
            "note": "Đơn hàng nguyên vật liệu và bao bì quý IV",
            "items": [("P002", 20), ("P003", 100)],
            "created_at": datetime.combine(TODAY - timedelta(days=8), datetime.min.time()),
        },
        {
            "id": "CPR003",
            "status": "Converted",
            "note": "Nhu cầu thép và vật tư đóng gói tháng 11",
            "items": [("P005", 50), ("P006", 30)],
            "created_at": datetime.combine(TODAY - timedelta(days=15), datetime.min.time()),
        },
    ]

    for spec in specs:
        cur.execute("SELECT CPRID, Status FROM customer_purchase_requests WHERE CPRID=%s", (spec["id"],))
        existing = cur.fetchone()
        if existing:
            continue

        total = sum(product_price(cur, pid) * qty for pid, qty in spec["items"])
        cur.execute(
            """
            INSERT INTO customer_purchase_requests
                (CPRID, OrganizationID, CustomerID, RequestedByUserID,
                 RequestedByName, Status, Note, TotalEstimated, ApprovedByName,
                 ApprovedAt, ConvertedAt, CreatedAt)
            VALUES (%s, 'ORG001', 'C001', %s, 'Trần Thị Bình', %s, %s, %s,
                    %s, %s, %s, %s)
            """,
            (
                spec["id"], manager_id, spec["status"], spec["note"], round(total, 2),
                "Nguyễn Văn An" if spec["status"] in ("Approved", "Converted") else None,
                datetime.combine(TODAY - timedelta(days=2), datetime.min.time())
                if spec["status"] in ("Approved", "Converted") else None,
                datetime.combine(TODAY - timedelta(days=12), datetime.min.time())
                if spec["status"] == "Converted" else None,
                spec["created_at"],
            ),
        )
        for line_no, (pid, qty) in enumerate(spec["items"], 1):
            cur.execute(
                """
                INSERT INTO customer_purchase_request_items
                    (CPRID, LineNo, ProductID, Quantity, UnitPrice)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (spec["id"], line_no, pid, qty, product_price(cur, pid)),
            )
        print(f"  + CPR {spec['id']} ({spec['status']})")

    # Convert CPR003 → 2 SO (Pending)
    if int(fetch_one(cur, "SELECT COUNT(*) AS n FROM orders WHERE SourceCPRID='CPR003'")["n"]) == 0:
        cur.execute(
            "SELECT ProductID, Quantity, UnitPrice FROM customer_purchase_request_items "
            "WHERE CPRID='CPR003' ORDER BY LineNo"
        )
        for item in cur.fetchall():
            order_id = next_order(cur)
            qty = int(item["Quantity"])
            bill = round(float(item["UnitPrice"]) * qty, 2)
            vat_amount = round(bill * 0.10, 2)
            cur.execute(
                """
                INSERT INTO orders
                    (OrderID, OrderDate, Bill, CustomerID, Status, ProductID,
                     Quantity, InvoiceNumber, VatRate, VatAmount, PaymentMethod,
                     OrganizationID, SourceCPRID, WarehouseID, CreatedByUserID)
                VALUES (%s, %s, %s, 'C001', 'Pending', %s, %s, NULL, 10.00, %s,
                        'Chuyển khoản', 'ORG001', 'CPR003', 'W001', 1)
                """,
                (order_id, TODAY - timedelta(days=12), bill, item["ProductID"],
                 qty, vat_amount),
            )
            print(f"  + SO {order_id} từ CPR003")
        cur.execute(
            "UPDATE customer_purchase_requests SET ConvertedAt=%s WHERE CPRID='CPR003' AND ConvertedAt IS NULL",
            (datetime.combine(TODAY - timedelta(days=12), datetime.min.time()),),
        )

    # Gắn lịch sử đơn của C001 vào tổ chức
    cur.execute(
        "UPDATE orders SET OrganizationID='ORG001' WHERE CustomerID='C001' AND OrganizationID IS NULL"
    )


def seed_procurement(cur):
    pr_specs = [
        {
            "id": "PR001",
            "status": "Approved",
            "items": [("P002", 100), ("P003", 500)],
            "reason": "Bổ sung tồn kho nguyên liệu và bao bì quý IV",
            "warehouse": "W001",
            "requested_by": "Nguyễn Văn An",
            "created": TODAY - timedelta(days=6),
            "approved": True,
        },
        {
            "id": "PR002",
            "status": "Pending_Approval",
            "items": [("P004", 20), ("P006", 10)],
            "reason": "Thiết bị điện tử phục vụ bảo trì",
            "warehouse": "W002",
            "requested_by": "Trần Thị Bình",
            "created": TODAY - timedelta(days=2),
            "approved": False,
        },
        {
            "id": "PR003",
            "status": "Converted",
            "items": [("P001", 5)],
            "reason": "Mua động cơ bổ sung theo yêu cầu CPR003",
            "warehouse": "W001",
            "requested_by": "Nguyễn Văn An",
            "created": TODAY - timedelta(days=14),
            "approved": True,
        },
    ]
    first_ids = {}
    for spec in pr_specs:
        cur.execute("SELECT PRID, Status FROM purchase_requisitions WHERE PRID=%s", (spec["id"],))
        if cur.fetchone():
            continue
        first_product, first_qty = spec["items"][0]
        first_ids[spec["id"]] = (first_product, first_qty)
        cur.execute(
            """
            INSERT INTO purchase_requisitions
                (PRID, ProductID, Quantity, RequestedBy, Status, CreatedAt, Reason,
                 WarehouseID, OrganizationID, CreatedByUserID, ApprovedBy, ApprovedAt)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NULL, 1, %s, %s)
            """,
            (
                spec["id"], first_product, first_qty, spec["requested_by"],
                spec["status"], datetime.combine(spec["created"], datetime.min.time()),
                spec["reason"], spec["warehouse"],
                "admin" if spec["approved"] else None,
                datetime.combine(spec["created"] + timedelta(days=1), datetime.min.time())
                if spec["approved"] else None,
            ),
        )
        for line_no, (pid, qty) in enumerate(spec["items"], 1):
            cur.execute(
                """
                INSERT INTO purchase_requisition_items (PRID, LineNo, ProductID, Quantity)
                VALUES (%s, %s, %s, %s)
                """,
                (spec["id"], line_no, pid, qty),
            )
        print(f"  + PR {spec['id']} ({spec['status']})")

    # PO001 — từ PR003, nhận một phần 3/5
    po_specs = [
        {
            "id": "PO001",
            "prid": "PR003",
            "supplier": "S002",
            "items": [("P001", 5, 11800000.00)],
            "status": "Partially_Received",
            "order_date": TODAY - timedelta(days=12),
            "expected": TODAY + timedelta(days=3),
            "warehouse": "W001",
            "received": [("P001", 3)],
            "grn": "GRN001",
            "notes": "Nhận đợt 1, còn 2 chiếc chờ giao",
        },
        {
            "id": "PO002",
            "prid": None,
            "supplier": "S005",
            "items": [("P003", 500, 13500.00)],
            "status": "Received",
            "order_date": TODAY - timedelta(days=20),
            "expected": TODAY - timedelta(days=10),
            "warehouse": "W001",
            "received": [("P003", 500)],
            "grn": "GRN002",
            "notes": "Giao đủ, đã nhập kho",
        },
        {
            "id": "PO003",
            "prid": None,
            "supplier": "S004",
            "items": [("P004", 30, 1420000.00)],
            "status": "Sent",
            "order_date": TODAY - timedelta(days=4),
            "expected": TODAY + timedelta(days=6),
            "warehouse": "W001",
            "received": [],
            "grn": None,
            "notes": "Đã gửi nhà cung cấp, chờ giao",
        },
    ]

    for spec in po_specs:
        cur.execute("SELECT POID FROM purchase_orders WHERE POID=%s", (spec["id"],))
        if cur.fetchone():
            continue

        first_pid, first_qty, first_price = spec["items"][0]
        total = round(sum(qty * price for _, qty, price in spec["items"]), 2)
        cur.execute(
            """
            INSERT INTO purchase_orders
                (POID, PRID, SupplierID, ProductID, Quantity, UnitPrice,
                 TotalAmount, Status, OrderDate, CreatedAt, ExpectedDate,
                 WarehouseID, TaxAmount, ShippingFee, Notes, SentAt,
                 CompletedAt, CreatedByUserID)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    0.00, 0.00, %s, %s, %s, 1)
            """,
            (
                spec["id"], spec["prid"], spec["supplier"], first_pid, first_qty,
                first_price, total, spec["status"], spec["order_date"],
                datetime.combine(spec["order_date"], datetime.min.time()),
                spec["expected"], spec["warehouse"], spec["notes"],
                datetime.combine(spec["order_date"], datetime.min.time())
                if spec["status"] in ("Sent", "Partially_Received", "Received") else None,
                datetime.combine(spec["order_date"] + timedelta(days=10), datetime.min.time())
                if spec["status"] == "Received" else None,
            ),
        )
        for line_no, (pid, qty, price) in enumerate(spec["items"], 1):
            cur.execute(
                """
                INSERT INTO purchase_order_items
                    (POID, LineNo, ProductID, Quantity, UnitPrice, LineTotal,
                     ReceivedQuantity)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (spec["id"], line_no, pid, qty, price, round(qty * price, 2),
                 sum(q for p, q in spec["received"] if p == pid)),
            )
        print(f"  + PO {spec['id']} ({spec['status']})")

        if spec["prid"]:
            cur.execute(
                "UPDATE purchase_requisitions SET Status='Converted' WHERE PRID=%s",
                (spec["prid"],),
            )

        # GRN + cộng kho (chỉ chạy một lần)
        if spec["grn"]:
            cur.execute("SELECT GRNID FROM goods_receipt_notes WHERE GRNID=%s", (spec["grn"],))
            if not cur.fetchone():
                received_at = datetime.combine(
                    spec["order_date"] + timedelta(days=2), datetime.min.time()
                )
                cur.execute(
                    """
                    INSERT INTO goods_receipt_notes
                        (GRNID, POID, WarehouseID, ReceivedBy, ReceivedAt, Notes, Status)
                    VALUES (%s, %s, %s, 'admin', %s, %s, 'Posted')
                    """,
                    (spec["grn"], spec["id"], spec["warehouse"], received_at, spec["notes"]),
                )
                for line_no, (pid, qty) in enumerate(spec["received"], 1):
                    cur.execute(
                        """
                        INSERT INTO goods_receipt_items
                            (GRNID, LineNo, ProductID, QuantityReceived)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (spec["grn"], line_no, pid, qty),
                    )
                    add_stock(
                        cur, pid, spec["warehouse"], qty, "GoodsReceipt",
                        "GRN", spec["grn"], f"Nhập hàng theo {spec['id']}", "admin",
                    )
                print(f"  + GRN {spec['grn']} (nhận {sum(q for _, q in spec['received'])})")

    # Đảm bảo ReceivedQuantity khớp GRN kể cả khi GRN có sẵn từ lần chạy trước
    cur.execute(
        """
        UPDATE purchase_order_items poi
        JOIN goods_receipt_items gri ON gri.ProductID = poi.ProductID
        JOIN goods_receipt_notes grn ON grn.GRNID = gri.GRNID AND grn.POID = poi.POID
        SET poi.ReceivedQuantity = LEAST(
            poi.Quantity,
            (SELECT COALESCE(SUM(gri2.QuantityReceived), 0)
             FROM goods_receipt_items gri2
             JOIN goods_receipt_notes grn2 ON grn2.GRNID = gri2.GRNID
             WHERE grn2.POID = poi.POID AND gri2.ProductID = poi.ProductID)
        )
        """
    )


def seed_returns(cur):
    cur.execute("SELECT OrderID, Quantity, ProductID FROM orders WHERE OrderID='ORD001'")
    order = cur.fetchone()
    if not order:
        return

    # RTN001 — chờ duyệt
    cur.execute("SELECT ReturnID FROM return_orders WHERE ReturnID='RTN001'")
    if not cur.fetchone():
        cur.execute(
            """
            INSERT INTO return_orders
                (ReturnID, OriginalOrderID, ProductID, Quantity, Reason, Status,
                 RefundAmount, OrganizationID, RefundStatus, CreatedAt)
            VALUES ('RTN001', 'ORD001', %s, 1,
                    'Động cơ có tiếng ồn bất thường khi chạy thử',
                    'Pending', 0.00, 'ORG001', 'None', %s)
            """,
            (order["ProductID"], datetime.combine(TODAY - timedelta(days=2), datetime.min.time())),
        )
        print("  + Return RTN001 (Pending)")

    # RTN002 — đã duyệt, đã nhận hàng, đã hoàn tiền
    cur.execute("SELECT ReturnID FROM return_orders WHERE ReturnID='RTN002'")
    if not cur.fetchone():
        refund = round((25000000.00 / 2) * 1, 2)
        cur.execute(
            """
            INSERT INTO return_orders
                (ReturnID, OriginalOrderID, ProductID, Quantity, Reason, Status,
                 RefundAmount, OrganizationID, RefundStatus, ReviewedBy,
                 ReviewedAt, ReceivedBy, ReceivedAt, CreatedAt)
            VALUES ('RTN002', 'ORD001', %s, 1,
                    'Sai quy cách so với đơn đặt hàng',
                    'Received', %s, 'ORG001', 'Refunded', 'admin', %s, 'admin', %s, %s)
            """,
            (
                order["ProductID"], refund,
                datetime.combine(TODAY - timedelta(days=6), datetime.min.time()),
                datetime.combine(TODAY - timedelta(days=4), datetime.min.time()),
                datetime.combine(TODAY - timedelta(days=7), datetime.min.time()),
            ),
        )
        add_stock(
            cur, order["ProductID"], "W001", 1, "CustomerReturn",
            "RTN", "RTN002", "Nhận hàng trả theo RTN002", "admin",
        )
        print("  + Return RTN002 (Received, đã cộng kho)")


def seed_stocktake(cur):
    cur.execute("SELECT SessionID FROM stocktake_sessions WHERE SessionID='ST001'")
    if cur.fetchone():
        return

    cur.execute(
        """
        INSERT INTO stocktake_sessions
            (SessionID, WarehouseID, CreatedBy, Status, CreatedAt,
             CompletedBy, CompletedAt)
        VALUES ('ST001', 'W002', 'admin', 'Completed', %s, 'admin', %s)
        """,
        (
            datetime.combine(TODAY - timedelta(days=30), datetime.min.time()),
            datetime.combine(TODAY - timedelta(days=29), datetime.min.time()),
        ),
    )
    cur.execute(
        """
        SELECT InventoryID, ProductID, QuantityAvailable
        FROM inventory WHERE WarehouseID='W002' ORDER BY InventoryID
        """
    )
    rows = cur.fetchall()
    for row in rows:
        qty = int(row["QuantityAvailable"] or 0)
        cur.execute(
            """
            INSERT INTO stocktake_items
                (SessionID, ProductID, SystemQuantity, ActualQuantity, Difference)
            VALUES ('ST001', %s, %s, %s, 0)
            """,
            (row["ProductID"], qty, qty),
        )
    print(f"  + Stocktake ST001 (Completed, {len(rows)} sản phẩm)")


def seed_opening_balances(cur):
    """Ghi ledger tồn đầu kỳ cho dòng tồn kho chưa có giao dịch nào.

    Idempotent: chỉ thêm khi InventoryID chưa xuất hiện trong inventory_transactions,
    nên chạy lại seed không sinh giao dịch trùng.
    """
    cur.execute(
        """
        SELECT i.InventoryID, i.ProductID, i.WarehouseID, i.QuantityAvailable
        FROM inventory i
        WHERE i.QuantityAvailable > 0
          AND NOT EXISTS (
              SELECT 1 FROM inventory_transactions t WHERE t.InventoryID=i.InventoryID
          )
        ORDER BY i.InventoryID
        """
    )
    rows = cur.fetchall()
    for row in rows:
        qty = int(row["QuantityAvailable"])
        txn_id = next_entity(cur, "TXN", "TXN")
        cur.execute(
            """
            INSERT INTO inventory_transactions
                (TransactionID, InventoryID, ProductID, WarehouseID, TransactionType,
                 QuantityChange, QuantityBefore, QuantityAfter, ReferenceType,
                 ReferenceID, Notes, PerformedBy)
            VALUES (%s, %s, %s, %s, 'OpeningBalance', %s, 0, %s, 'OpeningBalance',
                    NULL, 'Tồn đầu kỳ khi nâng cấp B2B', 'system')
            """,
            (txn_id, row["InventoryID"], row["ProductID"], row["WarehouseID"], qty, qty),
        )
    if rows:
        print(f"  + {len(rows)} giao dịch tồn đầu kỳ (ledger)")


def sync_sequences(cur):
    cur.execute("SELECT CPRID FROM customer_purchase_requests")
    bump_sequence(cur, "CPR", [r["CPRID"] for r in cur.fetchall()])
    cur.execute("SELECT PRID FROM purchase_requisitions")
    bump_sequence(cur, "PR", [r["PRID"] for r in cur.fetchall()])
    cur.execute("SELECT POID FROM purchase_orders")
    bump_sequence(cur, "PO", [r["POID"] for r in cur.fetchall()])
    cur.execute("SELECT GRNID FROM goods_receipt_notes")
    bump_sequence(cur, "GRN", [r["GRNID"] for r in cur.fetchall()])
    cur.execute("SELECT ReturnID FROM return_orders")
    bump_sequence(cur, "RTN", [r["ReturnID"] for r in cur.fetchall()])
    cur.execute("SELECT SessionID FROM stocktake_sessions")
    bump_sequence(cur, "ST", [r["SessionID"] for r in cur.fetchall()])
    cur.execute("SELECT TransactionID FROM inventory_transactions")
    bump_sequence(cur, "TXN", [r["TransactionID"] for r in cur.fetchall()])
    cur.execute("SELECT AdjustmentID FROM inventory_adjustments")
    bump_sequence(cur, "ADJ", [r["AdjustmentID"] for r in cur.fetchall()])
    cur.execute("SELECT InventoryID FROM inventory WHERE InventoryID LIKE 'INV%'")
    bump_sequence(cur, "INV", [r["InventoryID"] for r in cur.fetchall()])


def main():
    conn = None
    cur = None
    try:
        conn = get_connection()
        conn.start_transaction()
        cur = conn.cursor(dictionary=True)

        print("Seeding B2B demo data...")
        seed_organization(cur)
        seed_users(cur)

        cur.execute("SELECT UserID FROM `user` WHERE Username='an.nguyen'")
        manager = cur.fetchone()
        manager_id = manager["UserID"] if manager else None

        seed_cprs(cur, manager_id)
        seed_procurement(cur)
        seed_returns(cur)
        seed_stocktake(cur)
        seed_opening_balances(cur)
        sync_sequences(cur)

        conn.commit()
        print("\nHoàn tất seed demo.")
        print("Tài khoản demo:")
        print(f"  - an.nguyen / {DEMO_PASSWORD}  (Org_Manager, ORG001)")
        print(f"  - binh.tran / {DEMO_PASSWORD}  (Org_Staff, ORG001)")
        print("  - admin / admin123            (Admin)")
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"SEED FAILED: {exc}")
        sys.exit(1)
