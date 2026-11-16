"""End-to-end acceptance tests for the B2B/ERP upgrade.

Runs against the real database through the Flask test client, creates real
documents, verifies stock + ledger behaviour, then removes everything it
created and restores the original inventory quantities.
"""
import sys
from datetime import date, timedelta

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from dotenv import load_dotenv

load_dotenv()

from flask import Flask  # noqa: E402
from app import app, create_access_token  # noqa: E402
from db import get_connection  # noqa: E402

PASS = []
FAIL = []
CREATED = {
    "grn": [], "po": [], "pr": [], "cpr": [], "orders": [], "returns": [], "sessions": [],
}
STOCK_SNAPSHOT = {}
ADJ_SNAPSHOT = set()


def check(name, condition, detail=""):
    if condition:
        PASS.append(name)
        print(f"  PASS  {name}")
    else:
        FAIL.append(f"{name} :: {detail}")
        print(f"  FAIL  {name}  {detail}")


def token(username, role, org_id=None, customer_id=None):
    with app.app_context():
        return create_access_token(
            identity=username,
            additional_claims={
                "role": role,
                "organization_id": org_id,
                "customer_id": customer_id,
                "full_name": username,
            },
        )


def hdr(tok):
    return {"Authorization": f"Bearer {tok}"}


def login(username, password):
    with app.test_client() as c:
        r = c.post("/api/auth/login", json={"username": username, "password": password})
        return r


def stock(product_id, warehouse_id="W001", cur=None):
    own = cur is None
    if own:
        conn = get_connection()
        cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT QuantityAvailable FROM inventory WHERE ProductID=%s AND WarehouseID=%s",
        (product_id, warehouse_id),
    )
    row = cur.fetchone()
    if own:
        cur.close()
        conn.close()
    return int(row["QuantityAvailable"]) if row else 0


def snapshot_stock(pairs):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    for product_id, warehouse_id in pairs:
        STOCK_SNAPSHOT[(product_id, warehouse_id)] = stock(product_id, warehouse_id, cur)
    cur.execute("SELECT AdjustmentID FROM inventory_adjustments")
    for row in cur.fetchall():
        ADJ_SNAPSHOT.add(row["AdjustmentID"])
    cur.close()
    conn.close()


def main():
    client = app.test_client()

    admin = token("admin", "admin")
    manager = token("an.nguyen", "org_manager", "ORG001", "C001")
    staff = token("binh.tran", "org_staff", "ORG001", "C001")
    other_org = token("fake.manager", "org_manager", "ORG999", "C999")
    customer = token("C001", "customer", None, "C001")

    print("\n== 1. Login API trả về role + organization ==")
    r = login("an.nguyen", "org123456")
    body = r.get_json() or {}
    check("login org_manager 200", r.status_code == 200, r.status_code)
    check("login trả organization", (body.get("organization") or {}).get("OrganizationID") == "ORG001", body.get("organization"))
    check("login trả role", body.get("role") == "org_manager", body.get("role"))
    check("login trả customer_id", body.get("customer_id") == "C001", body.get("customer_id"))
    r = login("binh.tran", "org123456")
    check("login org_staff 200", r.status_code == 200, r.status_code)
    check("login sai mật khẩu 401", login("binh.tran", "wrong-password").status_code == 401)

    print("\n== 2. Authorization / cách ly tổ chức ==")
    check("admin GET /organizations 200", client.get("/api/organizations", headers=hdr(admin)).status_code == 200)
    check("org_staff GET /organizations 403", client.get("/api/organizations", headers=hdr(staff)).status_code == 403)
    check("org_staff GET /purchase-orders 403", client.get("/api/purchase-orders", headers=hdr(staff)).status_code == 403)
    r = client.get("/api/customer-purchase-requests", headers=hdr(customer))
    rows = r.get_json() or []
    check("customer chỉ thấy CPR của chính mình",
          r.status_code == 200 and all(row.get("CustomerID") == "C001" for row in rows), r.status_code)
    check("customer không thấy dữ liệu tổ chức khác",
          all(row.get("OrganizationID") == "ORG001" for row in rows), rows[:1])
    check("customer GET /dashboard/summary 403",
          client.get("/api/dashboard/summary", headers=hdr(customer)).status_code == 403)

    r = client.put("/api/organizations/ORG001", json={"OrganizationName": "Hack"}, headers=hdr(staff))
    check("org_staff sửa hồ sơ pháp lý 403", r.status_code == 403, r.status_code)
    r = client.put("/api/organizations/ORG001", json={"OrganizationName": "Hack"}, headers=hdr(manager))
    check("org_manager không sửa được tên pháp lý", r.status_code == 400, r.status_code)
    r = client.put("/api/organizations/ORG001", json={"Address": "Số 1 Lý Thường Kiệt"}, headers=hdr(manager))
    check("org_manager sửa được địa chỉ", r.status_code == 200, r.status_code)

    r = client.get("/api/customer-purchase-requests", headers=hdr(other_org))
    check("org khác không thấy CPR của ORG001", r.status_code == 200 and len(r.get_json()) == 0, r.get_json())
    r = client.get("/api/customer-purchase-requests/CPR001", headers=hdr(other_org))
    check("org khác truy cập CPR001 bị chặn", r.status_code == 404, r.status_code)

    print("\n== 3. CPR → SO (sales) ==")
    rf = client.get("/api/organizations/me", headers=hdr(staff))
    check("org_staff đọc hồ sơ tổ chức 200", rf.status_code == 200, rf.status_code)

    snapshot_stock([("P001", "W001"), ("P002", "W001"), ("P003", "W001")])
    before_p001 = stock("P001")

    r = client.post("/api/customer-purchase-requests",
                    json={"Items": [{"ProductID": "P001", "Quantity": 2}], "Note": "Smoke test"},
                    headers=hdr(staff))
    check("org_staff tạo CPR 201", r.status_code == 201, r.get_json())
    cpr = (r.get_json() or {}).get("CPRID")
    CREATED["cpr"].append(cpr)
    r = client.post("/api/customer-purchase-requests",
                    json={"Items": [{"ProductID": "P001", "Quantity": 1}]}, headers=hdr(admin))
    check("admin không tạo CPR thay khách 403", r.status_code == 403, r.status_code)

    r = client.post(f"/api/customer-purchase-requests/{cpr}/convert", headers=hdr(admin))
    check("chưa duyệt CPR thì không convert được", r.status_code == 409, r.status_code)
    r = client.patch(f"/api/customer-purchase-requests/{cpr}/status", json={"Status": "Approved"}, headers=hdr(admin))
    check("admin duyệt CPR 200", r.status_code == 200, r.get_json())
    r = client.post(f"/api/customer-purchase-requests/{cpr}/convert", headers=hdr(admin))
    order_ids = (r.get_json() or {}).get("OrderIDs") or []
    check("convert CPR → SO 201", r.status_code == 201 and order_ids, r.get_json())
    CREATED["orders"].extend(order_ids)
    r = client.post(f"/api/customer-purchase-requests/{cpr}/convert", headers=hdr(admin))
    check("convert lặp không tạo SO trùng", r.status_code == 409, r.status_code)

    so = order_ids[0] if order_ids else None
    r = client.patch(f"/api/orders/{so}/status", json={"Status": "Accepted"}, headers=hdr(admin))
    check("duyệt SO 200", r.status_code == 200, r.get_json())
    check("duyệt SO trừ kho đúng 2", stock("P001") == before_p001 - 2, f"{stock('P001')} vs {before_p001 - 2}")

    r = client.post("/api/orders", json={"CustomerID": "C001", "ProductID": "P001",
                                         "Quantity": 999999, "Bill": 0,
                                         "OrderDate": date.today().isoformat()}, headers=hdr(admin))
    big_order = (r.get_json() or {}).get("OrderID")
    if big_order:
        CREATED["orders"].append(big_order)
    r = client.patch(f"/api/orders/{big_order}/status", json={"Status": "Accepted"}, headers=hdr(admin))
    check("không bán vượt tồn khả dụng", r.status_code in (400, 409), r.status_code)
    check("tồn kho không đổi sau khi bán vượt", stock("P001") == before_p001 - 2, stock("P001"))

    r = client.get("/api/inventory/transactions?transaction_type=SalesIssue&limit=5", headers=hdr(admin))
    txs = r.get_json() or []
    check("bán hàng ghi ledger SalesIssue", any((t.get("ReferenceID") == so) for t in txs), txs[:2])

    print("\n== 4. PR → PO → GRN ==")
    r = client.post("/api/purchase-requisitions",
                    json={"Items": [{"ProductID": "P001", "Quantity": 5}],
                          "Reason": "Smoke test bổ sung", "WarehouseID": "W001"}, headers=hdr(admin))
    check("tạo PR 201", r.status_code == 201, r.get_json())
    pr = (r.get_json() or {}).get("PRID")
    CREATED["pr"].append(pr)
    r = client.patch(f"/api/purchase-requisitions/{pr}/status", json={"Status": "Approved"}, headers=hdr(admin))
    check("duyệt PR 200", r.status_code == 200, r.get_json())

    stock_before_po = stock("P001")
    r = client.post("/api/purchase-orders",
                    json={"PRID": pr, "SupplierID": "S002", "WarehouseID": "W001",
                          "ExpectedDate": (date.today() + timedelta(days=7)).isoformat()},
                    headers=hdr(admin))
    check("duyệt PR tạo PO 201", r.status_code == 201, r.get_json())
    po = (r.get_json() or {}).get("POID")
    CREATED["po"].append(po)
    check("tạo PO không cộng kho", stock("P001") == stock_before_po, stock("P001"))

    r = client.get("/api/purchase-orders", headers=hdr(admin))
    po_row = next((p for p in (r.get_json() or []) if p.get("POID") == po), {})
    check("PO mới ở trạng thái Ordered", po_row.get("Status") == "Ordered", po_row.get("Status"))

    r = client.post(f"/api/purchase-orders/{po}/receipts",
                    json={"WarehouseID": "W001", "Items": [{"ProductID": "P001", "QuantityReceived": 2}]},
                    headers=hdr(admin))
    grn = (r.get_json() or {}).get("GRNID")
    CREATED["grn"].append(grn)
    check("GRN nhận một phần 201", r.status_code == 201, r.get_json())
    check("nhận một phần cộng kho 2", stock("P001") == stock_before_po + 2, stock("P001"))

    r = client.post(f"/api/purchase-orders/{po}/receipts",
                    json={"WarehouseID": "W001", "Items": [{"ProductID": "P001", "QuantityReceived": 3}]},
                    headers=hdr(admin))
    CREATED["grn"].append((r.get_json() or {}).get("GRNID"))
    check("nhận phần còn lại 201", r.status_code == 201, r.get_json())
    check("nhận đủ cộng kho tổng 5", stock("P001") == stock_before_po + 5, stock("P001"))

    r = client.post(f"/api/purchase-orders/{po}/receipts", json={"WarehouseID": "W001"}, headers=hdr(admin))
    check("nhận lại không cộng kho lần hai", r.status_code == 409 and stock("P001") == stock_before_po + 5,
          f"{r.status_code} / {stock('P001')}")

    r = client.post(f"/api/purchase-orders/{po}/receipts",
                    json={"WarehouseID": "W001", "Items": [{"ProductID": "P001", "QuantityReceived": 1}]},
                    headers=hdr(admin))
    check("không nhận vượt số lượng đặt", r.status_code in (400, 409), r.status_code)

    r = client.get("/api/inventory/transactions?transaction_type=GoodsReceipt&limit=10", headers=hdr(admin))
    check("GRN ghi ledger GoodsReceipt", any(t.get("ReferenceID") in CREATED["grn"] for t in (r.get_json() or [])),
          (r.get_json() or [])[:2])

    print("\n== 5. Return ==")
    stock_before_return = stock("P001")
    r = client.post("/api/orders", json={"CustomerID": "C001", "ProductID": "P001",
                                         "Quantity": 2, "Bill": 0,
                                         "OrderDate": date.today().isoformat()}, headers=hdr(admin))
    ro = (r.get_json() or {}).get("OrderID")
    CREATED["orders"].append(ro)
    client.patch(f"/api/orders/{ro}/status", json={"Status": "Accepted"}, headers=hdr(admin))
    stock_after_sale = stock("P001")

    r = client.post("/api/returns", json={"OriginalOrderID": ro, "Quantity": 3, "Reason": "Smoke test"},
                    headers=hdr(customer))
    check("trả vượt số lượng đã mua bị chặn", r.status_code in (400, 409), r.status_code)

    r = client.post("/api/returns", json={"OriginalOrderID": ro, "Quantity": 2, "Reason": "Smoke test"},
                    headers=hdr(customer))
    ret = (r.get_json() or {}).get("ReturnID")
    CREATED["returns"].append(ret)
    check("tạo Return Request 201", r.status_code == 201, r.get_json())
    r = client.patch(f"/api/returns/{ret}/status", json={"Status": "Approved"}, headers=hdr(admin))
    check("duyệt trả hàng 200", r.status_code == 200, r.get_json())
    check("duyệt trả hàng chưa cộng kho", stock("P001") == stock_after_sale, stock("P001"))
    r = client.post(f"/api/returns/{ret}/receive", json={"WarehouseID": "W001"}, headers=hdr(admin))
    check("nhận hàng trả cộng kho đúng 2", r.status_code == 200 and stock("P001") == stock_after_sale + 2,
          f"{r.status_code} / {stock('P001')}")
    r = client.post(f"/api/returns/{ret}/receive", json={"WarehouseID": "W001"}, headers=hdr(admin))
    check("nhận hàng trả lần hai idempotent (không cộng kho)",
          r.status_code == 200 and stock("P001") == stock_after_sale + 2, f"{r.status_code} / {stock('P001')}")
    check("tồn cuối khớp sau bán và trả hàng", stock("P001") == stock_before_return, stock("P001"))

    print("\n== 6. Stocktake ==")
    r = client.post("/api/stocktake-sessions", json={"WarehouseID": "W001"}, headers=hdr(admin))
    session = (r.get_json() or {}).get("SessionID")
    CREATED["sessions"].append(session)
    check("tạo phiên kiểm kê 201", r.status_code == 201, r.get_json())
    if session:
        r = client.get(f"/api/stocktake-sessions/{session}", headers=hdr(admin))
        items = (r.get_json() or {}).get("Items") or []
        if items:
            first = items[0]
            actual = int(first["SystemQuantity"]) + 0
            r = client.patch(f"/api/stocktake-sessions/{session}/items",
                             json={"Items": [{"ProductID": first["ProductID"], "ActualQuantity": actual}]},
                             headers=hdr(admin))
            check("lưu số thực tế kiểm kê 200", r.status_code == 200, r.get_json())
            r = client.patch(f"/api/stocktake-sessions/{session}/complete", headers=hdr(admin))
            check("hoàn tất kiểm kê 200", r.status_code == 200, r.get_json())

    print("\n== 7. Dashboard ==")
    r = client.get("/api/dashboard/summary", headers=hdr(admin))
    d = r.get_json() or {}
    check("dashboard summary 200", r.status_code == 200, r.status_code)
    check("dashboard có tổng quan theo danh mục", "inventoryByCategory" in d, list(d.keys()))
    check("dashboard có nhập/xuất theo thời gian", "goodsFlow" in d, list(d.keys()))
    check("dashboard có top supplier", "topSuppliers" in d, list(d.keys()))
    r = client.get("/api/dashboard/org", headers=hdr(manager))
    od = r.get_json() or {}
    check("dashboard tổ chức 200", r.status_code == 200, r.status_code)
    check("dashboard tổ chức có KPI", "totals" in od, list(od.keys()))

    cleanup()


def cleanup():
    print("\n== Cleanup dữ liệu kiểm thử ==")
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    for grn in [g for g in CREATED["grn"] if g]:
        cur.execute("DELETE FROM goods_receipt_items WHERE GRNID=%s", (grn,))
        cur.execute("DELETE FROM goods_receipt_notes WHERE GRNID=%s", (grn,))
    for po in CREATED["po"]:
        cur.execute("DELETE FROM purchase_order_items WHERE POID=%s", (po,))
        cur.execute("DELETE FROM purchase_orders WHERE POID=%s", (po,))
    for pr in CREATED["pr"]:
        cur.execute("DELETE FROM purchase_requisition_items WHERE PRID=%s", (pr,))
        cur.execute("DELETE FROM purchase_requisitions WHERE PRID=%s", (pr,))
    for cpr in CREATED["cpr"]:
        cur.execute("DELETE FROM customer_purchase_request_items WHERE CPRID=%s", (cpr,))
        cur.execute("DELETE FROM customer_purchase_requests WHERE CPRID=%s", (cpr,))
    for oid in CREATED["orders"]:
        if not oid:
            continue
        cur.execute("DELETE FROM inventory_transactions WHERE ReferenceID=%s", (oid,))
        cur.execute("DELETE FROM orders WHERE OrderID=%s", (oid,))
    for rid in [x for x in CREATED["returns"] if x]:
        cur.execute("DELETE FROM inventory_transactions WHERE ReferenceID=%s", (rid,))
        cur.execute("DELETE FROM return_orders WHERE ReturnID=%s", (rid,))
    for sid in [x for x in CREATED["sessions"] if x]:
        cur.execute("DELETE FROM stocktake_items WHERE SessionID=%s", (sid,))
        cur.execute("DELETE FROM inventory_transactions WHERE ReferenceID=%s", (sid,))
        cur.execute("DELETE FROM stocktake_sessions WHERE SessionID=%s", (sid,))
    for grn in [g for g in CREATED["grn"] if g]:
        cur.execute("DELETE FROM inventory_transactions WHERE ReferenceID=%s", (grn,))
    cur.execute("SELECT AdjustmentID FROM inventory_adjustments")
    for row in cur.fetchall():
        if row["AdjustmentID"] not in ADJ_SNAPSHOT:
            cur.execute("DELETE FROM inventory_adjustments WHERE AdjustmentID=%s", (row["AdjustmentID"],))
    conn.commit()

    # Restore the exact inventory quantities captured before the test run
    for (product_id, warehouse_id), qty in STOCK_SNAPSHOT.items():
        cur.execute(
            "UPDATE inventory SET QuantityAvailable=%s WHERE ProductID=%s AND WarehouseID=%s",
            (qty, product_id, warehouse_id),
        )
    conn.commit()
    cur.close()
    conn.close()
    print("  Đã xoá chứng từ kiểm thử và khôi phục tồn kho.")

    total = len(PASS) + len(FAIL)
    print(f"\n===== KẾT QUẢ: {len(PASS)}/{total} PASS, {len(FAIL)} FAIL =====")
    for f in FAIL:
        print("  FAILED:", f)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        cleanup()
        raise
