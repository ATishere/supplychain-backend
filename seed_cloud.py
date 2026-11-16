"""Seed dữ liệu demo B2B trực tiếp lên MySQL Cloud (Aiven) — không cần sửa .env.

Vì sao có script này?
    backend/seed_b2b_demo.py đọc kết nối từ .env của máy (localhost, port 3307).
    Trên Aiven, host/port/user/password/database khác hoàn toàn, nên script này
    nhận thông tin kết nối từ CLI hoặc biến môi trường và dùng CHÍNH logic seed
    của seed_b2b_demo.py (một nguồn sự thật duy nhất, không copy code).

Cách dùng (PowerShell / Git Bash / CMD):

    # 1) Truyền qua biến môi trường
    export DB_HOST=mysql-xxxxx.aivencloud.com
    export DB_PORT=12345
    export DB_USER=avnadmin
    export DB_NAME=defaultdb
    export DB_PASSWORD=...            # hoặc để trống, script sẽ hỏi
    python backend/seed_cloud.py

    # 2) Truyền qua tham số dòng lệnh
    python backend/seed_cloud.py \
        --host mysql-xxxxx.aivencloud.com --port 12345 \
        --user avnadmin --database defaultdb --ssl-ca ca.pem

    # 3) Xem trước rồi rollback (không ghi gì)
    python backend/seed_cloud.py --dry-run

An toàn:
    - Idempotent: chạy lại nhiều lần không nhân đôi chứng từ, không reset
      mật khẩu người dùng đã tồn tại (logic nằm trong seed_b2b_demo.py).
    - Toàn bộ seed chạy trong MỘT transaction: lỗi giữa chừng => rollback.
    - Không bao giờ ghi đè user/đơn hàng đã có.
"""

import argparse
import getpass
import os
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import mysql.connector
from dotenv import load_dotenv

# Nạp .env local chỉ để lấy giá trị mặc định; biến môi trường/CLI luôn thắng.
load_dotenv(dotenv_path=BASE_DIR / ".env", override=False)

# Dùng lại toàn bộ logic seed đã được kiểm chứng (không duplicate code).
import seed_b2b_demo as demo  # noqa: E402

# Bảng tối thiểu phải tồn tại trước khi seed (tức là đã chạy schema + migration).
REQUIRED_TABLES = (
    "organizations",
    "customer",
    "user",
    "product",
    "inventory",
    "inventory_adjustments",
    "inventory_transactions",
    "orders",
    "customer_purchase_requests",
    "customer_purchase_request_items",
    "purchase_requisitions",
    "purchase_requisition_items",
    "purchase_orders",
    "purchase_order_items",
    "goods_receipt_notes",
    "goods_receipt_items",
    "return_orders",
    "stocktake_sessions",
    "stocktake_items",
    "entity_id_sequence",
    "order_id_sequence",
)

REPORT_TABLES = (
    "organizations",
    "user",
    "customer_purchase_requests",
    "orders",
    "purchase_requisitions",
    "purchase_orders",
    "goods_receipt_notes",
    "return_orders",
    "stocktake_sessions",
    "inventory_transactions",
)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Seed dữ liệu demo B2B lên MySQL Cloud (Aiven)."
    )
    parser.add_argument("--host", default=os.environ.get("DB_HOST"),
                        help="DB host (mặc định: $DB_HOST)")
    parser.add_argument("--port", default=os.environ.get("DB_PORT"),
                        help="DB port (mặc định: $DB_PORT)")
    parser.add_argument("--user", default=os.environ.get("DB_USER"),
                        help="DB user (mặc định: $DB_USER)")
    parser.add_argument("--password", default=os.environ.get("DB_PASSWORD"),
                        help="DB password (mặc định: $DB_PASSWORD; không truyền sẽ hỏi)")
    parser.add_argument("--database", default=os.environ.get("DB_NAME"),
                        help="DB name (mặc định: $DB_NAME)")
    parser.add_argument("--ssl-ca", dest="ssl_ca", default=os.environ.get("DB_SSL_CA"),
                        help="Đường dẫn CA cert của Aiven (bật verify TLS)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Chạy toàn bộ seed rồi ROLLBACK, không ghi dữ liệu")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Không hỏi xác nhận trước khi ghi lên DB cloud")
    args = parser.parse_args(argv)

    missing = [name for name, value in (
        ("host", args.host), ("port", args.port),
        ("user", args.user), ("database", args.database),
    ) if not value]
    if missing:
        parser.error(
            "Thiếu thông tin kết nối: " + ", ".join(missing)
            + ". Truyền --host/--port/--user/--database hoặc set DB_HOST/DB_PORT/DB_USER/DB_NAME."
        )

    # Chỉ hỏi khi KHÔNG có nguồn nào cung cấp password (None).
    # Chuỗi rỗng ("") vẫn được coi là password hợp lệ (DB local không mật khẩu).
    if args.password is None:
        args.password = getpass.getpass("DB password: ")

    try:
        args.port = int(args.port)
    except ValueError:
        parser.error("--port phải là số nguyên (Aiven thường dùng port 5 chữ số).")

    return args


def connect(args):
    """Kết nối TLS tới cloud DB. Không đọc/ghi .env local."""
    cfg = {
        "host": args.host,
        "port": args.port,
        "user": args.user,
        "password": args.password,
        "database": args.database,
        "connection_timeout": 30,
        "charset": "utf8mb4",
        "ssl_disabled": False,  # Aiven bắt buộc TLS
    }
    if args.ssl_ca:
        cfg["ssl_ca"] = args.ssl_ca
        cfg["ssl_verify_cert"] = True

    print(f"Kết nối {args.user}@{args.host}:{args.port}/{args.database} ...")
    conn = mysql.connector.connect(**cfg)
    print("  OK — đã kết nối.")
    return conn


def preflight(cur):
    """Chặn seed khi migration chưa chạy (tránh lỗi khó hiểu giữa chừng)."""
    cur.execute(
        """
        SELECT TABLE_NAME
          FROM information_schema.TABLES
         WHERE TABLE_SCHEMA = DATABASE()
        """
    )
    existing = {row["TABLE_NAME"] for row in cur.fetchall()}
    missing = [t for t in REQUIRED_TABLES if t not in existing]
    if missing:
        raise SystemExit(
            "Thiếu bảng: " + ", ".join(missing) + "\n"
            "=> Chạy backend/schema.sql rồi backend/migration_b2b_v1.sql trước khi seed."
        )

    cur.execute("SELECT DATABASE() AS db, VERSION() AS version")
    info = cur.fetchone()
    print(f"  Database: {info['db']} | Server: {info['version']}")

    cur.execute("SELECT COUNT(*) AS n FROM `user` WHERE Role = 'admin'")
    if not cur.fetchone()["n"]:
        print("  CẢNH BÁO: chưa có user role 'admin' — seed vẫn chạy nhưng không có tài khoản quản trị.")


def report_counts(cur):
    print("\nSố dòng hiện tại:")
    for table in REPORT_TABLES:
        cur.execute(f"SELECT COUNT(*) AS n FROM `{table}`")
        print(f"  - {table:<32} {cur.fetchone()['n']}")


def seed(cur):
    """Đúng thứ tự phụ thuộc của seed_b2b_demo.main()."""
    print("\nSeeding B2B demo data...")
    demo.seed_organization(cur)
    demo.seed_users(cur)

    cur.execute("SELECT UserID FROM `user` WHERE Username='an.nguyen'")
    manager = cur.fetchone()
    manager_id = manager["UserID"] if manager else None

    demo.seed_cprs(cur, manager_id)
    demo.seed_procurement(cur)
    demo.seed_returns(cur)
    demo.seed_stocktake(cur)
    demo.seed_opening_balances(cur)
    demo.sync_sequences(cur)


def main(argv=None):
    args = parse_args(argv)

    conn = None
    cur = None
    try:
        conn = connect(args)
        cur = conn.cursor(dictionary=True)

        preflight(cur)

        if not args.dry_run and not args.yes:
            answer = input(
                f"\nGhi dữ liệu demo vào DB CLOUD '{args.database}' @ {args.host}? [y/N] "
            ).strip().lower()
            if answer not in ("y", "yes"):
                print("Đã hủy.")
                return 0

        # Các SELECT của preflight mở một transaction ngầm (autocommit=0).
        # Đóng nó trước, nếu không start_transaction() báo
        # "Transaction already in progress".
        if getattr(conn, "in_transaction", False):
            conn.commit()

        # Một transaction cho toàn bộ seed: lỗi giữa chừng => rollback sạch.
        conn.start_transaction()
        try:
            seed(cur)
            report_counts(cur)
            if args.dry_run:
                conn.rollback()
                print("\n[DRY-RUN] Đã ROLLBACK — không có thay đổi nào được ghi.")
            else:
                conn.commit()
                print("\nĐã COMMIT. Hoàn tất seed demo.")
        except Exception:
            conn.rollback()
            print("\nSeed lỗi => đã ROLLBACK, DB giữ nguyên trạng thái trước đó.")
            raise

        print("\nTài khoản demo:")
        print(f"  - an.nguyen / {demo.DEMO_PASSWORD}  (org_manager, ORG001)")
        print(f"  - binh.tran / {demo.DEMO_PASSWORD}  (org_staff, ORG001)")
        print("  - admin / admin123                (admin)")
        return 0

    except mysql.connector.Error as exc:
        print(f"\nLỖI MySQL: {exc}", file=sys.stderr)
        if getattr(exc, "errno", None) == 3819:
            print(
                "Gợi ý: CHECK constraint trên bảng `user` vẫn là bản cũ "
                "(chỉ admin/customer).\n"
                "=> Chạy lại backend/migration_b2b_v1.sql để mở rộng role "
                "org_manager/org_staff.",
                file=sys.stderr,
            )
        elif getattr(exc, "errno", None) in (1045, 1044):
            print("Gợi ý: sai user/password hoặc user không có quyền trên database này.", file=sys.stderr)
        elif getattr(exc, "errno", None) in (2003, 2013):
            print("Gợi ý: sai host/port hoặc IP chưa được phép (Aiven > Allowed IP).", file=sys.stderr)
        return 1
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())
