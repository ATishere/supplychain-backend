# SupplyChain7VN — Backend

API Flask cho hệ thống quản lý chuỗi cung ứng.

## Yêu cầu

- Python 3.10+
- MySQL 8

## Cài đặt

```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

**Bắt buộc:** copy file cấu hình mẫu thành `.env` trước khi chạy:

```bash
copy .env.example .env
```

Mở `.env` và điền đầy đủ:

- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `JWT_SECRET_KEY` (tối thiểu 32 ký tự)
- `CORS_ORIGINS` (mặc định chỉ localhost)

## Khởi tạo database

```bash
mysql -u root -p < schema.sql
```

## Chạy server

```bash
python app.py
```

API chạy tại `http://127.0.0.1:5000/api`.
