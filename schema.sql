-- ============================================================
--  SupplyChain7VN - Supply Chain Management System
--  Database Schema (as per schema diagram)
-- ============================================================

CREATE DATABASE IF NOT EXISTS chainsync;
USE chainsync;

-- ─────────────────────────────────────────────────────────────
-- TABLE 1: supplier
-- ─────────────────────────────────────────────────────────────
CREATE TABLE supplier (
    SupplierID      VARCHAR(10)     PRIMARY KEY,
    SupplierName    VARCHAR(100)    NOT NULL,
    ContactNumber   VARCHAR(20),
    Location        VARCHAR(150),
    TaxCode         VARCHAR(20)     DEFAULT NULL,
    Email           VARCHAR(100)    DEFAULT NULL,
    UNIQUE (Email)
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 2: product
-- ─────────────────────────────────────────────────────────────
CREATE TABLE product (
    ProductID       VARCHAR(10)     PRIMARY KEY,
    ProductName     VARCHAR(100)    NOT NULL,
    Category        VARCHAR(50),
    UnitPrice       DECIMAL(15,2)   NOT NULL,
    SupplierID      VARCHAR(10),
    Unit            VARCHAR(20)     DEFAULT 'Cái',
    Origin          VARCHAR(50)     DEFAULT 'Việt Nam',
    CHECK (UnitPrice >= 0),
    FOREIGN KEY (SupplierID) REFERENCES supplier(SupplierID)
        ON DELETE SET NULL
        ON UPDATE CASCADE
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 3: warehouse
-- ─────────────────────────────────────────────────────────────
CREATE TABLE warehouse (
    WarehouseID     VARCHAR(10)     PRIMARY KEY,
    WarehouseName   VARCHAR(100)    NOT NULL,
    Location        VARCHAR(150),
    Capacity        INT             NOT NULL,
    ProvinceCode    VARCHAR(10)     DEFAULT NULL,
    CHECK (Capacity > 0)
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 4: inventory
-- ─────────────────────────────────────────────────────────────
CREATE TABLE inventory (
    InventoryID         VARCHAR(10)     PRIMARY KEY,
    QuantityAvailable   INT             DEFAULT 0,
    ProductID           VARCHAR(10)     NOT NULL,
    WarehouseID         VARCHAR(10)     NOT NULL,
    CHECK (QuantityAvailable >= 0),
    FOREIGN KEY (ProductID)   REFERENCES product(ProductID)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (WarehouseID) REFERENCES warehouse(WarehouseID)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 5: customer
-- ─────────────────────────────────────────────────────────────
CREATE TABLE customer (
    CustomerID      VARCHAR(10)     PRIMARY KEY,
    CustomerName    VARCHAR(100)    NOT NULL,
    ContactNumber   VARCHAR(20),
    Address         VARCHAR(200),
    TaxCode         VARCHAR(20)     DEFAULT NULL,
    CustomerType    VARCHAR(20)     DEFAULT 'Individual',
    CHECK (CustomerType IN ('Individual', 'Business'))
);
-- ─────────────────────────────────────────────────────────────
-- TABLE 6: orders
-- ─────────────────────────────────────────────────────────────

CREATE TABLE orders (
    OrderID         VARCHAR(10)     PRIMARY KEY,
    OrderDate       DATE            NOT NULL,
    Bill            DECIMAL(15,2)   NOT NULL,
    CustomerID      VARCHAR(10)     NOT NULL,
    Status          VARCHAR(20)     DEFAULT 'Pending',
    ProductID       VARCHAR(10),
    Quantity        INT             DEFAULT 1,
    InvoiceNumber   VARCHAR(30)     DEFAULT NULL,
    VatRate         DECIMAL(5,2)    DEFAULT 10.00,
    VatAmount       DECIMAL(15,2)   DEFAULT 0.00,
    PaymentMethod   VARCHAR(30)     DEFAULT 'Tiền mặt',
    CHECK (Bill >= 0),
    CHECK (Quantity > 0),
    CHECK (Status IN ('Pending', 'Accepted', 'Rejected')),
    CHECK (VatRate >= 0 AND VatRate <= 100),
    FOREIGN KEY (CustomerID) REFERENCES customer(CustomerID)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (ProductID) REFERENCES product(ProductID)
        ON DELETE SET NULL ON UPDATE CASCADE
);

-- ============================================================
--  SAMPLE DATA
-- ============================================================

INSERT INTO supplier (SupplierID, SupplierName, ContactNumber, Location, TaxCode, Email) VALUES
('S001', 'Công ty TNHH Nông nghiệp Xanh',        '0281234567', 'KCN Tân Bình, TP. Hồ Chí Minh',  '0101234567', 'nongnghiepxanh@supplychain7vn.vn'),
('S002', 'Công ty CP Thiết bị Công nghiệp Việt',  '0241234567', 'KCN Bắc Thăng Long, Hà Nội',     '0101234568', 'thietbicongnghiep@supplychain7vn.vn'),
('S003', 'Công ty TNHH Logistics Miền Nam',       '0287654321', 'Cảng Cát Lái, TP. Hồ Chí Minh',  '0101234569', 'logisticsmiennam@supplychain7vn.vn'),
('S004', 'Công ty CP Linh kiện Điện tử',          '0247654321', 'KCNC Hòa Lạc, Hà Nội',           '0101234570', 'linhkiendientu@supplychain7vn.vn'),
('S005', 'Công ty TNHH Bao bì Sinh thái',         '0283456789', 'KCN VSIP, Bình Dương',           '0101234571', 'baobisinhthai@supplychain7vn.vn');

INSERT INTO product (ProductID, ProductName, Category, UnitPrice, SupplierID, Unit, Origin) VALUES
('P001', 'Động cơ công nghiệp A4',  'Máy móc',     12500000.00, 'S002', 'Chiếc', 'Việt Nam'),
('P002', 'Phân bón hữu cơ X',       'Nguyên liệu',   850000.00, 'S001', 'Bao',   'Việt Nam'),
('P003', 'Thùng carton cỡ L',       'Bao bì',         15000.00, 'S005', 'Thùng', 'Việt Nam'),
('P004', 'Bo mạch điều khiển PCB',  'Linh kiện',    1500000.00, 'S004', 'Bộ',    'Nhật Bản'),
('P005', 'Thanh thép 12mm',         'Nguyên liệu',   250000.00, 'S002', 'Cây',   'Việt Nam'),
('P006', 'Cuộn bọc bong bóng',      'Bao bì',        120000.00, 'S003', 'Cuộn',  'Hàn Quốc');

INSERT INTO warehouse (WarehouseID, WarehouseName, Location, Capacity, ProvinceCode) VALUES
('W001', 'Kho trung tâm TP.HCM', 'Quận Bình Tân, TP. Hồ Chí Minh',  4000, 'HCM'),
('W002', 'Kho Hà Nội',           'Quận Long Biên, Hà Nội',          3000, 'HN'),
('W003', 'Kho cảng Hải Phòng',   'Quận Hải An, Hải Phòng',         12000, 'HP'),
('W004', 'Kho Đà Nẵng',          'Quận Liên Chiểu, Đà Nẵng',        1500, 'DN');

INSERT INTO inventory (InventoryID, QuantityAvailable, ProductID, WarehouseID) VALUES
('I001',  120, 'P001', 'W001'),
('I002', 1200, 'P002', 'W002'),
('I003', 8000, 'P003', 'W003'),
('I004',  350, 'P004', 'W001'),
('I005',  500, 'P005', 'W004'),
('I006',  800, 'P006', 'W003'),
('I007',   40, 'P001', 'W002'),  -- dưới ngưỡng 50: cảnh báo tồn kho thấp
('I008',  300, 'P002', 'W004'),
('I009', 1500, 'P003', 'W001'),
('I010',  150, 'P004', 'W002'),
('I011',  200, 'P005', 'W001'),
('I012',  250, 'P006', 'W002');

INSERT INTO customer (CustomerID, CustomerName, ContactNumber, Address, TaxCode, CustomerType) VALUES
('C001', 'Nguyễn Văn An',  '0912345678', '12 Lê Lợi, Quận 1, TP. Hồ Chí Minh', '0301234567', 'Business'),
('C002', 'Trần Thị Bình',  '0987654321', '45 Nguyễn Huệ, Hà Nội',              '0301234568', 'Business'),
('C003', 'Lê Hoàng Cường', '0905123456', '78 Trần Hưng Đạo, Đà Nẵng',          NULL,         'Individual'),
('C004', 'Phạm Thị Dung',  '0938123456', '23 Hai Bà Trưng, TP. Hồ Chí Minh',    '0301234569', 'Business'),
('C005', 'Hoàng Văn Em',   '0912345679', '56 Lý Thường Kiệt, Cần Thơ',         NULL,         'Individual');

-- Quy ước tính tiền (khớp backend/app.py và InvoiceModal):
--   Bill      = UnitPrice × Quantity       -> tạm tính TRƯỚC VAT
--   VatAmount = Bill × VatRate / 100       -> thuế GTGT
--   Tổng thanh toán hóa đơn = Bill + VatAmount
-- Phân bón (P002) áp dụng VAT 0% theo quy định miễn thuế GTGT của Việt Nam.
-- InvoiceNumber chỉ cấp cho đơn Accepted; Pending/Rejected để NULL.
INSERT INTO orders (OrderID, OrderDate, Bill, CustomerID, ProductID, Quantity, Status, InvoiceNumber, VatRate, VatAmount, PaymentMethod) VALUES
('ORD001', '2026-01-15',  25000000.00, 'C001', 'P001',   2, 'Accepted', 'HD-ORD001', 10.00,  2500000.00, 'Chuyển khoản'),
('ORD002', '2026-02-10',  85000000.00, 'C002', 'P002', 100, 'Accepted', 'HD-ORD002',  0.00,        0.00, 'Chuyển khoản'),
('ORD003', '2026-03-18',  15000000.00, 'C003', 'P004',  10, 'Pending',  NULL,       10.00,  1500000.00, 'Chuyển khoản'),
('ORD004', '2026-04-07',   1500000.00, 'C004', 'P003', 100, 'Rejected', NULL,       10.00,   150000.00, 'Tiền mặt'),
('ORD005', '2026-05-22',  12500000.00, 'C005', 'P005',  50, 'Accepted', 'HD-ORD005', 10.00,  1250000.00, 'Ví điện tử'),
('ORD006', '2026-06-30',   3600000.00, 'C001', 'P006',  30, 'Pending',  NULL,       10.00,   360000.00, 'Chuyển khoản'),
('ORD007', '2026-07-14',   7500000.00, 'C002', 'P003', 500, 'Accepted', 'HD-ORD007', 10.00,   750000.00, 'Chuyển khoản'),
('ORD008', '2026-08-05',  50000000.00, 'C003', 'P005', 200, 'Accepted', 'HD-ORD008', 10.00,  5000000.00, 'Chuyển khoản'),
('ORD009', '2026-09-09',  37500000.00, 'C004', 'P004',  25, 'Accepted', 'HD-ORD009', 10.00,  3750000.00, 'Chuyển khoản'),
('ORD010', '2026-10-21', 255000000.00, 'C005', 'P002', 300, 'Accepted', 'HD-ORD010',  0.00,        0.00, 'Chuyển khoản'),
('ORD011', '2026-11-02',   7200000.00, 'C001', 'P006',  60, 'Pending',  NULL,       10.00,   720000.00, 'Ví điện tử'),
('ORD012', '2026-11-06',  12500000.00, 'C002', 'P001',   1, 'Rejected', NULL,       10.00,  1250000.00, 'Chuyển khoản');

-- ─────────────────────────────────────────────────────────────
-- TABLE 7: user (JWT authentication)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE user (
    UserID          INT             PRIMARY KEY AUTO_INCREMENT,
    Username        VARCHAR(50)     NOT NULL UNIQUE,
    PasswordHash    VARCHAR(100)    NOT NULL,
    Role            VARCHAR(20)     NOT NULL DEFAULT 'customer',
    CustomerID      VARCHAR(10)     DEFAULT NULL,
    CHECK (Role IN ('admin', 'customer')),
    FOREIGN KEY (CustomerID) REFERENCES customer(CustomerID)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- Seed: admin (admin/admin123) + 5 khách hàng (C001..C005 / customer123)
INSERT INTO user (Username, PasswordHash, Role, CustomerID) VALUES
('admin', '$2b$12$kD8YkhGR9KW7e3.UQ/QSL.XLGKn9Xz2fJafb223mAabirgV13s8n.', 'admin', NULL),
('C001',  '$2b$12$z7waJAK0QAundU1xdXEVBeF/GujKv8aW6v1nHVYz71CC6nd/xTTOe', 'customer', 'C001'),
('C002',  '$2b$12$z7waJAK0QAundU1xdXEVBeF/GujKv8aW6v1nHVYz71CC6nd/xTTOe', 'customer', 'C002'),
('C003',  '$2b$12$z7waJAK0QAundU1xdXEVBeF/GujKv8aW6v1nHVYz71CC6nd/xTTOe', 'customer', 'C003'),
('C004',  '$2b$12$z7waJAK0QAundU1xdXEVBeF/GujKv8aW6v1nHVYz71CC6nd/xTTOe', 'customer', 'C004'),
('C005',  '$2b$12$z7waJAK0QAundU1xdXEVBeF/GujKv8aW6v1nHVYz71CC6nd/xTTOe', 'customer', 'C005');

-- ─────────────────────────────────────────────────────────────
-- TABLE 8: token_blacklist (JWT Revocation / Blacklist)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS token_blacklist (
    jti         VARCHAR(64)     PRIMARY KEY,
    RevokedAt   TIMESTAMP       DEFAULT CURRENT_TIMESTAMP
);
