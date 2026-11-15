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
    Rating          INT             NOT NULL DEFAULT 5,
    OnTimeRate      DECIMAL(5,2)    NOT NULL DEFAULT 100.00,
    CHECK (Rating BETWEEN 1 AND 5),
    CHECK (OnTimeRate >= 0 AND OnTimeRate <= 100),
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

CREATE TABLE inventory_adjustments (
    AdjustmentID    VARCHAR(10)     PRIMARY KEY,
    InventoryID     VARCHAR(10)     NOT NULL,
    OldQuantity     INT             NOT NULL,
    NewQuantity     INT             NOT NULL,
    Reason          VARCHAR(255)    NOT NULL,
    CreatedAt       TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    CHECK (OldQuantity >= 0),
    CHECK (NewQuantity >= 0),
    FOREIGN KEY (InventoryID) REFERENCES inventory(InventoryID)
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
    CHECK (Status IN ('Pending', 'Accepted', 'Rejected', 'Cancelled')),
    CHECK (VatRate >= 0 AND VatRate <= 100),
    FOREIGN KEY (CustomerID) REFERENCES customer(CustomerID)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (ProductID) REFERENCES product(ProductID)
        ON DELETE SET NULL ON UPDATE CASCADE
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 6b: order_id_sequence (sinh OrderID tuần tự, chống race)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE order_id_sequence (
    id          TINYINT UNSIGNED  NOT NULL PRIMARY KEY,
    next_value  INT UNSIGNED      NOT NULL
) ENGINE=InnoDB;

-- ============================================================
--  SAMPLE DATA
-- ============================================================

INSERT INTO supplier (SupplierID, SupplierName, ContactNumber, Location, TaxCode, Email, Rating, OnTimeRate) VALUES
('S001', 'Công ty TNHH Nông nghiệp Xanh',        '0281234567', 'KCN Tân Bình, TP. Hồ Chí Minh',  '0101234567', 'nongnghiepxanh@supplychain7vn.vn', 4, 98.50),
('S002', 'Công ty CP Thiết bị Công nghiệp Việt',  '0241234567', 'KCN Bắc Thăng Long, Hà Nội',     '0101234568', 'thietbicongnghiep@supplychain7vn.vn', 5, 96.00),
('S003', 'Công ty TNHH Logistics Miền Nam',       '0287654321', 'Cảng Cát Lái, TP. Hồ Chí Minh',  '0101234569', 'logisticsmiennam@supplychain7vn.vn', 3, 88.00),
('S004', 'Công ty CP Linh kiện Điện tử',          '0247654321', 'KCNC Hòa Lạc, Hà Nội',           '0101234570', 'linhkiendientu@supplychain7vn.vn', 4, 92.50),
('S005', 'Công ty TNHH Bao bì Sinh thái',         '0283456789', 'KCN VSIP, Bình Dương',           '0101234571', 'baobisinhthai@supplychain7vn.vn', 5, 99.00);

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

-- Seed sequence: MAX(ORDxxx hiện có) + 1 (idempotent cho DB đã migrate)
INSERT INTO order_id_sequence (id, next_value)
SELECT 1, COALESCE(MAX(CAST(SUBSTRING(OrderID, 4) AS UNSIGNED)), 0) + 1
FROM orders
WHERE OrderID REGEXP '^ORD[0-9]+$'
ON DUPLICATE KEY UPDATE next_value = GREATEST(next_value, VALUES(next_value));

-- ─────────────────────────────────────────────────────────────
-- TABLE 7: purchase_requisitions (yêu cầu mua hàng)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE purchase_requisitions (
    PRID            VARCHAR(10)     PRIMARY KEY,
    ProductID       VARCHAR(10)     NOT NULL,
    Quantity        INT             NOT NULL,
    RequestedBy     VARCHAR(50)     NOT NULL,
    Status          VARCHAR(20)     NOT NULL DEFAULT 'Pending_Approval',
    CreatedAt       TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    CHECK (Quantity > 0),
    CHECK (Status IN ('Draft', 'Pending_Approval', 'Approved', 'Rejected')),
    FOREIGN KEY (ProductID) REFERENCES product(ProductID)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 8: purchase_orders (đơn mua hàng)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE purchase_orders (
    POID            VARCHAR(10)     PRIMARY KEY,
    PRID            VARCHAR(10)     DEFAULT NULL,
    SupplierID      VARCHAR(10)     NOT NULL,
    ProductID       VARCHAR(10)     NOT NULL,
    Quantity        INT             NOT NULL,
    UnitPrice       DECIMAL(15,2)   NOT NULL,
    TotalAmount     DECIMAL(15,2)   NOT NULL,
    Status          VARCHAR(20)     NOT NULL DEFAULT 'Ordered',
    OrderDate       DATE            NOT NULL,
    CreatedAt       TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    CHECK (Quantity > 0),
    CHECK (UnitPrice >= 0),
    CHECK (TotalAmount >= 0),
    CHECK (Status IN ('Ordered', 'Received', 'Cancelled')),
    FOREIGN KEY (PRID)       REFERENCES purchase_requisitions(PRID)
        ON DELETE SET NULL ON UPDATE CASCADE,
    FOREIGN KEY (SupplierID) REFERENCES supplier(SupplierID)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    FOREIGN KEY (ProductID)  REFERENCES product(ProductID)
        ON DELETE RESTRICT ON UPDATE CASCADE
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 9: return_orders (đơn trả hàng)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE return_orders (
    ReturnID        VARCHAR(10)     PRIMARY KEY,
    OriginalOrderID VARCHAR(10)     NOT NULL,
    ProductID       VARCHAR(10)     NOT NULL,
    Quantity        INT             NOT NULL,
    Reason          VARCHAR(255)    NOT NULL,
    Status          VARCHAR(20)     NOT NULL DEFAULT 'Pending',
    RefundAmount    DECIMAL(15,2)   NOT NULL DEFAULT 0.00,
    CreatedAt       TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    CHECK (Quantity > 0),
    CHECK (RefundAmount >= 0),
    CHECK (Status IN ('Pending', 'Approved', 'Rejected')),
    FOREIGN KEY (OriginalOrderID) REFERENCES orders(OrderID)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (ProductID)       REFERENCES product(ProductID)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 10: stocktake_sessions (phiên kiểm kê)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE stocktake_sessions (
    SessionID       VARCHAR(10)     PRIMARY KEY,
    WarehouseID     VARCHAR(10)     NOT NULL,
    CreatedBy       VARCHAR(50)     NOT NULL,
    Status          VARCHAR(20)     NOT NULL DEFAULT 'Draft',
    CreatedAt       TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    CHECK (Status IN ('Draft', 'In_Progress', 'Completed')),
    FOREIGN KEY (WarehouseID) REFERENCES warehouse(WarehouseID)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE stocktake_items (
    SessionID       VARCHAR(10)     NOT NULL,
    ProductID       VARCHAR(10)     NOT NULL,
    SystemQuantity  INT             NOT NULL,
    ActualQuantity  INT             DEFAULT NULL,
    Difference      INT             DEFAULT NULL,
    PRIMARY KEY (SessionID, ProductID),
    FOREIGN KEY (SessionID)  REFERENCES stocktake_sessions(SessionID)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (ProductID)  REFERENCES product(ProductID)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 11: entity_id_sequence (ID tuần tự cho chứng từ)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE entity_id_sequence (
    entity          VARCHAR(20)     PRIMARY KEY,
    next_value      INT UNSIGNED    NOT NULL
) ENGINE=InnoDB;

INSERT INTO entity_id_sequence (entity, next_value) VALUES
('ADJ', 0), ('PR', 0), ('PO', 0), ('RTN', 0), ('ST', 0)
ON DUPLICATE KEY UPDATE next_value = next_value;

-- ─────────────────────────────────────────────────────────────
-- TABLE 12: user (JWT authentication)
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
