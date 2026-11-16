-- ============================================================
--  SupplyChain7VN — B2B ERP migration v1
--  MySQL 8.0+ (Aiven Cloud) / MariaDB 10.4+
--  Chạy:  mysql -h <host> -P <port> -u <user> -p --database <db> < migration_b2b_v1.sql
--  An toàn khi chạy lại (idempotent). KHÔNG xóa dữ liệu cũ.
--
--  GHI CHÚ MySQL 8.0 (Aiven):
--    information_schema.CHECK_CONSTRAINTS KHÔNG có cột TABLE_NAME
--    (MariaDB mới có) => mọi truy vấn "...WHERE ... TABLE_NAME" trên view này
--    đều lỗi [42S22] Unknown column 'TABLE_NAME' in 'where clause'.
--    Vì vậy file này chỉ dùng information_schema.TABLE_CONSTRAINTS.
--    MySQL cũng KHÔNG hỗ trợ "ALTER TABLE ... DROP CHECK IF EXISTS",
--    nên việc xóa CHECK được bọc trong thủ tục sc7_drop_checks() bên dưới.
--    => Phải chạy bằng client hiểu lệnh DELIMITER (mysql CLI, Workbench,
--       DBeaver, phpMyAdmin).
-- ============================================================

USE chainsync;

-- ─────────────────────────────────────────────────────────────
-- 0. Helper: xóa toàn bộ CHECK constraint của một bảng (nếu có)
--    - Dùng TABLE_CONSTRAINTS (an toàn trên cả MySQL 8.0 và MariaDB)
--    - DDL bắt buộc phải là câu lệnh động vì tên constraint do engine tự sinh
--      (MySQL: <table>_chk_N, MariaDB: CONSTRAINT_N, hoặc tên do migration đặt)
--    - Gọi lại nhiều lần vẫn đúng: bảng không còn CHECK thì vòng lặp rỗng.
-- ─────────────────────────────────────────────────────────────
DROP PROCEDURE IF EXISTS sc7_drop_checks;

DELIMITER $$

CREATE PROCEDURE sc7_drop_checks(IN p_table VARCHAR(64))
BEGIN
    DECLARE v_done INT DEFAULT 0;
    DECLARE v_name VARCHAR(64);

    DROP TEMPORARY TABLE IF EXISTS sc7_check_names;
    CREATE TEMPORARY TABLE sc7_check_names (name VARCHAR(64) NOT NULL);

    INSERT INTO sc7_check_names (name)
    SELECT CONSTRAINT_NAME
      FROM information_schema.TABLE_CONSTRAINTS
     WHERE CONSTRAINT_SCHEMA = DATABASE()
       AND TABLE_SCHEMA      = DATABASE()
       AND TABLE_NAME        = p_table
       AND CONSTRAINT_TYPE   = 'CHECK';

    BEGIN
        DECLARE cur CURSOR FOR SELECT name FROM sc7_check_names;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = 1;

        OPEN cur;
        read_loop: LOOP
            FETCH cur INTO v_name;
            IF v_done = 1 THEN
                LEAVE read_loop;
            END IF;

            -- "DROP CONSTRAINT" là cú pháp duy nhất chạy được trên CẢ
            -- MariaDB 10.2+ và MySQL 8.0.19+ (MySQL 8 chỉ có thêm DROP CHECK,
            -- còn MariaDB thì không hỗ trợ DROP CHECK).
            SET @sc7_ddl = CONCAT('ALTER TABLE `', p_table, '` DROP CONSTRAINT `', v_name, '`');
            PREPARE sc7_stmt FROM @sc7_ddl;
            EXECUTE sc7_stmt;
            DEALLOCATE PREPARE sc7_stmt;
        END LOOP;
        CLOSE cur;
    END;

    DROP TEMPORARY TABLE IF EXISTS sc7_check_names;
END$$

DELIMITER ;

-- ─────────────────────────────────────────────────────────────
-- 1. organizations — pháp nhân khách hàng doanh nghiệp
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS organizations (
    OrganizationID       VARCHAR(10)  PRIMARY KEY,
    OrganizationCode     VARCHAR(20)  NOT NULL,
    OrganizationName     VARCHAR(150) NOT NULL,
    TaxCode              VARCHAR(20)  DEFAULT NULL,
    OrganizationType     VARCHAR(30)  NOT NULL DEFAULT 'OrganizationCustomer',
    Address              VARCHAR(255) DEFAULT NULL,
    Representative       VARCHAR(100) DEFAULT NULL,
    RepresentativePhone  VARCHAR(20)  DEFAULT NULL,
    RepresentativeEmail  VARCHAR(100) DEFAULT NULL,
    Status               VARCHAR(20)  NOT NULL DEFAULT 'Active',
    CreatedAt            TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt            TIMESTAMP    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_org_code (OrganizationCode),
    UNIQUE KEY uq_org_tax (TaxCode),
    CONSTRAINT org_type_chk CHECK (OrganizationType IN ('OrganizationCustomer', 'Supplier', 'Central')),
    CONSTRAINT org_status_chk CHECK (Status IN ('Active', 'Inactive'))
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 2. user — gắn Organization + hồ sơ nhân sự, mở rộng role
-- ─────────────────────────────────────────────────────────────
SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `user` ADD COLUMN OrganizationID VARCHAR(10) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user' AND COLUMN_NAME = 'OrganizationID');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `user` ADD COLUMN FullName VARCHAR(100) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user' AND COLUMN_NAME = 'FullName');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `user` ADD COLUMN Position VARCHAR(50) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user' AND COLUMN_NAME = 'Position');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `user` ADD COLUMN Email VARCHAR(100) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user' AND COLUMN_NAME = 'Email');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `user` ADD COLUMN Status VARCHAR(20) NOT NULL DEFAULT ''Active''',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user' AND COLUMN_NAME = 'Status');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `user` ADD COLUMN CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user' AND COLUMN_NAME = 'CreatedAt');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Thay CHECK role cũ (admin/customer) bằng bộ role B2B.
-- Bước 1: bỏ CHECK cũ do schema.sql tạo (MySQL tự đặt tên user_chk_1)
--         hoặc do lần migrate trước tạo (user_role_chk).
CALL sc7_drop_checks('user');

-- Bước 2: thêm CHECK tĩnh, đúng 4 role mà backend chấp nhận.
ALTER TABLE `user`
    ADD CONSTRAINT user_role_chk
    CHECK (Role IN ('admin', 'org_manager', 'org_staff', 'customer'));

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `user` ADD CONSTRAINT fk_user_org FOREIGN KEY (OrganizationID) REFERENCES organizations(OrganizationID) ON DELETE SET NULL ON UPDATE CASCADE',
    'SELECT 1')
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = 'user' AND CONSTRAINT_NAME = 'fk_user_org');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `user` ADD INDEX idx_user_org (OrganizationID)',
    'SELECT 1')
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user' AND INDEX_NAME = 'idx_user_org');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ─────────────────────────────────────────────────────────────
-- 3. customer — liên kết hồ sơ pháp nhân
-- ─────────────────────────────────────────────────────────────
SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE customer ADD COLUMN OrganizationID VARCHAR(10) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'customer' AND COLUMN_NAME = 'OrganizationID');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE customer ADD COLUMN Email VARCHAR(100) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'customer' AND COLUMN_NAME = 'Email');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE customer ADD UNIQUE KEY uq_customer_org (OrganizationID)',
    'SELECT 1')
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'customer' AND INDEX_NAME = 'uq_customer_org');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE customer ADD CONSTRAINT fk_customer_org FOREIGN KEY (OrganizationID) REFERENCES organizations(OrganizationID) ON DELETE SET NULL ON UPDATE CASCADE',
    'SELECT 1')
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = 'customer' AND CONSTRAINT_NAME = 'fk_customer_org');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ─────────────────────────────────────────────────────────────
-- 4. customer_purchase_requests (CPR) — yêu cầu mua của doanh nghiệp
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS customer_purchase_requests (
    CPRID             VARCHAR(10)   PRIMARY KEY,
    OrganizationID    VARCHAR(10)   NOT NULL,
    CustomerID        VARCHAR(10)   NOT NULL,
    RequestedByUserID INT           DEFAULT NULL,
    RequestedByName   VARCHAR(100)  DEFAULT NULL,
    Status            VARCHAR(30)   NOT NULL DEFAULT 'Draft',
    Note              VARCHAR(500)  DEFAULT NULL,
    RejectReason      VARCHAR(255)  DEFAULT NULL,
    TotalEstimated    DECIMAL(15,2) NOT NULL DEFAULT 0.00,
    ApprovedByName    VARCHAR(100)  DEFAULT NULL,
    ApprovedAt        DATETIME      DEFAULT NULL,
    ConvertedAt       DATETIME      DEFAULT NULL,
    CreatedAt         TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt         TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT cpr_status_chk CHECK (Status IN ('Draft', 'Submitted', 'Approved', 'Rejected', 'Converted', 'Cancelled')),
    CONSTRAINT cpr_total_chk CHECK (TotalEstimated >= 0),
    CONSTRAINT fk_cpr_org FOREIGN KEY (OrganizationID) REFERENCES organizations(OrganizationID)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_cpr_customer FOREIGN KEY (CustomerID) REFERENCES customer(CustomerID)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_cpr_user FOREIGN KEY (RequestedByUserID) REFERENCES `user`(UserID)
        ON DELETE SET NULL ON UPDATE CASCADE,
    KEY idx_cpr_org (OrganizationID),
    KEY idx_cpr_customer (CustomerID),
    KEY idx_cpr_status (Status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS customer_purchase_request_items (
    CPRID     VARCHAR(10)   NOT NULL,
    LineNo    INT           NOT NULL,
    ProductID VARCHAR(10)   NOT NULL,
    Quantity  INT           NOT NULL,
    UnitPrice DECIMAL(15,2) NOT NULL DEFAULT 0.00,
    PRIMARY KEY (CPRID, LineNo),
    CONSTRAINT cpritem_qty_chk CHECK (Quantity > 0),
    CONSTRAINT cpritem_price_chk CHECK (UnitPrice >= 0),
    CONSTRAINT fk_cpritem_cpr FOREIGN KEY (CPRID) REFERENCES customer_purchase_requests(CPRID)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_cpritem_product FOREIGN KEY (ProductID) REFERENCES product(ProductID)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 5. purchase_requisitions — header + dòng hàng
-- ─────────────────────────────────────────────────────────────
SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_requisitions ADD COLUMN Reason VARCHAR(255) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_requisitions' AND COLUMN_NAME = 'Reason');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_requisitions ADD COLUMN WarehouseID VARCHAR(10) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_requisitions' AND COLUMN_NAME = 'WarehouseID');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_requisitions ADD COLUMN OrganizationID VARCHAR(10) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_requisitions' AND COLUMN_NAME = 'OrganizationID');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_requisitions ADD COLUMN CreatedByUserID INT NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_requisitions' AND COLUMN_NAME = 'CreatedByUserID');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_requisitions ADD COLUMN ApprovedBy VARCHAR(50) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_requisitions' AND COLUMN_NAME = 'ApprovedBy');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_requisitions ADD COLUMN ApprovedAt DATETIME NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_requisitions' AND COLUMN_NAME = 'ApprovedAt');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 1,
    'ALTER TABLE purchase_requisitions MODIFY ProductID VARCHAR(10) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_requisitions'
      AND COLUMN_NAME = 'ProductID' AND IS_NULLABLE = 'NO');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 1,
    'ALTER TABLE purchase_requisitions MODIFY Quantity INT NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_requisitions'
      AND COLUMN_NAME = 'Quantity' AND IS_NULLABLE = 'NO');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- PR: QC Status cũ (Draft/Pending_Approval/Approved/Rejected) không có
-- Converted/Cancelled => thay bằng bộ trạng thái đầy đủ của luồng B2B.
CALL sc7_drop_checks('purchase_requisitions');

ALTER TABLE purchase_requisitions
    ADD CONSTRAINT pr_qty_chk    CHECK (Quantity > 0),
    ADD CONSTRAINT pr_status_chk CHECK (Status IN ('Draft', 'Pending_Approval', 'Approved', 'Rejected', 'Converted', 'Cancelled'));

CREATE TABLE IF NOT EXISTS purchase_requisition_items (
    PRID      VARCHAR(10) NOT NULL,
    LineNo    INT         NOT NULL,
    ProductID VARCHAR(10) NOT NULL,
    Quantity  INT         NOT NULL,
    PRIMARY KEY (PRID, LineNo),
    CONSTRAINT pritem_qty_chk CHECK (Quantity > 0),
    CONSTRAINT fk_pritem_pr FOREIGN KEY (PRID) REFERENCES purchase_requisitions(PRID)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_pritem_product FOREIGN KEY (ProductID) REFERENCES product(ProductID)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

INSERT IGNORE INTO purchase_requisition_items (PRID, LineNo, ProductID, Quantity)
SELECT PRID, 1, ProductID, Quantity
FROM purchase_requisitions
WHERE ProductID IS NOT NULL AND Quantity IS NOT NULL;

-- ─────────────────────────────────────────────────────────────
-- 6. purchase_orders — header + dòng hàng + received quantity
-- ─────────────────────────────────────────────────────────────
SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_orders ADD COLUMN ExpectedDate DATE NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_orders' AND COLUMN_NAME = 'ExpectedDate');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_orders ADD COLUMN WarehouseID VARCHAR(10) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_orders' AND COLUMN_NAME = 'WarehouseID');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_orders ADD COLUMN TaxAmount DECIMAL(15,2) NOT NULL DEFAULT 0.00',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_orders' AND COLUMN_NAME = 'TaxAmount');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_orders ADD COLUMN ShippingFee DECIMAL(15,2) NOT NULL DEFAULT 0.00',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_orders' AND COLUMN_NAME = 'ShippingFee');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_orders ADD COLUMN Notes VARCHAR(255) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_orders' AND COLUMN_NAME = 'Notes');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_orders ADD COLUMN SentAt DATETIME NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_orders' AND COLUMN_NAME = 'SentAt');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_orders ADD COLUMN CompletedAt DATETIME NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_orders' AND COLUMN_NAME = 'CompletedAt');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_orders ADD COLUMN CreatedByUserID INT NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_orders' AND COLUMN_NAME = 'CreatedByUserID');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 1,
    'ALTER TABLE purchase_orders MODIFY ProductID VARCHAR(10) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_orders'
      AND COLUMN_NAME = 'ProductID' AND IS_NULLABLE = 'NO');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 1,
    'ALTER TABLE purchase_orders MODIFY Quantity INT NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_orders'
      AND COLUMN_NAME = 'Quantity' AND IS_NULLABLE = 'NO');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 1,
    'ALTER TABLE purchase_orders MODIFY UnitPrice DECIMAL(15,2) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_orders'
      AND COLUMN_NAME = 'UnitPrice' AND IS_NULLABLE = 'NO');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- PO: bổ sung Draft/Sent/Partially_Received/Completed cho nhận hàng từng phần.
CALL sc7_drop_checks('purchase_orders');

ALTER TABLE purchase_orders
    ADD CONSTRAINT po_qty_chk       CHECK (Quantity > 0),
    ADD CONSTRAINT po_unitprice_chk CHECK (UnitPrice >= 0),
    ADD CONSTRAINT po_total_chk     CHECK (TotalAmount >= 0),
    ADD CONSTRAINT po_status_chk    CHECK (Status IN ('Draft', 'Ordered', 'Sent', 'Partially_Received', 'Received', 'Completed', 'Cancelled'));

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE purchase_orders ADD CONSTRAINT fk_po_warehouse FOREIGN KEY (WarehouseID) REFERENCES warehouse(WarehouseID) ON DELETE SET NULL ON UPDATE CASCADE',
    'SELECT 1')
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = 'purchase_orders' AND CONSTRAINT_NAME = 'fk_po_warehouse');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS purchase_order_items (
    POID             VARCHAR(10)   NOT NULL,
    LineNo           INT           NOT NULL,
    ProductID        VARCHAR(10)   NOT NULL,
    Quantity         INT           NOT NULL,
    UnitPrice        DECIMAL(15,2) NOT NULL,
    LineTotal        DECIMAL(15,2) NOT NULL,
    ReceivedQuantity INT           NOT NULL DEFAULT 0,
    PRIMARY KEY (POID, LineNo),
    CONSTRAINT poitem_qty_chk CHECK (Quantity > 0),
    CONSTRAINT poitem_price_chk CHECK (UnitPrice >= 0),
    CONSTRAINT poitem_total_chk CHECK (LineTotal >= 0),
    CONSTRAINT poitem_received_chk CHECK (ReceivedQuantity >= 0 AND ReceivedQuantity <= Quantity),
    CONSTRAINT fk_poitem_po FOREIGN KEY (POID) REFERENCES purchase_orders(POID)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_poitem_product FOREIGN KEY (ProductID) REFERENCES product(ProductID)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

INSERT IGNORE INTO purchase_order_items
    (POID, LineNo, ProductID, Quantity, UnitPrice, LineTotal, ReceivedQuantity)
SELECT POID, 1, ProductID, Quantity, UnitPrice, TotalAmount,
       CASE WHEN Status = 'Received' THEN Quantity ELSE 0 END
FROM purchase_orders
WHERE ProductID IS NOT NULL AND Quantity IS NOT NULL AND UnitPrice IS NOT NULL;

-- ─────────────────────────────────────────────────────────────
-- 7. goods_receipt_notes (GRN)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS goods_receipt_notes (
    GRNID       VARCHAR(10) PRIMARY KEY,
    POID        VARCHAR(10) NOT NULL,
    WarehouseID VARCHAR(10) NOT NULL,
    ReceivedBy  VARCHAR(50) NOT NULL,
    ReceivedAt  DATETIME    DEFAULT CURRENT_TIMESTAMP,
    Notes       VARCHAR(255) DEFAULT NULL,
    Status      VARCHAR(20) NOT NULL DEFAULT 'Posted',
    CONSTRAINT fk_grn_po FOREIGN KEY (POID) REFERENCES purchase_orders(POID)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_grn_warehouse FOREIGN KEY (WarehouseID) REFERENCES warehouse(WarehouseID)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    KEY idx_grn_po (POID)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS goods_receipt_items (
    GRNID            VARCHAR(10) NOT NULL,
    LineNo           INT         NOT NULL,
    ProductID        VARCHAR(10) NOT NULL,
    QuantityReceived INT         NOT NULL,
    PRIMARY KEY (GRNID, LineNo),
    CONSTRAINT grnitem_qty_chk CHECK (QuantityReceived > 0),
    CONSTRAINT fk_grnitem_grn FOREIGN KEY (GRNID) REFERENCES goods_receipt_notes(GRNID)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_grnitem_product FOREIGN KEY (ProductID) REFERENCES product(ProductID)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 8. inventory_transactions — ledger biến động kho
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS inventory_transactions (
    TransactionID   VARCHAR(10) PRIMARY KEY,
    InventoryID     VARCHAR(10) DEFAULT NULL,
    ProductID       VARCHAR(10) NOT NULL,
    WarehouseID     VARCHAR(10) NOT NULL,
    TransactionType VARCHAR(30) NOT NULL,
    QuantityChange  INT         NOT NULL,
    QuantityBefore  INT         NOT NULL,
    QuantityAfter   INT         NOT NULL,
    ReferenceType   VARCHAR(30) DEFAULT NULL,
    ReferenceID     VARCHAR(20) DEFAULT NULL,
    Notes           VARCHAR(255) DEFAULT NULL,
    PerformedBy     VARCHAR(50) DEFAULT NULL,
    CreatedAt       TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT txn_after_chk CHECK (QuantityAfter >= 0),
    CONSTRAINT txn_before_chk CHECK (QuantityBefore >= 0),
    CONSTRAINT fk_txn_inventory FOREIGN KEY (InventoryID) REFERENCES inventory(InventoryID)
        ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT fk_txn_product FOREIGN KEY (ProductID) REFERENCES product(ProductID)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_txn_warehouse FOREIGN KEY (WarehouseID) REFERENCES warehouse(WarehouseID)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    KEY idx_txn_product (ProductID),
    KEY idx_txn_warehouse (WarehouseID),
    KEY idx_txn_type (TransactionType),
    KEY idx_txn_ref (ReferenceType, ReferenceID)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────────────────────────
-- 9. orders (Sales Order) — B2B + trạng thái mở rộng
-- ─────────────────────────────────────────────────────────────
SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE orders ADD COLUMN OrganizationID VARCHAR(10) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'OrganizationID');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE orders ADD COLUMN SourceCPRID VARCHAR(10) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'SourceCPRID');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE orders ADD COLUMN WarehouseID VARCHAR(10) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'WarehouseID');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE orders ADD COLUMN CreatedByUserID INT NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'CreatedByUserID');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- SO: bổ sung Processing/Completed cho luồng giao hàng B2B.
CALL sc7_drop_checks('orders');

ALTER TABLE orders
    ADD CONSTRAINT orders_bill_chk   CHECK (Bill >= 0),
    ADD CONSTRAINT orders_qty_chk    CHECK (Quantity > 0),
    ADD CONSTRAINT orders_vat_chk    CHECK (VatRate BETWEEN 0 AND 100),
    ADD CONSTRAINT orders_status_chk CHECK (Status IN ('Pending', 'Accepted', 'Processing', 'Completed', 'Rejected', 'Cancelled'));

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE orders ADD UNIQUE KEY uq_orders_cpr_product (SourceCPRID, ProductID)',
    'SELECT 1')
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND INDEX_NAME = 'uq_orders_cpr_product');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE orders ADD CONSTRAINT fk_orders_org FOREIGN KEY (OrganizationID) REFERENCES organizations(OrganizationID) ON DELETE SET NULL ON UPDATE CASCADE',
    'SELECT 1')
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND CONSTRAINT_NAME = 'fk_orders_org');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE orders ADD CONSTRAINT fk_orders_cpr FOREIGN KEY (SourceCPRID) REFERENCES customer_purchase_requests(CPRID) ON DELETE SET NULL ON UPDATE CASCADE',
    'SELECT 1')
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND CONSTRAINT_NAME = 'fk_orders_cpr');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE orders ADD INDEX idx_orders_org (OrganizationID)',
    'SELECT 1')
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND INDEX_NAME = 'idx_orders_org');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ─────────────────────────────────────────────────────────────
-- 10. return_orders — quy trình duyệt → xác nhận nhận hàng
-- ─────────────────────────────────────────────────────────────
SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE return_orders ADD COLUMN ReviewedBy VARCHAR(50) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'return_orders' AND COLUMN_NAME = 'ReviewedBy');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE return_orders ADD COLUMN ReviewedAt DATETIME NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'return_orders' AND COLUMN_NAME = 'ReviewedAt');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE return_orders ADD COLUMN ReceivedBy VARCHAR(50) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'return_orders' AND COLUMN_NAME = 'ReceivedBy');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE return_orders ADD COLUMN ReceivedAt DATETIME NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'return_orders' AND COLUMN_NAME = 'ReceivedAt');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE return_orders ADD COLUMN RefundStatus VARCHAR(20) NOT NULL DEFAULT ''None''',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'return_orders' AND COLUMN_NAME = 'RefundStatus');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE return_orders ADD COLUMN OrganizationID VARCHAR(10) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'return_orders' AND COLUMN_NAME = 'OrganizationID');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Return: thêm Received (đã nhận hàng trả) vào sau bước approve.
CALL sc7_drop_checks('return_orders');

ALTER TABLE return_orders
    ADD CONSTRAINT return_qty_chk    CHECK (Quantity > 0),
    ADD CONSTRAINT return_refund_chk CHECK (RefundAmount >= 0),
    ADD CONSTRAINT return_status_chk CHECK (Status IN ('Pending', 'Approved', 'Rejected', 'Received', 'Cancelled'));

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE return_orders ADD CONSTRAINT fk_returns_org FOREIGN KEY (OrganizationID) REFERENCES organizations(OrganizationID) ON DELETE SET NULL ON UPDATE CASCADE',
    'SELECT 1')
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = 'return_orders' AND CONSTRAINT_NAME = 'fk_returns_org');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE return_orders ADD INDEX idx_returns_org (OrganizationID)',
    'SELECT 1')
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'return_orders' AND INDEX_NAME = 'idx_returns_org');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ─────────────────────────────────────────────────────────────
-- 11. stocktake_sessions — người/ thời điểm hoàn tất
-- ─────────────────────────────────────────────────────────────
SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE stocktake_sessions ADD COLUMN CompletedBy VARCHAR(50) NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'stocktake_sessions' AND COLUMN_NAME = 'CompletedBy');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE stocktake_sessions ADD COLUMN CompletedAt DATETIME NULL',
    'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'stocktake_sessions' AND COLUMN_NAME = 'CompletedAt');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ─────────────────────────────────────────────────────────────
-- 12. Bổ sung sequence chứng từ mới
-- ─────────────────────────────────────────────────────────────
INSERT INTO entity_id_sequence (entity, next_value) VALUES
    ('CPR', 0), ('GRN', 0), ('TXN', 0), ('INV', 0)
ON DUPLICATE KEY UPDATE next_value = next_value;

-- ─────────────────────────────────────────────────────────────
-- 13. Dọn thủ tục tạm (không để rác trong schema cloud)
-- ─────────────────────────────────────────────────────────────
DROP PROCEDURE IF EXISTS sc7_drop_checks;
