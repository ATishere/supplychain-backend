-- SupplyChain7VN - migration cho các nâng cấp V1/V2/V3
-- Chạy một lần trên database hiện có:
--   mysql -u root -p chainsync < migration_v3.sql
-- File này an toàn khi chạy lại (bỏ qua cột đã tồn tại, CREATE TABLE IF NOT EXISTS).

USE chainsync;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE supplier ADD COLUMN Rating INT NOT NULL DEFAULT 5',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'supplier' AND COLUMN_NAME = 'Rating'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE supplier ADD COLUMN OnTimeRate DECIMAL(5,2) NOT NULL DEFAULT 100.00',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'supplier' AND COLUMN_NAME = 'OnTimeRate'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS inventory_adjustments (
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

CREATE TABLE IF NOT EXISTS purchase_requisitions (
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

CREATE TABLE IF NOT EXISTS purchase_orders (
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

CREATE TABLE IF NOT EXISTS return_orders (
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

CREATE TABLE IF NOT EXISTS stocktake_sessions (
    SessionID       VARCHAR(10)     PRIMARY KEY,
    WarehouseID     VARCHAR(10)     NOT NULL,
    CreatedBy       VARCHAR(50)     NOT NULL,
    Status          VARCHAR(20)     NOT NULL DEFAULT 'Draft',
    CreatedAt       TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    CHECK (Status IN ('Draft', 'In_Progress', 'Completed')),
    FOREIGN KEY (WarehouseID) REFERENCES warehouse(WarehouseID)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS stocktake_items (
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

CREATE TABLE IF NOT EXISTS entity_id_sequence (
    entity          VARCHAR(20)     PRIMARY KEY,
    next_value      INT UNSIGNED    NOT NULL
) ENGINE=InnoDB;

INSERT INTO entity_id_sequence (entity, next_value) VALUES
('ADJ', 0), ('PR', 0), ('PO', 0), ('RTN', 0), ('ST', 0)
ON DUPLICATE KEY UPDATE next_value = next_value;
