-- ============================================================================
--  SupplyChain7VN — Chuẩn hóa dữ liệu nghiệp vụ (giá, kho, tồn kho, đơn hàng)
--  File: backend/fix_business_data.sql
--
--  QUY ƯỚC TÍNH TIỀN (khớp backend/app.py và InvoiceModal của frontend):
--      Bill      = UnitPrice × Quantity     -> tạm tính TRƯỚC VAT
--      VatAmount = Bill × VatRate / 100     -> thuế GTGT
--      Tổng thanh toán hóa đơn = Bill + VatAmount
--
--  LƯU Ý AN TOÀN:
--      - Nên backup database trước khi chạy.
--      - File idempotent: chạy lại nhiều lần vẫn cho cùng kết quả.
--      - File KHÔNG chứa USE; hãy chọn đúng database trước khi chạy.
--      - Chạy trên PowerShell: dùng cmd /c "... < file.sql" (xem README/hướng dẫn).
-- ============================================================================

-- Chọn database nếu chạy bằng Workbench/DBeaver (bỏ comment khi cần):
-- USE chainsync;

SET SQL_SAFE_UPDATES = 0;

-- ----------------------------------------------------------------------------
-- 0. Nới cột tiền để tránh tràn số với đơn hàng giá trị lớn
--    (Bill lớn nhất trong bộ dữ liệu chuẩn: 255.000.000 đ)
--    DDL tự động commit nên phải đặt ngoài transaction.
-- ----------------------------------------------------------------------------
ALTER TABLE product MODIFY COLUMN UnitPrice DECIMAL(15,2) NOT NULL;
ALTER TABLE orders  MODIFY COLUMN Bill      DECIMAL(15,2) NOT NULL;

START TRANSACTION;

-- ----------------------------------------------------------------------------
-- 1. Giá bán sản phẩm theo thị trường Việt Nam (VNĐ)
-- ----------------------------------------------------------------------------
UPDATE product SET UnitPrice = 12500000.00 WHERE ProductID = 'P001'; -- Động cơ công nghiệp A4 (chiếc)
UPDATE product SET UnitPrice =   850000.00 WHERE ProductID = 'P002'; -- Phân bón hữu cơ X (bao)
UPDATE product SET UnitPrice =    15000.00 WHERE ProductID = 'P003'; -- Thùng carton cỡ L (thùng)
UPDATE product SET UnitPrice =  1500000.00 WHERE ProductID = 'P004'; -- Bo mạch điều khiển PCB (bộ)
UPDATE product SET UnitPrice =   250000.00 WHERE ProductID = 'P005'; -- Thanh thép 12mm (cây)
UPDATE product SET UnitPrice =   120000.00 WHERE ProductID = 'P006'; -- Cuộn bọc bong bóng (cuộn)

-- 1.1 Đơn vị tính hiển thị đúng tiếng Việt (chuẩn hóa giá trị 'u' cũ nếu có)
UPDATE product SET Unit = 'Chiếc' WHERE ProductID = 'P001';
UPDATE product SET Unit = 'Bao'   WHERE ProductID = 'P002';
UPDATE product SET Unit = 'Thùng' WHERE ProductID = 'P003';
UPDATE product SET Unit = 'Bộ'    WHERE ProductID = 'P004';
UPDATE product SET Unit = 'Cây'   WHERE ProductID = 'P005';
UPDATE product SET Unit = 'Cuộn'  WHERE ProductID = 'P006';

-- Các sản phẩm khác còn đơn vị rỗng hoặc 'u' -> suy ra theo danh mục
UPDATE product SET Unit = CASE
    WHEN Category IN ('Máy móc', 'Machinery')         THEN 'Chiếc'
    WHEN Category IN ('Nguyên liệu', 'Raw Materials') THEN 'Bao'
    WHEN Category IN ('Bao bì', 'Packaging')          THEN 'Thùng'
    WHEN Category IN ('Linh kiện', 'Components')      THEN 'Bộ'
    ELSE 'Cái'
END
WHERE Unit IS NULL OR TRIM(Unit) IN ('', 'u', 'U');

-- ----------------------------------------------------------------------------
-- 2. Sức chứa kho — gắn với quy mô tồn kho thực tế (mục tiêu sử dụng 50–75%)
-- ----------------------------------------------------------------------------
UPDATE warehouse SET Capacity =  4000 WHERE WarehouseID = 'W001'; -- Kho trung tâm TP.HCM
UPDATE warehouse SET Capacity =  3000 WHERE WarehouseID = 'W002'; -- Kho Hà Nội
UPDATE warehouse SET Capacity = 12000 WHERE WarehouseID = 'W003'; -- Kho cảng Hải Phòng
UPDATE warehouse SET Capacity =  1500 WHERE WarehouseID = 'W004'; -- Kho Đà Nẵng

-- ----------------------------------------------------------------------------
-- 3. Tồn kho hiện hữu — số lượng chẵn, hợp lý theo từng loại hàng
-- ----------------------------------------------------------------------------
UPDATE inventory SET QuantityAvailable =  120 WHERE InventoryID = 'I001'; -- P001 @ W001
UPDATE inventory SET QuantityAvailable = 1200 WHERE InventoryID = 'I002'; -- P002 @ W002
UPDATE inventory SET QuantityAvailable = 8000 WHERE InventoryID = 'I003'; -- P003 @ W003
UPDATE inventory SET QuantityAvailable =  350 WHERE InventoryID = 'I004'; -- P004 @ W001
UPDATE inventory SET QuantityAvailable =  500 WHERE InventoryID = 'I005'; -- P005 @ W004
UPDATE inventory SET QuantityAvailable =  800 WHERE InventoryID = 'I006'; -- P006 @ W003

-- ----------------------------------------------------------------------------
-- 4. Bổ sung tồn kho đa kho (mỗi sản phẩm có mặt ở 2 kho)
--    Idempotent: nếu InventoryID đã tồn tại thì cập nhật thay vì báo lỗi.
-- ----------------------------------------------------------------------------
INSERT INTO inventory (InventoryID, QuantityAvailable, ProductID, WarehouseID) VALUES
('I007',   40, 'P001', 'W002'), -- Động cơ @ Hà Nội (dưới ngưỡng 50 -> cảnh báo tồn thấp)
('I008',  300, 'P002', 'W004'), -- Phân bón @ Đà Nẵng
('I009', 1500, 'P003', 'W001'), -- Carton @ TP.HCM
('I010',  150, 'P004', 'W002'), -- PCB @ Hà Nội
('I011',  200, 'P005', 'W001'), -- Thép @ TP.HCM
('I012',  250, 'P006', 'W002')  -- Bong bóng @ Hà Nội
ON DUPLICATE KEY UPDATE
    QuantityAvailable = VALUES(QuantityAvailable),
    ProductID         = VALUES(ProductID),
    WarehouseID       = VALUES(WarehouseID);

-- ----------------------------------------------------------------------------
-- 5. Cập nhật 6 đơn hàng hiện hữu (ORD001–ORD006)
--    Bill = UnitPrice × Quantity (chưa VAT); VatAmount = Bill × VatRate/100
--    Phân bón VAT 0% (miễn thuế GTGT); hóa đơn chỉ cấp cho đơn Accepted.
-- ----------------------------------------------------------------------------
UPDATE orders SET
    OrderDate     = '2026-01-15',
    Bill          = 25000000.00,
    CustomerID    = 'C001',
    ProductID     = 'P001',
    Quantity      = 2,
    Status        = 'Accepted',
    InvoiceNumber = 'HD-ORD001',
    VatRate       = 10.00,
    VatAmount     = 2500000.00,
    PaymentMethod = 'Chuyển khoản'
WHERE OrderID = 'ORD001';

UPDATE orders SET
    OrderDate     = '2026-02-10',
    Bill          = 85000000.00,
    CustomerID    = 'C002',
    ProductID     = 'P002',
    Quantity      = 100,
    Status        = 'Accepted',
    InvoiceNumber = 'HD-ORD002',
    VatRate       = 0.00,
    VatAmount     = 0.00,
    PaymentMethod = 'Chuyển khoản'
WHERE OrderID = 'ORD002';

UPDATE orders SET
    OrderDate     = '2026-03-18',
    Bill          = 15000000.00,
    CustomerID    = 'C003',
    ProductID     = 'P004',
    Quantity      = 10,
    Status        = 'Pending',
    InvoiceNumber = NULL,
    VatRate       = 10.00,
    VatAmount     = 1500000.00,
    PaymentMethod = 'Chuyển khoản'
WHERE OrderID = 'ORD003';

UPDATE orders SET
    OrderDate     = '2026-04-07',
    Bill          = 1500000.00,
    CustomerID    = 'C004',
    ProductID     = 'P003',
    Quantity      = 100,
    Status        = 'Rejected',
    InvoiceNumber = NULL,
    VatRate       = 10.00,
    VatAmount     = 150000.00,
    PaymentMethod = 'Tiền mặt'
WHERE OrderID = 'ORD004';

UPDATE orders SET
    OrderDate     = '2026-05-22',
    Bill          = 12500000.00,
    CustomerID    = 'C005',
    ProductID     = 'P005',
    Quantity      = 50,
    Status        = 'Accepted',
    InvoiceNumber = 'HD-ORD005',
    VatRate       = 10.00,
    VatAmount     = 1250000.00,
    PaymentMethod = 'Ví điện tử'
WHERE OrderID = 'ORD005';

UPDATE orders SET
    OrderDate     = '2026-06-30',
    Bill          = 3600000.00,
    CustomerID    = 'C001',
    ProductID     = 'P006',
    Quantity      = 30,
    Status        = 'Pending',
    InvoiceNumber = NULL,
    VatRate       = 10.00,
    VatAmount     = 360000.00,
    PaymentMethod = 'Chuyển khoản'
WHERE OrderID = 'ORD006';

-- ----------------------------------------------------------------------------
-- 6. Bổ sung 6 đơn hàng mới (ORD007–ORD012) trải đều tháng 7–11/2026
--    Idempotent: nếu OrderID đã tồn tại thì cập nhật thay vì báo lỗi.
-- ----------------------------------------------------------------------------
INSERT INTO orders
    (OrderID, OrderDate, Bill, CustomerID, ProductID, Quantity, Status, InvoiceNumber, VatRate, VatAmount, PaymentMethod)
VALUES
('ORD007', '2026-07-14',   7500000.00, 'C002', 'P003', 500, 'Accepted', 'HD-ORD007', 10.00,   750000.00, 'Chuyển khoản'),
('ORD008', '2026-08-05',  50000000.00, 'C003', 'P005', 200, 'Accepted', 'HD-ORD008', 10.00,  5000000.00, 'Chuyển khoản'),
('ORD009', '2026-09-09',  37500000.00, 'C004', 'P004',  25, 'Accepted', 'HD-ORD009', 10.00,  3750000.00, 'Chuyển khoản'),
('ORD010', '2026-10-21', 255000000.00, 'C005', 'P002', 300, 'Accepted', 'HD-ORD010',  0.00,        0.00, 'Chuyển khoản'),
('ORD011', '2026-11-02',   7200000.00, 'C001', 'P006',  60, 'Pending',  NULL,       10.00,   720000.00, 'Ví điện tử'),
('ORD012', '2026-11-06',  12500000.00, 'C002', 'P001',   1, 'Rejected', NULL,       10.00,  1250000.00, 'Chuyển khoản')
ON DUPLICATE KEY UPDATE
    OrderDate     = VALUES(OrderDate),
    Bill          = VALUES(Bill),
    CustomerID    = VALUES(CustomerID),
    ProductID     = VALUES(ProductID),
    Quantity      = VALUES(Quantity),
    Status        = VALUES(Status),
    InvoiceNumber = VALUES(InvoiceNumber),
    VatRate       = VALUES(VatRate),
    VatAmount     = VALUES(VatAmount),
    PaymentMethod = VALUES(PaymentMethod);

-- ----------------------------------------------------------------------------
-- 7. Chuẩn hóa các bản ghi phát sinh ngoài bộ dữ liệu mẫu (nếu có)
-- ----------------------------------------------------------------------------
-- 7.1 Tồn kho lẻ (VD 5.609 / 5.399) -> làm tròn về bội số 50 gần nhất
UPDATE inventory
SET QuantityAvailable = GREATEST(0, ROUND(COALESCE(QuantityAvailable, 0) / 50) * 50)
WHERE InventoryID NOT IN ('I001','I002','I003','I004','I005','I006','I007','I008','I009','I010','I011','I012');

-- 7.2 Đơn hàng ngoài bộ mẫu: tính lại Bill/VAT theo bảng giá mới
UPDATE orders o
JOIN product p ON p.ProductID = o.ProductID
SET o.Bill      = ROUND(p.UnitPrice * COALESCE(o.Quantity, 1), 2),
    o.VatAmount = ROUND(p.UnitPrice * COALESCE(o.Quantity, 1) * COALESCE(o.VatRate, 10) / 100, 2)
WHERE o.OrderID NOT IN ('ORD001','ORD002','ORD003','ORD004','ORD005','ORD006',
                        'ORD007','ORD008','ORD009','ORD010','ORD011','ORD012');

-- 7.3 Quy tắc hóa đơn: chỉ đơn Accepted mới có số hóa đơn
UPDATE orders SET InvoiceNumber = NULL WHERE Status <> 'Accepted';
UPDATE orders SET InvoiceNumber = CONCAT('HD-', OrderID)
WHERE Status = 'Accepted' AND (InvoiceNumber IS NULL OR InvoiceNumber = '');

COMMIT;

-- ----------------------------------------------------------------------------
-- 8. KIỂM TRA SAU KHI CHẠY (các SELECT dưới đây chỉ đọc, không sửa dữ liệu)
-- ----------------------------------------------------------------------------

-- 8.1 Giá sản phẩm và đơn vị tính
SELECT ProductID, ProductName, Unit, UnitPrice FROM product ORDER BY ProductID;

-- 8.2 Tồn kho theo kho và % sử dụng (kỳ vọng 50–75%)
SELECT w.WarehouseID, w.WarehouseName, w.Capacity,
       COALESCE(SUM(i.QuantityAvailable), 0) AS Used,
       ROUND(COALESCE(SUM(i.QuantityAvailable), 0) / w.Capacity * 100, 1) AS PctUsed
FROM warehouse w
LEFT JOIN inventory i ON i.WarehouseID = w.WarehouseID
GROUP BY w.WarehouseID, w.WarehouseName, w.Capacity
ORDER BY w.WarehouseID;

-- 8.3 Bill phải bằng UnitPrice × Quantity (kỳ vọng: 0 dòng lệch)
SELECT o.OrderID, o.Bill, ROUND(p.UnitPrice * o.Quantity, 2) AS ExpectedBill
FROM orders o
JOIN product p ON p.ProductID = o.ProductID
WHERE ABS(o.Bill - ROUND(p.UnitPrice * o.Quantity, 2)) > 0.01;

-- 8.4 VatAmount phải bằng Bill × VatRate/100 (kỳ vọng: 0 dòng lệch)
SELECT o.OrderID, o.VatAmount, ROUND(o.Bill * o.VatRate / 100, 2) AS ExpectedVat
FROM orders o
WHERE ABS(o.VatAmount - ROUND(o.Bill * o.VatRate / 100, 2)) > 0.01;

-- 8.5 Ngày đơn hàng phải thuộc năm 2026 và không trùng ngày (kỳ vọng: 0 dòng)
SELECT OrderID, OrderDate FROM orders WHERE YEAR(OrderDate) <> 2026;
SELECT OrderDate, COUNT(*) AS Cnt FROM orders GROUP BY OrderDate HAVING COUNT(*) > 1;

-- 8.6 Phân bổ trạng thái và doanh thu (kỳ vọng Accepted=7, Pending=3, Rejected=2)
SELECT Status, COUNT(*) AS Orders, COALESCE(SUM(Bill), 0) AS TotalBill
FROM orders GROUP BY Status ORDER BY Status;

SELECT COALESCE(SUM(Bill), 0)      AS AcceptedRevenue,
       COALESCE(SUM(VatAmount), 0) AS AcceptedVat
FROM orders WHERE Status = 'Accepted';
-- Kỳ vọng: AcceptedRevenue = 472.500.000; AcceptedVat = 13.250.000

-- 8.7 Hóa đơn chỉ cấp cho đơn Accepted (kỳ vọng: 0 dòng vi phạm)
SELECT OrderID, Status, InvoiceNumber FROM orders
WHERE (Status = 'Accepted'  AND InvoiceNumber IS NULL)
   OR (Status <> 'Accepted' AND InvoiceNumber IS NOT NULL);

-- 8.8 Danh sách đơn ngoài năm 2026 (nếu có, cần xử lý thủ công)
SELECT OrderID, OrderDate, Status FROM orders WHERE YEAR(OrderDate) <> 2026;

SET SQL_SAFE_UPDATES = 1;
