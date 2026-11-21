-- =============================================================================
-- KASED KARIM LUXURY LIGHTING - RELATIONAL SQL SCHEMA MIGRATION (001)
-- Standards: OWASP ASVS Level 3 & ISO/IEC 27001 Data Integrity Architecture
-- Engine: PostgreSQL 14+ / Relational SQL Standard
-- Features: Strict Foreign Keys (ON DELETE RESTRICT), Soft Delete (deleted_at),
--           Normalized Tables (products, orders, pricelist, inventory, sales)
-- =============================================================================

BEGIN;

-- 1. Categories Table (تصنيفات الكتالوج)
CREATE TABLE IF NOT EXISTS categories (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    en_name VARCHAR(150),
    slug VARCHAR(100) UNIQUE NOT NULL,
    parent_id VARCHAR(64) REFERENCES categories(id) ON DELETE SET NULL,
    icon VARCHAR(100),
    sort_order INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. Products Table (كتالوج المنتجات الفاخرة)
-- Core Rule: Soft Delete via `deleted_at`. Records are never physically purged if historical links exist.
CREATE TABLE IF NOT EXISTS products (
    id VARCHAR(64) PRIMARY KEY,
    sku VARCHAR(100) UNIQUE,
    name VARCHAR(255) NOT NULL,
    en_name VARCHAR(255),
    category_id VARCHAR(64) REFERENCES categories(id) ON DELETE RESTRICT,
    category_name VARCHAR(150),
    price DECIMAL(12, 2) NOT NULL CHECK (price >= 0),
    sale_price DECIMAL(12, 2) CHECK (sale_price IS NULL OR (sale_price > 0 AND sale_price <= price)),
    original_price DECIMAL(12, 2),
    cost_price DECIMAL(12, 2) CHECK (cost_price IS NULL OR cost_price >= 0),
    stock INT NOT NULL DEFAULT 0 CHECK (stock >= 0),
    image TEXT,
    secondary_image TEXT,
    images JSONB DEFAULT '[]'::jsonb,
    description TEXT,
    short_description TEXT,
    style VARCHAR(100),
    warranty VARCHAR(100) DEFAULT '5 سنوات ضمان معتمد',
    specs JSONB DEFAULT '{}'::jsonb,
    variants JSONB DEFAULT '[]'::jsonb,
    tags JSONB DEFAULT '[]'::jsonb,
    active BOOLEAN DEFAULT TRUE,
    featured BOOLEAN DEFAULT FALSE,
    is_new BOOLEAN DEFAULT FALSE,
    is_bestseller BOOLEAN DEFAULT FALSE,
    status VARCHAR(30) DEFAULT 'published',
    -- SOFT DELETE FIELD (قاعدة الحذف اللطيف الإلزامية)
    deleted_at TIMESTAMPTZ DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. Price Lists (قوائم الأسعار وعروض الأسعار للعملاء التجاريين والمشاريع)
CREATE TABLE IF NOT EXISTS pricelists (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    code VARCHAR(50) UNIQUE,
    currency VARCHAR(10) DEFAULT 'EGP',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 4. Price List Items (بنود قوائم الأسعار المرتبطة بالمنتجات)
CREATE TABLE IF NOT EXISTS pricelist_items (
    id VARCHAR(64) PRIMARY KEY,
    pricelist_id VARCHAR(64) NOT NULL REFERENCES pricelists(id) ON DELETE CASCADE,
    product_id VARCHAR(64) NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    tier_price DECIMAL(12, 2) NOT NULL CHECK (tier_price >= 0),
    min_quantity INT DEFAULT 1 CHECK (min_quantity > 0),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_pricelist_product UNIQUE (pricelist_id, product_id)
);

-- 5. Inventory Tracking (إدارة المستودعات وحركات المخزون)
CREATE TABLE IF NOT EXISTS inventory (
    id VARCHAR(64) PRIMARY KEY,
    product_id VARCHAR(64) NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    warehouse_name VARCHAR(150) DEFAULT 'المستودع الرئيسي - الشيخ زايد',
    quantity_on_hand INT NOT NULL DEFAULT 0 CHECK (quantity_on_hand >= 0),
    quantity_reserved INT NOT NULL DEFAULT 0 CHECK (quantity_reserved >= 0),
    reorder_threshold INT DEFAULT 5 CHECK (reorder_threshold >= 0),
    bin_location VARCHAR(50),
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_product_warehouse UNIQUE (product_id, warehouse_name)
);

-- 6. Orders Master Table (طلبات الشراء والعملاء)
CREATE TABLE IF NOT EXISTS orders (
    id VARCHAR(64) PRIMARY KEY,
    order_number VARCHAR(64) UNIQUE NOT NULL,
    customer_name VARCHAR(150) NOT NULL,
    customer_phone VARCHAR(50) NOT NULL,
    customer_email VARCHAR(150),
    shipping_address TEXT NOT NULL,
    delivery_city VARCHAR(100),
    notes TEXT,
    subtotal DECIMAL(12, 2) NOT NULL CHECK (subtotal >= 0),
    discount DECIMAL(12, 2) DEFAULT 0 CHECK (discount >= 0),
    delivery_fee DECIMAL(12, 2) DEFAULT 0 CHECK (delivery_fee >= 0),
    total DECIMAL(12, 2) NOT NULL CHECK (total >= 0),
    status VARCHAR(50) DEFAULT 'pending',
    payment_method VARCHAR(50) DEFAULT 'cod',
    payment_status VARCHAR(50) DEFAULT 'unpaid',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 7. Order Items (بنود الطلبات - ترتبط بالمنتج بعلاقة إلزامية تمنع حذفه نهائياً)
CREATE TABLE IF NOT EXISTS order_items (
    id VARCHAR(64) PRIMARY KEY,
    order_id VARCHAR(64) NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id VARCHAR(64) NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    product_name VARCHAR(255) NOT NULL,
    sku VARCHAR(100),
    unit_price DECIMAL(12, 2) NOT NULL CHECK (unit_price >= 0),
    quantity INT NOT NULL CHECK (quantity > 0),
    total_price DECIMAL(12, 2) NOT NULL CHECK (total_price >= 0)
);

-- 8. Sales & Financial Transactions (حركات المبيعات والأرباح التحليلية)
CREATE TABLE IF NOT EXISTS sales (
    id VARCHAR(64) PRIMARY KEY,
    order_id VARCHAR(64) REFERENCES orders(id) ON DELETE SET NULL,
    product_id VARCHAR(64) NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    quantity_sold INT NOT NULL CHECK (quantity_sold > 0),
    unit_cost DECIMAL(12, 2) DEFAULT 0 CHECK (unit_cost >= 0),
    unit_price DECIMAL(12, 2) NOT NULL CHECK (unit_price >= 0),
    gross_revenue DECIMAL(12, 2) NOT NULL CHECK (gross_revenue >= 0),
    net_profit DECIMAL(12, 2) NOT NULL,
    sale_date TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 9. Long-Term Web Restore Points (نقاط الاسترجاع المؤرشفة تاريخياً لسنة أو أكثر مع دعم التقويم)
CREATE TABLE IF NOT EXISTS restore_points (
    id VARCHAR(64) PRIMARY KEY,
    timestamp BIGINT NOT NULL,
    date_str VARCHAR(20) NOT NULL,
    time_str VARCHAR(20) NOT NULL,
    label TEXT NOT NULL,
    point_type VARCHAR(50) DEFAULT 'auto_delete',
    counts JSONB DEFAULT '{}'::jsonb,
    total_revenue DECIMAL(12, 2) DEFAULT 0,
    snapshot_data JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 10. Customers & User Profiles (بيانات العملاء وحسابات الدخول)
CREATE TABLE IF NOT EXISTS customers (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    phone VARCHAR(32) UNIQUE,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    password_salt VARCHAR(255),
    google_sub VARCHAR(255) UNIQUE,
    avatar TEXT,
    role VARCHAR(32) DEFAULT 'customer',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_customers_phone ON customers(phone);
CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email);

-- -----------------------------------------------------------------------------
-- PERFORMANCE & INTEGRITY INDEXES
-- -----------------------------------------------------------------------------
-- Core Soft-Delete Filter Index (تسريع استعلامات الكتالوج التي تستثني المنتجات المحذوفة)
CREATE INDEX IF NOT EXISTS idx_products_active_storefront 
    ON products (category_id, created_at DESC) 
    WHERE deleted_at IS NULL AND active = TRUE;

CREATE INDEX IF NOT EXISTS idx_products_deleted_at 
    ON products (deleted_at);

-- Foreign Key Lookup Indexes (تسريع فحص الارتباطات عند محاولة الحذف)
CREATE INDEX IF NOT EXISTS idx_order_items_product_id 
    ON order_items (product_id);

CREATE INDEX IF NOT EXISTS idx_sales_product_id 
    ON sales (product_id);

CREATE INDEX IF NOT EXISTS idx_inventory_product_id 
    ON inventory (product_id);

CREATE INDEX IF NOT EXISTS idx_pricelist_items_product_id 
    ON pricelist_items (product_id);

CREATE INDEX IF NOT EXISTS idx_orders_status 
    ON orders (status, created_at DESC);

COMMIT;
