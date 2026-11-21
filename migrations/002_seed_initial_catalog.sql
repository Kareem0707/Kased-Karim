-- =============================================================================
-- KASED KARIM LUXURY LIGHTING - SEED INITIAL CATALOG (002)
-- Baseline categories, luxury products, inventory, and pricelist tiers
-- =============================================================================

BEGIN;

-- 1. Categories
INSERT INTO categories (id, name, en_name, slug, sort_order) VALUES
('cat_chandeliers', 'نجف وثريات فاخرة', 'Luxury Chandeliers', 'chandeliers', 1),
('cat_wall_lights', 'إنارة جدارية عصرية', 'Modern Wall Lights', 'wall-lights', 2),
('cat_architectural', 'إنارة معمارية ومخفية', 'Architectural Lighting', 'architectural', 3),
('cat_outdoor', 'إنارة حدائق وواجهات', 'Outdoor & Landscape', 'outdoor', 4),
('cat_smart_control', 'أنظمة تحكم ذكية', 'Smart Lighting Automation', 'smart-control', 5)
ON CONFLICT (id) DO NOTHING;

-- 2. Sample Products with Full Relational Attributes
INSERT INTO products (
    id, sku, name, en_name, category_id, category_name,
    price, sale_price, cost_price, stock, image, description,
    active, featured, is_bestseller, deleted_at
) VALUES
(
    'prod_crystal_palace',
    'KK-CH-001',
    'ثريا كريستال عصفور ملكية - قصر الكريستال',
    'Crystal Palace Royal Chandelier',
    'cat_chandeliers',
    'نجف وثريات فاخرة',
    48500.00,
    42000.00,
    28000.00,
    12,
    'https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=800&q=80',
    'ثريا ملكية فاخرة مطلية بذهب عيار 24 مع كريستال نقي ومصممة خصيصاً للصالات والقصور.',
    TRUE,
    TRUE,
    TRUE,
    NULL
),
(
    'prod_nordic_minimal',
    'KK-WL-002',
    'وحدة إضاءة جدارية نورديك ألمنيوم مصقول',
    'Nordic Minimalist Wall Sconce',
    'cat_wall_lights',
    'إنارة جدارية عصرية',
    3800.00,
    NULL,
    2100.00,
    45,
    'https://images.unsplash.com/photo-1513506003901-1e6a229e2d15?auto=format&fit=crop&w=800&q=80',
    'إضاءة جدارية غير مباشرة بدرجة حرارة لون 3000K تمنح راحة بصرية فائقة وأناقة راقية.',
    TRUE,
    FALSE,
    TRUE,
    NULL
),
(
    'prod_smart_magnetic',
    'KK-AR-003',
    'نظام المسار المغناطيسي المعماري الذكي 48V',
    'Smart 48V Magnetic Track Rail System',
    'cat_architectural',
    'إنارة معمارية ومخفية',
    12500.00,
    11200.00,
    7800.00,
    28,
    'https://images.unsplash.com/photo-1507473885765-e6ed057f782c?auto=format&fit=crop&w=800&q=80',
    'مسار مغناطيسي ذكي فائق النحافة يدعم تقنيات Zigbee و DALI للتحكم الكامل في توزيع الإضاءة.',
    TRUE,
    TRUE,
    FALSE,
    NULL
)
ON CONFLICT (id) DO NOTHING;

-- 3. Inventory Records
INSERT INTO inventory (id, product_id, warehouse_name, quantity_on_hand, quantity_reserved, reorder_threshold) VALUES
('inv_001', 'prod_crystal_palace', 'المستودع الرئيسي - الشيخ زايد', 12, 1, 3),
('inv_002', 'prod_nordic_minimal', 'المستودع الرئيسي - الشيخ زايد', 45, 0, 10),
('inv_003', 'prod_smart_magnetic', 'المستودع الرئيسي - الشيخ زايد', 28, 2, 5)
ON CONFLICT (id) DO NOTHING;

-- 4. Default Project Pricelist
INSERT INTO pricelists (id, name, code, currency, active) VALUES
('pl_contractors', 'قائمة أسعار المطورين والمشاريع الفاخرة', 'PROJECTS-VIP', 'EGP', TRUE)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pricelist_items (id, pricelist_id, product_id, tier_price, min_quantity) VALUES
('pli_001', 'pl_contractors', 'prod_crystal_palace', 36000.00, 3),
('pli_002', 'pl_contractors', 'prod_nordic_minimal', 3000.00, 10)
ON CONFLICT (id) DO NOTHING;

COMMIT;
