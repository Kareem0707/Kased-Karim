/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED
 * Storefront Checkout & Privacy-Protected Tracking Controller (js/checkout.js)
 * إدارة سلة الطلبات، التحقق الصارم من صحة البيانات، وإرسال وتتبع الطلبات السحابية
 */

(function () {
  "use strict";

  // Safe HTML Escaping Utility (XSS Prevention)
  window.escapeHtml = function (str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  };

  const formatPrice = window.formatPrice || function (num) {
    if (!num) return "0";
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  };

  const showToast = window.showToast || function (message) {
    const container = document.getElementById("toastContainer");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = "toast";
    toast.innerHTML = `<i class="fas fa-info-circle toast-icon"></i><span>${window.escapeHtml(message)}</span>`;
    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add("show"));
    setTimeout(() => {
      toast.classList.remove("show");
      setTimeout(() => toast.remove(), 400);
    }, 3500);
  };

  // --------------------------------------------------------------------------
  // 1. CHECKOUT MODAL CONTROLLER & CART RETRIEVAL
  // --------------------------------------------------------------------------
  function getCartItems() {
    if (window.STATE && Array.isArray(window.STATE.cart) && window.STATE.cart.length > 0) {
      return window.STATE.cart;
    }
    try {
      const saved = localStorage.getItem("kased_karim_quotation_cart");
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          if (window.STATE) {
            window.STATE.cart = parsed;
          } else {
            window.STATE = { cart: parsed };
          }
          return parsed;
        }
      }
    } catch (e) {}
    return [];
  }

  window.handleDeliveryAreaChange = function (areaId) {
    const areas = (window.KK_DB && typeof window.KK_DB.getDeliveryAreas === "function") 
      ? window.KK_DB.getDeliveryAreas() 
      : [];
    const area = areas.find(a => a.id === areaId);
    const areaError = document.getElementById("custAreaError");
    const submitBtn = document.getElementById("btnSubmitCheckout");
    const feeEl = document.getElementById("checkoutShippingFee");
    const subtotalEl = document.getElementById("checkoutSubtotalSum");
    const totalEl = document.getElementById("checkoutTotalSum");

    const cartItems = getCartItems();
    const subtotal = cartItems.reduce((sum, item) => sum + (item.price || 0) * (item.qty || 1), 0);
    if (subtotalEl) subtotalEl.textContent = `${formatPrice(subtotal)} ج.م`;

    if (!area || area.active === false) {
      if (areaError) areaError.style.display = "flex";
      if (submitBtn) submitBtn.disabled = true;
      if (feeEl) {
        feeEl.textContent = "غير متاح";
        feeEl.style.color = "#EF4444";
      }
      if (totalEl) totalEl.textContent = `${formatPrice(subtotal)} ج.م`;
      return;
    }

    if (areaError) areaError.style.display = "none";
    if (submitBtn) submitBtn.disabled = false;

    // Delivery fee rule (PRD Section 4 & 5): Free in Sheikh Zayed or orders >= 5,000 EGP
    let fee = Number(area.fee) || 0;
    if (area.id === "sheikh-zayed" || subtotal >= 5000) {
      fee = 0;
    }

    if (feeEl) {
      feeEl.textContent = fee === 0 ? "0 ج.م (مجاناً)" : `${formatPrice(fee)} ج.م`;
      feeEl.style.color = fee === 0 ? "#10B981" : "var(--text-main)";
    }

    const grandTotal = subtotal + fee;
    if (totalEl) {
      totalEl.textContent = `${formatPrice(grandTotal)} ج.م`;
    }
  };

  window.openCheckoutModal = function () {
    const cartItems = getCartItems();
    if (!cartItems || cartItems.length === 0) {
      showToast("سلة طلباتك فارغة! تفضل باختيار وحدات الإضاءة أولاً.");
      return;
    }

    // PRD Section 4: Customer account check before checkout (Guest cart preserved)
    const isCustomerLoggedIn = (window.KK_DB && typeof window.KK_DB.getCustomer === "function" && window.KK_DB.getCustomer()) ||
      (() => {
        try {
          const u = localStorage.getItem("kk_customer_user") || localStorage.getItem("kk_customer_account");
          return u ? JSON.parse(u) : null;
        } catch(e) { return null; }
      })();
    const isGuestApproved = sessionStorage.getItem("kk_guest_checkout") === "true";

    if (!isCustomerLoggedIn && !isGuestApproved && typeof window.openCustomerAuthModal === "function") {
      window.openCustomerAuthModal(() => {
        window.openCheckoutModal();
      });
      return;
    }

    if (typeof toggleCartDrawer === "function") {
      toggleCartDrawer(false);
    } else if (typeof closeCartDrawer === "function") {
      closeCartDrawer();
    }

    const modal = document.getElementById("checkoutModal");
    const summaryList = document.getElementById("checkoutSummaryList") || document.getElementById("checkoutItemsSummaryList");
    const subtotalEl = document.getElementById("checkoutSubtotalSum");
    const totalEl = document.getElementById("checkoutTotalSum") || document.getElementById("checkoutTotalSummary");

    const totalAmount = cartItems.reduce((sum, item) => sum + (item.price || 0) * (item.qty || 1), 0);
    if (subtotalEl) subtotalEl.textContent = `${formatPrice(totalAmount)} ج.م`;
    if (totalEl) totalEl.textContent = `${formatPrice(totalAmount)} ج.م`;

    if (summaryList) {
      summaryList.innerHTML = cartItems
        .map(
          item => `
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; padding: 0.45rem 0; border-bottom: 1px dashed var(--border-light); font-size: 0.85rem;">
          <div style="display: flex; align-items: center; gap: 0.5rem; overflow: hidden;">
            <img src="${window.escapeHtml(item.image)}" alt="${window.escapeHtml(item.name)}" style="width: 32px; height: 32px; border-radius: 4px; object-fit: cover;" onerror="this.src='https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=150&q=80'">
            <div style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 170px; font-weight: 700;">
              ${window.escapeHtml(item.name)}
            </div>
          </div>
          <div style="display: flex; align-items: center; gap: 0.65rem; white-space: nowrap;">
            <span style="font-size: 0.75rem; color: var(--text-muted);">× ${item.qty || 1}</span>
            <span style="font-weight: 800; color: var(--accent);">${formatPrice((item.price || 0) * (item.qty || 1))} ج.م</span>
          </div>
        </div>
      `
        )
        .join("");
    }

    // Populate Delivery Areas Dropdown
    const areaSelect = document.getElementById("custDeliveryAreaSelect");
    if (areaSelect && window.KK_DB && typeof window.KK_DB.getDeliveryAreas === "function") {
      const areas = window.KK_DB.getDeliveryAreas();
      if (areas && areas.length > 0) {
        const curVal = areaSelect.value || "sheikh-zayed";
        areaSelect.innerHTML = areas.map(a => `
          <option value="${window.escapeHtml(a.id)}" ${a.id === curVal ? 'selected' : ''}>
            ${window.escapeHtml(a.name)} (${a.fee === 0 ? 'توصيل مجاني' : a.fee + ' ج.م'} - ${window.escapeHtml(a.days || '1-3 أيام')})
          </option>
        `).join("") + `<option value="unsupported">محافظة أخرى (خارج نطاق التغطية الحالي)</option>`;
      }
    }

    // Auto-fill logged in customer data or saved details
    const nameInput = document.getElementById("custNameInput") || document.getElementById("checkoutCustomerName");
    const phoneInput = document.getElementById("custPhoneInput") || document.getElementById("checkoutCustomerPhone");
    const addressInput = document.getElementById("custAddressInput") || document.getElementById("checkoutCustomerAddress");

    if (isCustomerLoggedIn) {
      if (nameInput) nameInput.value = isCustomerLoggedIn.name || nameInput.value || "";
      if (phoneInput && !phoneInput.value) phoneInput.value = isCustomerLoggedIn.phone || "";
    } else {
      try {
        const savedName = localStorage.getItem("kk_customer_name");
        const savedPhone = localStorage.getItem("kk_customer_phone");
        if (nameInput && !nameInput.value && savedName) nameInput.value = savedName;
        if (phoneInput && !phoneInput.value && savedPhone) phoneInput.value = savedPhone;
      } catch (e) {}
    }

    // Calculate initial fee & grand total
    if (areaSelect) {
      handleDeliveryAreaChange(areaSelect.value);
    }

    if (modal) {
      modal.classList.add("active");
      document.body.style.overflow = "hidden";
      setTimeout(() => {
        if (nameInput && nameInput.value.trim().length >= 3) {
          if (phoneInput && !phoneInput.value.trim()) {
            phoneInput.focus();
          } else if (addressInput) {
            addressInput.focus();
          }
        } else if (nameInput) {
          nameInput.focus();
        }
      }, 120);
    }
  };

  window.closeCheckoutModal = function () {
    const modal = document.getElementById("checkoutModal");
    if (modal) {
      modal.classList.remove("active");
      document.body.style.overflow = "";
    }
  };

  // --------------------------------------------------------------------------
  // 2. CHECKOUT FIELD VALIDATION (Strict Dual-Name, 11-digit Phone, 15-char Address)
  // --------------------------------------------------------------------------
  window.validateCustomerName = function (name) {
    if (!name || typeof name !== "string") {
      return { valid: false, message: "⚠️ يرجى كتابة اسم العميل الكريم بالكامل" };
    }
    const clean = name.trim().replace(/\s+/g, " ");
    const parts = clean.split(" ").filter(p => p.replace(/[.\-_]/g, "").length >= 2);
    if (parts.length < 2) {
      return {
        valid: false,
        message: "⚠️ يرجى كتابة أول اسمين على الأقل للعميل لضمان تسجيل الطلب بشكل صحيح",
        cleanName: clean
      };
    }
    return { valid: true, cleanName: clean };
  };

  window.validateCustomerPhone = function (phone) {
    if (!phone) {
      return { valid: false, message: "⚠️ يرجى إدخال رقم الهاتف المحمول" };
    }
    const clean = phone.replace(/[^0-9]/g, "");
    if (clean.length < 11) {
      return {
        valid: false,
        message: `⚠️ رقم الهاتف ناقص (${clean.length} أرقام فقط)! يجب إدخال 11 رقماً كاملاً (مثال: 01012345678)`,
        cleanPhone: clean
      };
    }
    if (clean.length > 11) {
      return {
        valid: false,
        message: "⚠️ رقم الهاتف زائد عن 11 رقماً! يرجى التأكد من الرقم",
        cleanPhone: clean
      };
    }
    if (!clean.startsWith("01")) {
      return {
        valid: false,
        message: "⚠️ يجب أن يبدأ رقم الهاتف المصري بـ 01 (مثال: 010 أو 011 أو 012 أو 015)",
        cleanPhone: clean
      };
    }
    return { valid: true, cleanPhone: clean };
  };

  window.validateCustomerAddress = function (address) {
    if (!address || typeof address !== "string") {
      return { valid: false, message: "⚠️ يرجى إدخال عنوان التسليم بالتفصيل" };
    }
    const clean = address.trim();
    if (clean.length < 15) {
      return {
        valid: false,
        message: `⚠️ تفاصيل العنوان قصيرة (${clean.length} حرفاً)! يجب ألا يقل العنوان عن 15 حرفاً (مثال: كمبوند بيفرلي هيلز - فيلا 42)`,
        cleanAddress: clean
      };
    }
    return { valid: true, cleanAddress: clean };
  };

  function setupCheckoutLiveValidation() {
    const nameInput = document.getElementById("custNameInput") || document.getElementById("checkoutCustomerName");
    const phoneInput = document.getElementById("custPhoneInput") || document.getElementById("checkoutCustomerPhone");
    const addressInput = document.getElementById("custAddressInput") || document.getElementById("checkoutCustomerAddress");
    const addressCounter = document.getElementById("custAddressCounter");

    const nameError = document.getElementById("custNameError") || document.getElementById("checkoutNameError");
    const phoneError = document.getElementById("custPhoneError") || document.getElementById("checkoutPhoneError");
    const addressError = document.getElementById("custAddressError") || document.getElementById("checkoutAddressError");

    if (nameInput && !nameInput.dataset.hasListener) {
      nameInput.dataset.hasListener = "true";
      nameInput.addEventListener("input", () => {
        const val = validateCustomerName(nameInput.value);
        if (val.valid) {
          nameInput.classList.remove("is-invalid");
          nameInput.classList.add("is-valid");
          if (nameError) nameError.classList.remove("show");
        } else if (nameInput.value.trim().length > 3) {
          nameInput.classList.remove("is-valid");
        }
      });
    }

    if (phoneInput && !phoneInput.dataset.hasListener) {
      phoneInput.dataset.hasListener = "true";
      phoneInput.addEventListener("input", () => {
        phoneInput.value = phoneInput.value.replace(/[^0-9]/g, "");
        const val = validateCustomerPhone(phoneInput.value);
        if (val.valid) {
          phoneInput.classList.remove("is-invalid");
          phoneInput.classList.add("is-valid");
          if (phoneError) phoneError.classList.remove("show");
        } else if (phoneInput.value.length >= 11) {
          phoneInput.classList.add("is-invalid");
          phoneInput.classList.remove("is-valid");
          if (phoneError) {
            const span = phoneError.querySelector("span") || phoneError;
            span.textContent = val.message;
            phoneError.classList.add("show");
          }
        }
      });
    }

    if (addressInput && !addressInput.dataset.hasListener) {
      addressInput.dataset.hasListener = "true";
      addressInput.addEventListener("input", () => {
        const len = addressInput.value.trim().length;
        if (addressCounter) {
          if (len >= 15) {
            addressCounter.textContent = `✓ ${len} حرفاً (مكتمل)`;
            addressCounter.className = "form-char-counter valid";
          } else {
            addressCounter.textContent = `${len} / 15 حرفاً كحد أدنى`;
            addressCounter.className = "form-char-counter invalid";
          }
        }

        const val = validateCustomerAddress(addressInput.value);
        if (val.valid) {
          addressInput.classList.remove("is-invalid");
          addressInput.classList.add("is-valid");
          if (addressError) addressError.classList.remove("show");
        } else if (len >= 15) {
          addressInput.classList.remove("is-invalid");
        }
      });
    }
  }

  // --------------------------------------------------------------------------
  // 3. SECURE CHECKOUT SUBMISSION (Awaiting Central Server Confirmation)
  // --------------------------------------------------------------------------
  window.handleCheckoutSubmit = async function (e) {
    if (e) e.preventDefault();

    const submitBtn = document.getElementById("btnSubmitCheckout") || document.getElementById("checkoutSubmitBtn");
    if (submitBtn && submitBtn.disabled) return;

    const form = e ? e.target : document.getElementById("checkoutOrderForm");
    const nameInput = document.getElementById("custNameInput") || form?.custName || document.getElementById("checkoutCustomerName");
    const phoneInput = document.getElementById("custPhoneInput") || form?.custPhone || document.getElementById("checkoutCustomerPhone");
    const addressInput = document.getElementById("custAddressInput") || form?.custAddress || document.getElementById("checkoutCustomerAddress");
    const notesInput = form?.custNotes || document.querySelector("textarea[name='custNotes']") || document.getElementById("checkoutCustomerNotes");

    const rawName = (nameInput ? nameInput.value : "").trim();
    const rawPhone = (phoneInput ? phoneInput.value : "").trim();
    const rawAddress = (addressInput ? addressInput.value : "").trim();
    const rawNotes = (notesInput ? notesInput.value : "").trim();

    const nameVal = validateCustomerName(rawName);
    const phoneVal = validateCustomerPhone(rawPhone);
    const addressVal = validateCustomerAddress(rawAddress);

    const nameError = document.getElementById("custNameError") || document.getElementById("checkoutNameError");
    const phoneError = document.getElementById("custPhoneError") || document.getElementById("checkoutPhoneError");
    const addressError = document.getElementById("custAddressError") || document.getElementById("checkoutAddressError");

    let hasError = false;

    if (!nameVal.valid) {
      hasError = true;
      if (nameInput) {
        nameInput.classList.add("is-invalid");
        nameInput.classList.remove("is-valid");
      }
      if (nameError) {
        const span = nameError.querySelector("span") || nameError;
        span.textContent = nameVal.message;
        nameError.classList.add("show");
      }
    } else {
      if (nameInput) {
        nameInput.classList.remove("is-invalid");
        nameInput.classList.add("is-valid");
      }
      if (nameError) nameError.classList.remove("show");
    }

    if (!phoneVal.valid) {
      hasError = true;
      if (phoneInput) {
        phoneInput.classList.add("is-invalid");
        phoneInput.classList.remove("is-valid");
      }
      if (phoneError) {
        const span = phoneError.querySelector("span") || phoneError;
        span.textContent = phoneVal.message;
        phoneError.classList.add("show");
      }
    } else {
      if (phoneInput) {
        phoneInput.classList.remove("is-invalid");
        phoneInput.classList.add("is-valid");
      }
      if (phoneError) phoneError.classList.remove("show");
    }

    if (!addressVal.valid) {
      hasError = true;
      if (addressInput) {
        addressInput.classList.add("is-invalid");
        addressInput.classList.remove("is-valid");
      }
      if (addressError) {
        const span = addressError.querySelector("span") || addressError;
        span.textContent = addressVal.message;
        addressError.classList.add("show");
      }
    } else {
      if (addressInput) {
        addressInput.classList.remove("is-invalid");
        addressInput.classList.add("is-valid");
      }
      if (addressError) addressError.classList.remove("show");
    }

    if (hasError) {
      if (!nameVal.valid) {
        nameInput?.focus();
        showToast(nameVal.message);
      } else if (!phoneVal.valid) {
        phoneInput?.focus();
        showToast(phoneVal.message);
      } else if (!addressVal.valid) {
        addressInput?.focus();
        showToast(addressVal.message);
      }
      return;
    }

    const cartItems = getCartItems();
    if (!cartItems || cartItems.length === 0) {
      showToast("⚠️ سلة طلباتك فارغة! تفضل باختيار وحدات الإضاءة أولاً.");
      return;
    }

    if (!window.KK_DB) {
      showToast("⚠️ جاري تهيئة الاتصال السحابي، يرجى المحاولة بعد لحظات...");
      return;
    }

    // PRD Section 4 & 5: Validate Delivery Area and calculate breakdown
    const areaSelect = document.getElementById("custDeliveryAreaSelect");
    const selectedAreaId = areaSelect ? areaSelect.value : "sheikh-zayed";
    const areas = (window.KK_DB && typeof window.KK_DB.getDeliveryAreas === "function") 
      ? window.KK_DB.getDeliveryAreas() 
      : [];
    const selectedArea = areas.find(a => a.id === selectedAreaId);

    if (!selectedArea || selectedArea.active === false || selectedAreaId === "unsupported") {
      const areaErr = document.getElementById("custAreaError");
      if (areaErr) areaErr.style.display = "flex";
      showToast("⚠️ عفواً، التوصيل غير متاح حالياً لهذه المنطقة وفق لوائح التوزيع المعتمدة.");
      return;
    }

    const subtotal = cartItems.reduce((sum, item) => sum + (item.price || 0) * (item.qty || 1), 0);
    let shippingFee = Number(selectedArea.fee) || 0;
    if (selectedArea.id === "sheikh-zayed" || subtotal >= 5000) {
      shippingFee = 0;
    }
    const grandTotal = subtotal + shippingFee;

    const currentCustomer = (window.KK_DB && typeof window.KK_DB.getCustomer === "function") 
      ? window.KK_DB.getCustomer() 
      : null;

    const customerData = {
      name: nameVal.cleanName,
      phone: phoneVal.cleanPhone,
      city: selectedArea.name || "الشيخ زايد",
      deliveryArea: selectedArea.id,
      deliveryAreaName: selectedArea.name,
      shippingFee: shippingFee,
      subtotal: subtotal,
      total: grandTotal,
      address: addressVal.cleanAddress,
      notes: rawNotes,
      customerId: currentCustomer ? currentCustomer.id : null,
      customerEmail: currentCustomer ? currentCustomer.email : null,
      paymentMethod: "cod",
      paymentStatus: "uncollected"
    };

    const originalBtnHtml = submitBtn ? submitBtn.innerHTML : "";
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> <span>جارٍ تأكيد الطلب وحجزه سحابياً...</span>`;
    }

    try {
      const newOrder = await window.KK_DB.createOrder(customerData, cartItems);

      if (newOrder && newOrder.id) {
        closeCheckoutModal();

        // Clear cart everywhere
        if (window.STATE) window.STATE.cart = [];
        localStorage.removeItem("kased_karim_quotation_cart");
        if (typeof updateCartUI === "function") updateCartUI();
        if (typeof saveCart === "function") saveCart();

        // Save customer details for fast future orders
        try {
          localStorage.setItem("kk_customer_name", customerData.name);
          localStorage.setItem("kk_customer_phone", customerData.phone);
        } catch(e) {}

        // Save order ID and phone on customer device
        saveCustomerRecentOrder(newOrder.id, customerData.phone);

        // Open order success confirmation modal
        openOrderSuccessModal(newOrder);
      } else {
        throw new Error("لم نتمكن من الحصول على تأكيد رقم الطلب من الخادم");
      }
    } catch (err) {
      showToast(`❌ تعذر إرسال الطلب: ${err.message || "يرجى التحقق من الاتصال بالإنترنت"}`);
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnHtml;
      }
    }
  };

  // --------------------------------------------------------------------------
  // 4. ORDER SUCCESS CONFIRMATION MODAL & WHATSAPP DISPATCH
  // --------------------------------------------------------------------------
  window.generateOrderWhatsAppMessage = function (order) {
    if (!order) return "";
    const customer = (order.customer && typeof order.customer === "object") 
      ? order.customer 
      : (typeof order.customer === "string" ? { name: order.customer } : {});

    const items = Array.isArray(order.items) 
      ? order.items 
      : (order.items && typeof order.items === "object" ? Object.values(order.items) : []);

    const itemsList = items
      .map((it, idx) => `• *${it.name || it.title || 'وحدة إضاءة'}* (عدد: ${it.qty || it.quantity || 1}) - ${formatPrice((it.price || 0) * (it.qty || it.quantity || 1))} ج.م`)
      .join("\n");

    const trackUrl = `${window.location.origin}/?track=${encodeURIComponent(order.id)}`;

    let msg = `*طلب حجز جديد من معرض قاصد كريم للإضاءة الفاخرة* 💎\n`;
    msg += `----------------------------------------\n`;
    msg += `🏷️ *كود الطلب المعتمد:* #${order.id}\n`;
    if (customer.name) msg += `👤 *اسم العميل:* ${customer.name}\n`;
    if (customer.phone) msg += `📞 *رقم الهاتف:* ${customer.phone}\n`;
    if (customer.address) msg += `📍 *العنوان:* ${customer.address}\n`;
    if (customer.notes) msg += `📝 *ملاحظات:* ${customer.notes}\n`;
    msg += `----------------------------------------\n`;
    msg += `🛒 *وحدات الإضاءة المطلوبة:*\n${itemsList || "• وحدات مختارة من الكتالوج"}\n`;
    msg += `----------------------------------------\n`;
    msg += `💰 *إجمالي قيمة الطلب:* ${formatPrice(order.total || 0)} جنيه مصري\n`;
    msg += `🔗 *رابط مسار وتتبع الطلب:* ${trackUrl}\n`;
    msg += `----------------------------------------\n`;
    msg += `يرجى تأكيد استلام الحجز وتحديد موعد المعاينة والتسليم بالمعرض بالشيخ زايد.`;

    return msg;
  };

  window.sendOrderViaWhatsApp = function (order) {
    if (!order) return;
    const msg = window.generateOrderWhatsAppMessage(order);
    const waNumber = (window.SHOWROOM_INFO && window.SHOWROOM_INFO.whatsapp) || "201006367690";
    const url = `https://wa.me/${waNumber}?text=${encodeURIComponent(msg)}`;
    window.open(url, "_blank");
  };

  window.sendCurrentOrderViaWhatsApp = function () {
    const order = window.lastPlacedOrderObj;
    if (order) {
      window.sendOrderViaWhatsApp(order);
    } else if (window.lastPlacedOrderId) {
      const orders = window.KK_DB ? window.KK_DB.getOrders() : [];
      const found = orders.find(o => o.id === window.lastPlacedOrderId);
      if (found) {
        window.sendOrderViaWhatsApp(found);
      } else {
        const waNumber = (window.SHOWROOM_INFO && window.SHOWROOM_INFO.whatsapp) || "201006367690";
        const url = `https://wa.me/${waNumber}?text=${encodeURIComponent(`مرحباً معرض قاصد كريم بالشيخ زايد، أود تأكيد واستلام طلبي رقم #${window.lastPlacedOrderId}.`)}`;
        window.open(url, "_blank");
      }
    }
  };

  window.contactSupportAboutTrackedOrder = function (customQuery = null) {
    const targetId = customQuery || window.currentTrackedOrderId || window.lastPlacedOrderId;
    let order = null;
    if (window.KK_DB && targetId) {
      order = window.KK_DB.getOrders().find(o => o.id === targetId);
    }
    if (order) {
      window.sendOrderViaWhatsApp(order);
    } else {
      const waNumber = (window.SHOWROOM_INFO && window.SHOWROOM_INFO.whatsapp) || "201006367690";
      const msg = `مرحباً معرض قاصد كريم بالشيخ زايد، أود الاستفسار عن تفاصيل وحالة طلبي رقم #${targetId || 'طلب إضاءة'}. هل يمكنكم إفادتي بآخر المستجدات وموعد المعاينة والتوصيل؟`;
      const url = `https://wa.me/${waNumber}?text=${encodeURIComponent(msg)}`;
      window.open(url, "_blank");
    }
  };

  window.openOrderSuccessModal = function (order) {
    const modal = document.getElementById("orderSuccessModal");
    const idEl = document.getElementById("successOrderId");
    const totalEl = document.getElementById("successOrderTotal");

    if (idEl) idEl.textContent = `#${order.id}`;
    if (totalEl) totalEl.textContent = `${formatPrice(order.total)} ج.م`;

    window.lastPlacedOrderId = order.id;
    window.lastPlacedOrderObj = order;

    // Update WhatsApp Button Link
    const waBtn = document.getElementById("btnSendOrderViaWhatsApp");
    if (waBtn) {
      const waNumber = (window.SHOWROOM_INFO && window.SHOWROOM_INFO.whatsapp) || "201006367690";
      const msg = window.generateOrderWhatsAppMessage(order);
      waBtn.href = `https://wa.me/${waNumber}?text=${encodeURIComponent(msg)}`;
    }

    if (modal) {
      modal.classList.add("active");
      document.body.style.overflow = "hidden";
    }
  };

  window.closeOrderSuccessModal = function () {
    const modal = document.getElementById("orderSuccessModal");
    if (modal) {
      modal.classList.remove("active");
      document.body.style.overflow = "";
    }
  };

  window.trackOrderFromSuccessModal = function () {
    const orderId = window.lastPlacedOrderId;
    closeOrderSuccessModal();
    if (orderId) {
      openTrackOrderModal(orderId);
    }
  };

  // --------------------------------------------------------------------------
  // 5. PRIVACY-PROTECTED ORDER TRACKING MODAL (Multi-Factor Verification)
  // --------------------------------------------------------------------------
  window.openTrackOrderModal = function (targetOrderId = null) {
    const modal = document.getElementById("trackOrderModal");
    if (!modal) return;

    renderCustomerRecentOrderChips();

    const searchInput = document.getElementById("trackSearchInput");
    const savedId = targetOrderId || localStorage.getItem("kk_last_placed_order_id") || "";
    const savedPhone = localStorage.getItem("kk_customer_phone") || "";

    if (savedId && searchInput) {
      searchInput.value = savedId;
      loadAndRenderTrackOrder(savedId, savedPhone);
    } else {
      const emptyState = document.getElementById("trackEmptyState");
      const resultBox = document.getElementById("trackResultContainer");
      if (emptyState) emptyState.style.display = "block";
      if (resultBox) resultBox.style.display = "none";
    }

    modal.classList.add("active");
    document.body.style.overflow = "hidden";
  };

  window.closeTrackOrderModal = function () {
    const modal = document.getElementById("trackOrderModal");
    if (modal) {
      modal.classList.remove("active");
      document.body.style.overflow = "";
    }
  };

  window.searchAndTrackOrder = function () {
    const orderInput = document.getElementById("trackSearchInput");
    const rawVal = orderInput ? orderInput.value.trim() : "";

    if (!rawVal) {
      showToast("⚠️ يرجى إدخال رقم الطلب (مثال: ORD-XXXX-XXXX)");
      orderInput?.focus();
      return;
    }

    let orderId = rawVal;
    let phone = localStorage.getItem("kk_customer_phone") || "";

    // If customer entered phone number instead of order ID, prompt for order ID
    if (/^01[0-9]{9}$/.test(rawVal.replace(/[^0-9]/g, ""))) {
      phone = rawVal.replace(/[^0-9]/g, "");
      localStorage.setItem("kk_customer_phone", phone);
      const recent = JSON.parse(localStorage.getItem("kk_customer_recent_orders") || "[]");
      if (recent.length > 0) {
        orderId = recent[0];
        if (orderInput) orderInput.value = orderId;
      } else {
        const inputId = prompt("يرجى إدخال كود الطلب الخاص بك (مثال: ORD-XXXX):");
        if (!inputId) return;
        orderId = inputId.trim();
        if (orderInput) orderInput.value = orderId;
      }
    }

    loadAndRenderTrackOrder(orderId, phone);
  };

  window.loadAndRenderTrackOrder = async function (orderId, phone = "") {
    if (!orderId) return;

    const emptyState = document.getElementById("trackEmptyState");
    const resultBox = document.getElementById("trackResultContainer");
    const cleanId = orderId.toUpperCase().replace(/[#]/g, "").trim();

    try {
      const custToken = window.KK_DB ? window.KK_DB.getCustomerToken() : null;
      const headers = { "Content-Type": "application/json" };
      if (custToken) headers["Authorization"] = `Bearer ${custToken}`;

      const sendPhone = phone || (window.KK_DB && window.KK_DB.getCustomer() ? window.KK_DB.getCustomer().phone : "") || localStorage.getItem("kk_customer_phone") || "";

      const res = await fetch("/api/track", {
        method: "POST",
        headers,
        body: JSON.stringify({ orderId: cleanId, phone: sendPhone })
      });

      const data = await res.json();

      if (res.ok && data.success && data.order) {
        renderTrackedOrderUI(data.order);
        saveCustomerRecentOrder(data.order.id, phone);
      } else if (data.requirePhoneVerification) {
        // Customer requested order tracking, require matching phone verification
        const enteredPhone = prompt("لأمان وخصوصية بياناتك، يرجى إدخال رقم الهاتف المسجل لتأكيد تتبع الطلب:");
        if (enteredPhone) {
          loadAndRenderTrackOrder(cleanId, enteredPhone.trim());
        }
      } else {
        // Show Safe Error State (No XSS, TextContent only)
        if (resultBox) resultBox.style.display = "none";
        if (emptyState) {
          emptyState.style.display = "block";
          emptyState.innerHTML = "";

          const icon = document.createElement("i");
          icon.className = "fas fa-shield-halved";
          icon.style.cssText = "font-size: 2.2rem; color: #F59E0B; margin-bottom: 0.75rem; display: block;";

          const heading = document.createElement("h4");
          heading.style.cssText = "color: var(--text-main); margin-bottom: 0.35rem; font-weight: 700;";
          heading.textContent = data.error || "تعذر العثور على الطلب";

          const desc = document.createElement("p");
          desc.style.cssText = "color: var(--text-muted); font-size: 0.82rem; margin: 0 0 1rem 0;";
          desc.textContent = "لأمان وخصوصية بياناتك، يرجى كتابة كود الطلب كاملاً ورقم الهاتف المسجل للمعاينة وتتبع المراحل.";

          const waBtn = document.createElement("button");
          waBtn.type = "button";
          waBtn.className = "btn-whatsapp-customer";
          waBtn.style.cssText = "margin: 0 auto; padding: 0.5rem 1rem; font-size: 0.8rem;";
          waBtn.innerHTML = `<i class="fab fa-whatsapp"></i> استفسار المعرض عبر واتساب`;
          waBtn.addEventListener("click", () => {
            const waNumber = window.SHOWROOM_INFO?.whatsapp || "201006367690";
            const text = encodeURIComponent(`مرحباً معرض قاصد كريم، أود الاستفسار عن حالة طلبي رقم #${cleanId}.`);
            window.open(`https://wa.me/${waNumber}?text=${text}`, "_blank");
          });

          emptyState.appendChild(icon);
          emptyState.appendChild(heading);
          emptyState.appendChild(desc);
          emptyState.appendChild(waBtn);
        }
        showToast(data.error || "لم يتم العثور على طلب بهذه البيانات");
      }
    } catch (err) {
      showToast("تعذر الاتصال بمركز التتبع السحابي، يرجى المحاولة لاحقاً");
    }
  };

  function renderTrackedOrderUI(order) {
    window.renderTrackedOrderUI = renderTrackedOrderUI;
    window.currentTrackedOrderId = order.id;

    const emptyState = document.getElementById("trackEmptyState");
    const resultBox = document.getElementById("trackResultContainer");
    if (emptyState) emptyState.style.display = "none";
    if (resultBox) resultBox.style.display = "block";

    // Header Details (Safely assigned via textContent)
    const idDisplay = document.getElementById("trackOrderIdDisplay");
    const dateDisplay = document.getElementById("trackOrderDateDisplay");
    const totalSum = document.getElementById("trackOrderTotalSum");

    if (idDisplay) idDisplay.textContent = `#${order.id}`;
    if (dateDisplay) {
      dateDisplay.innerHTML = `<i class="fas fa-clock"></i> تم التسجيل: ${window.escapeHtml(order.dateFormatted)}`;
    }
    if (totalSum) totalSum.textContent = `${formatPrice(order.total)} ج.م`;

    // Render Items List Safely
    const itemsContainer = document.getElementById("trackItemsList");
    if (itemsContainer) {
      itemsContainer.innerHTML = (order.items || [])
        .map(
          item => `
        <div style="display: flex; align-items: center; justify-content: space-between; background: #FFFFFF; border: 1px solid var(--border-light); border-radius: var(--radius-sm); padding: 0.6rem 0.85rem;">
          <div style="display: flex; align-items: center; gap: 0.65rem;">
            <img src="${window.escapeHtml(item.image)}" alt="${window.escapeHtml(item.name)}" style="width: 42px; height: 42px; border-radius: 6px; object-fit: cover;" onerror="this.src='https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=300&q=80'">
            <div>
              <div style="font-weight: 700; font-size: 0.85rem; color: var(--text-main);">${window.escapeHtml(item.name)}</div>
              <div style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-brand);">${window.escapeHtml(item.categoryName || 'إضاءة فاخرة')} • الكمية: ${item.qty}</div>
            </div>
          </div>
          <div style="font-weight: 800; font-size: 0.85rem; color: var(--accent-hover);">${formatPrice(item.price * item.qty)} ج.م</div>
        </div>
      `
        )
        .join("");
    }

    // 5-Stage Stepper
    const steps = [
      document.getElementById("step1"),
      document.getElementById("step2"),
      document.getElementById("step3"),
      document.getElementById("step4"),
      document.getElementById("step5")
    ];
    const stepperFill = document.getElementById("trackStepperFill");
    const badgeDisplay = document.getElementById("trackStatusBadgeDisplay");
    const msgBox = document.getElementById("trackStatusMessageBox");
    const msgText = document.getElementById("trackStatusMessageText");

    steps.forEach(s => s && s.classList.remove("active", "completed"));

    const status = order.status || "pending";

    if (status === "pending") {
      if (stepperFill) stepperFill.style.width = "10%";
      if (steps[0]) steps[0].classList.add("active");
      if (badgeDisplay) {
        badgeDisplay.className = "status-badge-live status-pending";
        badgeDisplay.innerHTML = `<i class="fas fa-clock"></i> قيد المراجعة والاستلام`;
      }
      if (msgBox) {
        msgBox.style.background = "#FFFBEB";
        msgBox.style.borderColor = "#FDE68A";
        msgBox.style.color = "#92400E";
      }
      if (msgText) msgText.textContent = order.statusMessage || "تم استلام الطلب وقيد التأكيد بمعرض قاصد كريم بالشيخ زايد.";
    } else if (status === "confirmed") {
      if (stepperFill) stepperFill.style.width = "35%";
      if (steps[0]) steps[0].classList.add("completed");
      if (steps[1]) steps[1].classList.add("active");
      if (badgeDisplay) {
        badgeDisplay.className = "status-badge-live status-confirmed";
        badgeDisplay.innerHTML = `<i class="fas fa-check-double"></i> تم تأكيد الطلب بالمعرض`;
      }
      if (msgBox) {
        msgBox.style.background = "#EFF6FF";
        msgBox.style.borderColor = "#BFDBFE";
        msgBox.style.color = "#1E40AF";
      }
      if (msgText) msgText.textContent = order.statusMessage || "تم تأكيد طلبك وجارٍ تجهيز وحدات الإضاءة بالمعرض.";
    } else if (status === "processing") {
      if (stepperFill) stepperFill.style.width = "60%";
      if (steps[0]) steps[0].classList.add("completed");
      if (steps[1]) steps[1].classList.add("completed");
      if (steps[2]) steps[2].classList.add("active");
      if (badgeDisplay) {
        badgeDisplay.className = "status-badge-live status-processing";
        badgeDisplay.innerHTML = `<i class="fas fa-boxes-packing"></i> جارٍ التجهيز والفحص`;
      }
      if (msgBox) {
        msgBox.style.background = "#F5F3FF";
        msgBox.style.borderColor = "#DDD6FE";
        msgBox.style.color = "#5B21B6";
      }
      if (msgText) msgText.textContent = order.statusMessage || "جارٍ فحص المواصفات الفنية وتغليف الوحدات بعناية فائقة.";
    } else if (status === "shipped") {
      if (stepperFill) stepperFill.style.width = "85%";
      if (steps[0]) steps[0].classList.add("completed");
      if (steps[1]) steps[1].classList.add("completed");
      if (steps[2]) steps[2].classList.add("completed");
      if (steps[3]) steps[3].classList.add("active");
      if (badgeDisplay) {
        badgeDisplay.className = "status-badge-live status-shipped";
        badgeDisplay.innerHTML = `<i class="fas fa-truck-fast"></i> مع مندوب المعرض`;
      }
      if (msgBox) {
        msgBox.style.background = "#FFF7ED";
        msgBox.style.borderColor = "#FED7AA";
        msgBox.style.color = "#9A3412";
      }
      if (msgText) msgText.textContent = order.statusMessage || "الطلب في طريقه إليكم مع مندوب المعرض المعتمد.";
    } else if (status === "delivered" || status === "completed") {
      if (stepperFill) stepperFill.style.width = "100%";
      steps.forEach(s => s && s.classList.add("completed"));
      if (badgeDisplay) {
        badgeDisplay.className = "status-badge-live status-delivered";
        badgeDisplay.innerHTML = `<i class="fas fa-circle-check"></i> تم التسليم بنجاح`;
      }
      if (msgBox) {
        msgBox.style.background = "#F0FDF4";
        msgBox.style.borderColor = "#BBF7D0";
        msgBox.style.color = "#166534";
      }
      if (msgText) msgText.textContent = order.statusMessage || "تم تسليم الطلب بنجاح. شكراً لثقتكم بمعرض قاصد كريم.";
    }
  }

  // --------------------------------------------------------------------------
  // 6. CUSTOMER RECENT ORDERS CHIPS (Private to Customer Device)
  // --------------------------------------------------------------------------
  window.renderCustomerRecentOrderChips = function () {
    const wrap = document.getElementById("trackRecentOrdersWrap");
    const container = document.getElementById("trackRecentOrdersChips");
    if (!wrap || !container) return;

    try {
      const recent = JSON.parse(localStorage.getItem("kk_customer_recent_orders") || "[]");
      if (recent.length > 0) {
        wrap.style.display = "block";
        container.innerHTML = "";
        recent.forEach(id => {
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = `track-chip-btn ${id === window.currentTrackedOrderId ? "active" : ""}`;
          btn.innerHTML = `<i class="fas fa-tag"></i> #${window.escapeHtml(id)}`;
          btn.addEventListener("click", () => {
            const savedPhone = localStorage.getItem("kk_customer_phone") || "";
            const searchInput = document.getElementById("trackSearchInput");
            if (searchInput) searchInput.value = id;
            loadAndRenderTrackOrder(id, savedPhone);
          });
          container.appendChild(btn);
        });
      } else {
        wrap.style.display = "none";
      }
    } catch (e) {
      wrap.style.display = "none";
    }
  };

  window.saveCustomerRecentOrder = function (orderId, phone = "") {
    try {
      const recent = JSON.parse(localStorage.getItem("kk_customer_recent_orders") || "[]");
      if (!recent.includes(orderId)) {
        recent.unshift(orderId);
        localStorage.setItem("kk_customer_recent_orders", JSON.stringify(recent.slice(0, 8)));
      }
      localStorage.setItem("kk_last_placed_order_id", orderId);
      if (phone) {
        localStorage.setItem("kk_customer_phone", phone);
      }
      renderCustomerRecentOrderChips();
      updateCustomerTrackingBadge();
    } catch (e) {}
  };

  window.updateCustomerTrackingBadge = function () {
    const badge = document.getElementById("trackBadgeHeader");
    if (!badge) return;
    try {
      const recent = JSON.parse(localStorage.getItem("kk_customer_recent_orders") || "[]");
      if (recent.length > 0) {
        badge.style.display = "flex";
        badge.textContent = recent.length;
      } else {
        badge.style.display = "none";
      }
    } catch (e) {
      badge.style.display = "none";
    }
  };

  window.refreshCurrentTrackOrder = function (btn) {
    if (window.currentTrackedOrderId) {
      const savedPhone = localStorage.getItem("kk_customer_phone") || "";
      loadAndRenderTrackOrder(window.currentTrackedOrderId, savedPhone);
      showToast("تم تحديث حالة الطلب");
    }
  };

  window.continueCheckoutAsGuest = function () {
    sessionStorage.setItem("kk_guest_checkout", "true");
    if (typeof window.closeCustomerAuthModal === "function") {
      window.closeCustomerAuthModal();
    }
    window.openCheckoutModal();
  };

  // --------------------------------------------------------------------------
  // 7. INITIALIZATION & ACCESSIBILITY LISTENERS
  // --------------------------------------------------------------------------
  document.addEventListener("DOMContentLoaded", function () {
    setupCheckoutLiveValidation();
    updateCustomerTrackingBadge();

    const checkoutForm = document.getElementById("checkoutOrderForm");
    if (checkoutForm && !checkoutForm.getAttribute("onsubmit")) {
      checkoutForm.addEventListener("submit", handleCheckoutSubmit);
    }

    // Modal Close on Escape Key
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        closeCheckoutModal();
        closeOrderSuccessModal();
        closeTrackOrderModal();
        if (typeof closeQuickView === "function") closeQuickView();
        if (typeof closeCartDrawer === "function") closeCartDrawer();
      }
    });
  });
})();
