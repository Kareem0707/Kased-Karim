/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED
 * Dedicated Bilingual Internationalization & Localization Engine (js/i18n.js)
 * PRD Section 7: Arabic (RTL) & English (LTR) Native Storefront Support
 */

(function () {
  "use strict";

  const STORAGE_KEY = "kk_lang";

  const TRANSLATIONS = {
    ar: {
      // General & Brand
      brandName: "قاصد كريم",
      brandFullName: "معرض قاصد كريم للإضاءة الفاخرة",
      tagline: "أيقونة الإضاءة الفاخرة والمعمارية - الشيخ زايد",
      locationBadge: "الشيخ زايد - سنتر الطاهرة",
      phone: "01006367690",
      currency: "ج.م",
      currencyFullName: "جنيه مصري",
      cashOnDelivery: "الدفع نقدياً عند الاستلام",
      codUncollected: "الدفع نقدياً عند الاستلام — لم يتم التحصيل بعد",
      inStock: "متوفر بالمعرض",
      outOfStock: "غير متوفر حالياً",
      warranty: "ضمان",
      years: "سنوات",
      viewDetails: "معاينة سريعة",
      addToCart: "إضافة للسلة",
      buyNow: "شراء وتأكيد فوري",
      searchPlaceholder: "ابحث عن ثريات، أباليك، مسارات مغناطيسية، أباجورات...",
      allCategories: "الكل المعروض",
      exclusive: "حصري",
      newTag: "جديد",

      // Top bar & Nav
      showroomCity: "الشيخ زايد: 01006367690",
      navHome: "الرئيسية",
      navCatalog: "الكتالوج الفاخر",
      navCategories: "الأقسام",
      navShowroom: "عن المعرض",
      navLocation: "موقع المعرض",
      navTracking: "تتبع طلبك",
      navAccount: "حسابي",
      navCart: "السلة",
      adminPortal: "بوابة الإدارة",

      // Hero Section
      heroTag: "صُنعت لقصور وفيلات الشيخ زايد",
      heroTitle: "فخامة النور في أبهى تجلياتها",
      heroEditorialHeadingHtml: `قاصد كريم <span class="highlight-champagne">للإضاءة</span> الفاخرة`,
      heroEditorialDesc: "نصيغ الضوء ليتحول إلى تحفة فنية تليق بقصوركم وفيلاتكم الراقية. تشكيلات إيطالية حصرية من الدلايات الفاخرة، أنظمة المسارات المغناطيسية، وتنسيق متكامل يبرز فخامة المكان وأناقته.",
      heroSubtitle: "المعرض الأول للإضاءة الإيطالية الفاخرة، المسارات المغناطيسية المعمارية، وحلول الإنارة المتكاملة لكبار مهندسي الديكور وأصحاب الذوق الرفيع.",
      heroBtnExplore: "استكشف الكتالوج الفاخر",
      heroBtnVisit: "تفضل بزيارة صالة العرض",
      exclusiveCollectionsTag: "تشكيلات حصرية",
      exclusiveCollectionsTitle: "المجموعات الحصرية",
      loadMoreProducts: "عرض المزيد من المنتجات",

      // Filter & Sort
      sortFeatured: "المعروضات المميزة",
      sortDefault: "الترتيب الافتراضي (الأعلى تقييماً)",
      sortPriceAsc: "السعر: من الأقل للأعلى",
      sortPriceDesc: "السعر: من الأعلى للأقل",
      sortNewest: "أحدث الوصولات 2026",
      filterAll: "جميع الوحدات",

      // Cart Drawer
      cartTitle: "سلة الطلبات",
      cartEmptyTitle: "سلة طلباتك فارغة",
      cartEmptyDesc: "تفضل باختيار وحدات الإضاءة من المعرض لإضافتها إلى السلة وتأكيد حجزك مباشرة.",
      cartSubtotal: "المجموع المبدئي للوحدات:",
      cartDeliveryFee: "رسوم الشحن والتوصيل:",
      cartTotal: "إجمالي الطلب:",
      btnDirectCheckout: "إتمام وتأكيد الطلب المباشر للموقع",
      btnWhatsAppQuote: "إرسال تفاصيل الطلب لمسؤول المبيعات عبر واتساب",
      btnPrintQuote: "طباعة تفاصيل الطلب",
      freeShippingNote: "شحن مجاني لكافة طلبات الشيخ زايد والطلبات فوق 5,000 ج.م",

      // Customer Auth Modal
      authModalTitle: "تسجيل الدخول / إنشاء حساب عميل",
      authModalSubtitle: "سجل بياناتك لمتابعة طلباتك، حفظ سلة مشترياتك، وتسهيل تأكيد الحجز",
      tabSignIn: "تسجيل الدخول",
      tabRegister: "إنشاء حساب جديد",
      labelFullName: "الاسم بالكامل",
      labelPhone: "رقم الهاتف المحمول",
      labelEmail: "البريد الإلكتروني (اختياري)",
      labelPassword: "كلمة المرور",
      btnSignIn: "دخول لحسابي",
      btnRegister: "إنشاء حساب جديد ومتابعة الطلب",
      continueAsGuest: "أو المتابعة كزائر دون تسجيل",

      // Customer Profile Modal
      myAccountTitle: "حساب العميل",
      myOrdersTitle: "سجل طلباتي السابقة",
      noOrdersYet: "لم تقم بتسجيل أي طلبات حتى الآن",
      signOut: "تسجيل الخروج",

      // Checkout Modal
      checkoutTitle: "إتمام وتأكيد حجز وحدات الإضاءة",
      checkoutSubtitle: "الدفع نقدياً عند الاستلام بعد المعاينة والتأكد من سلامة المنتجات بالكامل",
      secCustomerInfo: "بيانات العميل والتوصيل",
      secDeliveryArea: "منطقة التوصيل بالجمهورية",
      selectAreaPrompt: "-- اختر منطقة التوصيل لحساب رسوم وموعد الشحن --",
      secDetailedAddress: "تفاصيل العنوان ورقم الفيلا / الشقة",
      secNotes: "ملاحظات خاصة بالتسليم والمعاينة (اختياري)",
      secSummary: "ملخص الطلب النهائي",
      btnConfirmOrder: "تأكيد الطلب وحجزه فوراً",
      btnCancel: "إلغاء والعودة للسلة",
      deliveryTerms: "بالضغط على تأكيد الطلب، يتم حجز القطع فوراً والتواصل معكم هاتفياً لترتيب موعد المعاينة والتسليم.",

      // Order Success Modal
      successTitle: "تم استلام وحجز طلبك بنجاح!",
      successSubtitle: "شكراً لثقتكم بمعرض قاصد كريم للإضاءة الفاخرة بالشيخ زايد",
      orderCodeLabel: "كود الطلب المعتمد:",
      orderTotalLabel: "إجمالي المبلغ المستحق عند الاستلام:",
      btnTrackOrderNow: "مسار وتتبع الطلب",
      btnWhatsAppDispatch: "مراسلة مسؤول المبيعات عبر واتساب لتأكيد الموعد",
      btnClose: "إغلاق ومتابعة التسوق",

      // Tracking Modal
      trackTitle: "تتبع مسار طلبك لحظياً",
      trackInputPlaceholder: "أدخل كود الطلب (مثال: ORD-1234)",
      trackPhonePlaceholder: "أدخل رقم الهاتف المسجل لتأكيد هويتك",
      btnTrack: "استعلام وتتبع",

      // Reviews
      reviewsSectionTitle: "آراء وتقييمات العملاء",
      writeReviewBtn: "أضف تقييمك وتجربتك",
      reviewModalTitle: "إضافة تقييم للوحدة",
      labelYourRating: "تقييمك للوحدة:",
      labelYourName: "اسمك الكريم:",
      labelYourComment: "تفاصيل رأيك وتجربتك مع الإضاءة:",
      btnSubmitReview: "إرسال التقييم للمراجعة",
      reviewPendingNotice: "ملاحظة: سيتم نشر تقييمك بالمعرض بعد اعتماده من إدارة الجودة لضمان مصداقية التجربة.",

      // Order Statuses (PRD Section 5)
      status_received: "تم الاستلام",
      status_confirmed: "تم التأكيد والمعاينة",
      status_preparing: "جاري التجهيز",
      status_packed: "تم التغليف",
      status_shipped: "خرج للشحن والتوصيل",
      status_delivered: "تم التسليم بنجاح",
      status_cancelled: "طلب ملغي",
      status_failed: "فشل التوصيل",

      // Delivery Areas
      area_sheikh_zayed: "الشيخ زايد (توصيل مجاني خلال 1-2 يوم)",
      area_october: "السادس من أكتوبر (50 ج.م - 1-2 يوم)",
      area_new_cairo: "القاهرة الجديدة والتجمع (75 ج.م - 2-3 أيام)",
      area_giza: "الجيزة والدقي والمهندسين (60 ج.م - 2-3 أيام)",
      area_cairo: "وسط البلد ومدينة نصر ومصر الجديدة (70 ج.م - 2-3 أيام)",
      area_alexandria: "الإسكندرية والساحل الشمالي (120 ج.م - 3-5 أيام)",

      // Showroom & Location Section
      showroomSectionTag: "صالة العرض بالشيخ زايد",
      showroomTitle: "معرض قاصد كريم في قلب الشيخ زايد",
      showroomDesc: "تفضل بزيارة صالة العرض الخاصة بنا واستمتع بتجربة حسية غامرة تجمع أرقى نماذج الإضاءة المعمارية والديكورية، مع استشارة مجانية لاختيار أرقى التصاميم التي تناسب منزلك.",
      showroomLocation: "الشيخ زايد - الحي الأول، سنتر الطاهرة، الجيزة",
      showroomHours: "يومياً من 11:00 صباحاً حتى 11:00 مساءً",
      showroomWhatsapp: "تواصل مع المعرض مباشرة",
      showroomMap: "الاتجاهات على الخريطة",

      // Footer
      footerDesc: "المعرض الأول للإضاءة الفاخرة والمعمارية في الشيخ زايد. شركاء الإبداع لأصحاب القصور والفيلات والباحثين عن التميز والفرادة.",
      footerCollectionsTitle: "مجموعات الإضاءة",
      footerContactTitle: "معرض الشيخ زايد والتواصل",

      // Google Sign In
      continueWithGoogle: "المتابعة السريعة بحساب Google",
      orUseForm: "أو عبر البريد ورقم الهاتف",

      // Auth & Form Placeholders
      ph_fullName: "مثال: كريم محمود",
      ph_phone: "010XXXXXXXX (11 رقماً)",
      ph_email: "example@kasedkarim.test",
      ph_password: "•••••••• (6 خانات على الأقل)",
      ph_loginIdentifier: "010XXXXXXXX أو your@email.test"
    },

    en: {
      // General & Brand
      brandName: "Kased Karim",
      brandFullName: "Kased Karim Luxury Lighting Showroom",
      tagline: "The Icon of Architectural & Decorative Lighting - Sheikh Zayed",
      locationBadge: "Sheikh Zayed - Al-Tahirah Center",
      phone: "+20 100 636 7690",
      currency: "EGP",
      currencyFullName: "Egyptian Pounds",
      cashOnDelivery: "Cash on Delivery",
      codUncollected: "Cash on delivery — not yet collected",
      inStock: "In Stock at Showroom",
      outOfStock: "Currently Out of Stock",
      warranty: "Warranty",
      years: "Years",
      viewDetails: "Quick Preview",
      addToCart: "Add to Cart",
      buyNow: "Direct Reservation",
      searchPlaceholder: "Search chandeliers, sconces, magnetic tracks, lamps...",
      allCategories: "All Products",
      exclusive: "Exclusive",
      newTag: "New",

      // Top bar & Nav
      showroomCity: "Sheikh Zayed: 01006367690",
      navHome: "Home",
      navCatalog: "Luxury Catalog",
      navCategories: "Categories",
      navShowroom: "About Showroom",
      navLocation: "Location",
      navTracking: "Track Order",
      navAccount: "My Account",
      navCart: "Cart",
      adminPortal: "Admin Portal",

      // Hero Section
      heroTag: "Crafted for Sheikh Zayed Palaces & Villas",
      heroTitle: "The Pure Splendor of Masterpiece Lighting",
      heroEditorialHeadingHtml: `KASED KARIM <span class="highlight-champagne">LUXURY</span> LIGHTING`,
      heroEditorialDesc: "Crafting light into an artistic masterpiece worthy of prestigious estates and villas. Exclusive Italian chandeliers, architectural magnetic tracks, and bespoke luxury illuminations.",
      heroSubtitle: "Egypt's premier destination for Italian luxury luminaires, architectural magnetic tracks, and complete lighting solutions for distinguished architects and homeowners.",
      heroBtnExplore: "Explore Luxury Catalog",
      heroBtnVisit: "Visit Sheikh Zayed Showroom",
      exclusiveCollectionsTag: "EXCLUSIVE COLLECTIONS",
      exclusiveCollectionsTitle: "Exclusive Collections",
      loadMoreProducts: "Load More Products",

      // Filter & Sort
      sortFeatured: "Featured Collections",
      sortDefault: "Default Sorting (Highest Rated)",
      sortPriceAsc: "Price: Low to High",
      sortPriceDesc: "Price: High to Low",
      sortNewest: "Newest Arrivals 2026",
      filterAll: "All Lighting Units",

      // Cart Drawer
      cartTitle: "Shopping Cart",
      cartEmptyTitle: "Your Cart is Empty",
      cartEmptyDesc: "Browse our showroom catalog to select lighting units and reserve them directly.",
      cartSubtotal: "Initial Units Subtotal:",
      cartDeliveryFee: "Delivery & Handling Fee:",
      cartTotal: "Order Total:",
      btnDirectCheckout: "Proceed to Direct Checkout",
      btnWhatsAppQuote: "Send Order Details to Sales via WhatsApp",
      btnPrintQuote: "Print Quotation Summary",
      freeShippingNote: "Free delivery on all Sheikh Zayed orders & orders over 5,000 EGP",

      // Customer Auth Modal
      authModalTitle: "Sign In / Create Customer Account",
      authModalSubtitle: "Access your saved cart, track your orders, and enjoy faster checkout",
      tabSignIn: "Sign In",
      tabRegister: "Create Account",
      labelFullName: "Full Name",
      labelPhone: "Mobile Phone Number",
      labelEmail: "Email Address (Optional)",
      labelPassword: "Password",
      btnSignIn: "Sign In to My Account",
      btnRegister: "Create Account & Continue",
      continueAsGuest: "Or continue as a guest without signing in",

      // Customer Profile Modal
      myAccountTitle: "Customer Account",
      myOrdersTitle: "My Order History",
      noOrdersYet: "You haven't placed any orders yet",
      signOut: "Sign Out",

      // Checkout Modal
      checkoutTitle: "Confirm & Reserve Lighting Units",
      checkoutSubtitle: "Cash on delivery after visual inspection and complete satisfaction",
      secCustomerInfo: "Customer & Contact Information",
      secDeliveryArea: "Delivery Governorate & Area",
      selectAreaPrompt: "-- Select Delivery Area to calculate shipping and estimated time --",
      secDetailedAddress: "Detailed Street Address, Villa/Building No.",
      secNotes: "Special Delivery & Inspection Notes (Optional)",
      secSummary: "Order Final Summary",
      btnConfirmOrder: "Confirm Cash-on-Delivery Order",
      btnCancel: "Return to Cart",
      deliveryTerms: "By confirming your order, items are reserved immediately and our team will contact you to schedule inspection and delivery.",

      // Order Success Modal
      successTitle: "Order Successfully Received & Reserved!",
      successSubtitle: "Thank you for choosing Kased Karim Lighting in Sheikh Zayed",
      orderCodeLabel: "Official Order Reference:",
      orderTotalLabel: "Total Amount Due on Delivery:",
      btnTrackOrderNow: "Track Order Status",
      btnWhatsAppDispatch: "Message Sales on WhatsApp to Confirm Appointment",
      btnClose: "Close & Continue Shopping",

      // Tracking Modal
      trackTitle: "Real-Time Order Tracking",
      trackInputPlaceholder: "Enter Order ID (e.g., ORD-1234)",
      trackPhonePlaceholder: "Enter Registered Phone Number for verification",
      btnTrack: "Lookup & Track",

      // Reviews
      reviewsSectionTitle: "Customer Reviews & Experiences",
      writeReviewBtn: "Write a Product Review",
      reviewModalTitle: "Submit Product Review",
      labelYourRating: "Your Rating:",
      labelYourName: "Your Name:",
      labelYourComment: "Your Review & Feedback:",
      btnSubmitReview: "Submit for Moderation",
      reviewPendingNotice: "Note: Your review will be published once reviewed by our quality management team.",

      // Order Statuses (PRD Section 5)
      status_received: "Received",
      status_confirmed: "Confirmed",
      status_preparing: "Preparing",
      status_packed: "Packed",
      status_shipped: "Out for delivery",
      status_delivered: "Delivered",
      status_cancelled: "Cancelled",
      status_failed: "Delivery failed",

      // Delivery Areas
      area_sheikh_zayed: "Sheikh Zayed (Free Delivery, 1-2 Business Days)",
      area_october: "6th of October (50 EGP, 1-2 Business Days)",
      area_new_cairo: "New Cairo & Tagamoa (75 EGP, 2-3 Business Days)",
      area_giza: "Giza, Dokki & Mohandessin (60 EGP, 2-3 Business Days)",
      area_cairo: "Cairo, Nasr City & Heliopolis (70 EGP, 2-3 Business Days)",
      area_alexandria: "Alexandria & North Coast (120 EGP, 3-5 Business Days)",

      // Showroom & Location Section
      showroomSectionTag: "SHEIKH ZAYED FLAGSHIP",
      showroomTitle: "Kased Karim Flagship in the Heart of Sheikh Zayed",
      showroomDesc: "Visit our dedicated showroom to experience an immersive sensory journey through the finest architectural and decorative lighting, with complimentary bespoke lighting consultations.",
      showroomLocation: "Sheikh Zayed - District 1, Al-Tahirah Center, Giza",
      showroomHours: "Daily from 11:00 AM to 11:00 PM",
      showroomWhatsapp: "Direct WhatsApp Inquiries",
      showroomMap: "Get Directions on Google Maps",

      // Footer
      footerDesc: "Egypt's premier flagship showroom for luxury and architectural lighting in Sheikh Zayed. Creative lighting partners for estates, luxury villas, and discerning spaces.",
      footerCollectionsTitle: "Lighting Collections",
      footerContactTitle: "Showroom & Direct Contact",

      // Google Sign In
      continueWithGoogle: "Continue with Google",
      orUseForm: "Or with email & phone",

      // Auth & Form Placeholders
      ph_fullName: "e.g., Karim Mahmoud",
      ph_phone: "010XXXXXXXX (11 digits)",
      ph_email: "example@kasedkarim.test",
      ph_password: "•••••••• (min 6 characters)",
      ph_loginIdentifier: "010XXXXXXXX or your@email.test"
    }
  };

  class I18nManager {
    constructor() {
      let saved = "ar";
      try {
        saved = localStorage.getItem(STORAGE_KEY) || "ar";
      } catch (e) {}
      if (saved !== "en" && saved !== "ar") saved = "ar";
      this.currentLang = saved;
    }

    getLang() {
      return this.currentLang || "ar";
    }

    getCurrentLanguage() {
      return this.currentLang || "ar";
    }

    isEn() {
      return (this.currentLang || "ar") === "en";
    }

    isRTL() {
      return (this.currentLang || "ar") === "ar";
    }

    t(key, fallback = "") {
      const dict = TRANSLATIONS[this.currentLang] || TRANSLATIONS.ar;
      if (dict && dict[key] !== undefined) {
        return dict[key];
      }
      const arDict = TRANSLATIONS.ar;
      if (arDict && arDict[key] !== undefined) {
        return arDict[key];
      }
      return fallback || key;
    }

    setLang(lang) {
      if (lang !== "en" && lang !== "ar") return;
      this.currentLang = lang;
      try {
        localStorage.setItem(STORAGE_KEY, lang);
      } catch (e) {}
      this.applyLanguageToDOM();
      window.dispatchEvent(new CustomEvent("kk_language_changed", { detail: { lang } }));
    }

    toggleLanguage() {
      const newLang = this.currentLang === "ar" ? "en" : "ar";
      this.setLang(newLang);
    }

    applyLanguageToDOM() {
      const isEn = this.currentLang === "en";
      const dir = isEn ? "ltr" : "rtl";
      const lang = isEn ? "en" : "ar";

      document.documentElement.lang = lang;
      document.documentElement.dir = dir;

      if (isEn) {
        document.body.classList.add("is-en");
        document.body.classList.remove("is-ar");
      } else {
        document.body.classList.add("is-ar");
        document.body.classList.remove("is-en");
      }

      // Update text nodes with data-i18n attribute
      const elements = document.querySelectorAll("[data-i18n]");
      elements.forEach(el => {
        const key = el.getAttribute("data-i18n");
        const val = this.t(key);
        if (val) {
          el.textContent = val;
        }
      });

      // Update HTML nodes with data-i18n-html attribute
      const htmlElements = document.querySelectorAll("[data-i18n-html]");
      htmlElements.forEach(el => {
        const key = el.getAttribute("data-i18n-html");
        const val = this.t(key);
        if (val) {
          el.innerHTML = val;
        }
      });

      // Update CTA arrow direction
      const ctaArrow = document.getElementById("heroCtaArrow");
      if (ctaArrow) {
        ctaArrow.innerHTML = isEn ? "&rarr;" : "&larr;";
      }

      // Update sort dropdown labels
      const sortMap = {
        "featured": isEn ? "Featured Collections" : "المعروضات المميزة",
        "price-desc": isEn ? "Price: High to Low" : "السعر: من الأعلى للأقل",
        "price-asc": isEn ? "Price: Low to High" : "السعر: من الأقل للأعلى",
        "newest": isEn ? "Newest Arrivals 2026" : "أحدث الوصولات 2026"
      };
      document.querySelectorAll(".luxury-sort-option").forEach(opt => {
        const v = opt.getAttribute("data-value");
        const sp = opt.querySelector("span");
        if (v && sp && sortMap[v]) sp.textContent = sortMap[v];
      });
      const sortTriggerLabel = document.getElementById("sortTriggerLabel");
      const sortSelect = document.getElementById("sortSelect");
      if (sortTriggerLabel && sortSelect && sortMap[sortSelect.value || "featured"]) {
        sortTriggerLabel.textContent = sortMap[sortSelect.value || "featured"];
      }

      // Update placeholders with data-i18n-placeholder attribute
      const placeholders = document.querySelectorAll("[data-i18n-placeholder]");
      placeholders.forEach(el => {
        const key = el.getAttribute("data-i18n-placeholder");
        const val = this.t(key);
        if (val) {
          el.setAttribute("placeholder", val);
        }
      });

      // Update titles with data-i18n-title attribute
      const titles = document.querySelectorAll("[data-i18n-title]");
      titles.forEach(el => {
        const key = el.getAttribute("data-i18n-title");
        const val = this.t(key);
        if (val) {
          el.setAttribute("title", val);
        }
      });

      // Update Language Switcher Buttons in DOM
      const switcherLabels = document.querySelectorAll(".lang-switcher-text");
      switcherLabels.forEach(lbl => {
        lbl.textContent = isEn ? "العربية" : "English";
      });

      const currentLangTags = document.querySelectorAll(".lang-current-tag");
      currentLangTags.forEach(tag => {
        tag.textContent = isEn ? "EN" : "عربي";
      });
    }
  }

  window.KK_I18N = new I18nManager();
  window.KK_I18N.getCurrentLanguage = function () {
    return (window.KK_I18N && window.KK_I18N.currentLang) || "ar";
  };
  window.KK_I18N.getLang = function () {
    return (window.KK_I18N && window.KK_I18N.currentLang) || "ar";
  };
  window.KK_I18N.isEn = function () {
    return (window.KK_I18N && window.KK_I18N.currentLang) === "en";
  };
  window.t = function (key, fallback) {
    return window.KK_I18N.t(key, fallback);
  };
  window.toggleLanguage = function () {
    window.KK_I18N.toggleLanguage();
  };
  window.formatCurrency = function (amount) {
    const num = Math.round(Number(amount) || 0);
    const formatted = num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    const sym = window.KK_I18N.t("currency");
    return window.KK_I18N.isRTL() ? `${formatted} ${sym}` : `${formatted} ${sym}`;
  };

  document.addEventListener("DOMContentLoaded", () => {
    window.KK_I18N.applyLanguageToDOM();
  });
})();
