/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED
 * Interactive Light Lab / Simulator
 * محاكي درجات حرارة ألوان الإضاءة التفاعلي
 */

const LIGHT_PRESETS = {
  warm: {
    kelvin: "2700K",
    name: "ذهبي دافئ ملكي (Warm Amber)",
    desc: "الإضاءة المثالية للقصور والفلل في أوقات المساء؛ تبرز بريق الكريستال ودفء الرخام وتمنح الصالونات والمجالس طابعاً فندقياً فخماً.",
    bgImage: "https://images.unsplash.com/photo-1600585154340-be6161a56a0c?auto=format&fit=crop&w=1400&q=80",
    cri: "CRI > 98",
    lux: "150 - 250 Lux (محيطي هادئ)",
    recommended: "بهو الاستقبال، الصالونات، غرف النوم الماستر"
  },
  neutral: {
    kelvin: "3500K - 4000K",
    name: "طبيعي ناعم متوازن (Soft Natural)",
    desc: "درجة متوازنة لا تميل للحرارة ولا للزرقة، تكشف الألوان الحقيقية للأثاث الإيطالي، اللوحات الفنية، وخامات الرخام الطبيعي دون تشويه.",
    bgImage: "https://images.unsplash.com/photo-1600596542815-ffad4c1539a9?auto=format&fit=crop&w=1400&q=80",
    cri: "CRI > 97",
    lux: "300 - 450 Lux (إنارة وظيفية راقية)",
    recommended: "طاولات الطعام، غرف المعيشة العائلية، المكاتب"
  },
  cool: {
    kelvin: "5000K",
    name: "نهاري ناصع نقي (Pure Daylight)",
    desc: "إضاءة نهارية صريحة ونقية توفر أقصى تركيز ووضوح، مفضلة في مناطق الدريسنج روم وخزائن الملابس الراقية والمطابخ الكونسيبت.",
    bgImage: "https://images.unsplash.com/photo-1600607687939-ce8a6c25118c?auto=format&fit=crop&w=1400&q=80",
    cri: "CRI > 95",
    lux: "500+ Lux (رؤية بصرية فائقة)",
    recommended: "غرف الملابس (Dressing Rooms)، المطابخ المودرن"
  },
  night: {
    kelvin: "2200K - 2700K (Accents Only)",
    name: "المسار الليلي الدرامي (Night Ambience)",
    desc: "تعتيم كامل للإنارة العامة وتشغيل الإضاءة المعمارية الموجهة فقط (Dark Light Spots) مع البروفايل المخفي لإبراز المنحنيات الجمالية.",
    bgImage: "https://images.unsplash.com/photo-1512917774080-9991f1c4c750?auto=format&fit=crop&w=1400&q=80",
    cri: "CRI > 98",
    lux: "50 - 100 Lux (أجواء سينمائية ساحرة)",
    recommended: "الصالات المفتوحة ليلاً، الممرات الخارجية واللاندسكيب"
  }
};

function initLightingSimulator() {
  const stage = document.getElementById("simStage");
  const roomTitle = document.getElementById("simRoomTitle");
  const roomDesc = document.getElementById("simRoomDesc");
  const roomCri = document.getElementById("simRoomCri");
  const roomLux = document.getElementById("simRoomLux");
  const roomRecommended = document.getElementById("simRoomRecommended");
  const buttons = document.querySelectorAll(".temp-btn");

  if (!stage || !buttons.length) return;

  function setPreset(presetKey) {
    const data = LIGHT_PRESETS[presetKey];
    if (!data) return;

    // Remove previous classes
    stage.classList.remove("warm", "neutral", "cool", "night");
    stage.classList.add(presetKey);

    // Update active button state
    buttons.forEach(btn => {
      if (btn.dataset.preset === presetKey) {
        btn.classList.add("active");
      } else {
        btn.classList.remove("active");
      }
    });

    // Update background image with subtle transition
    stage.style.backgroundImage = `url('${data.bgImage}')`;

    // Update texts
    if (roomTitle) roomTitle.textContent = `${data.name} (${data.kelvin})`;
    if (roomDesc) roomDesc.textContent = data.desc;
    if (roomCri) roomCri.textContent = data.cri;
    if (roomLux) roomLux.textContent = data.lux;
    if (roomRecommended) roomRecommended.textContent = data.recommended;
  }

  // Bind click events
  buttons.forEach(btn => {
    btn.addEventListener("click", () => {
      const preset = btn.dataset.preset;
      setPreset(preset);
    });
  });

  // Initial preset
  setPreset("warm");
}

document.addEventListener("DOMContentLoaded", initLightingSimulator);
