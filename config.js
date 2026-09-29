/* Menü Risk landing — çalışma zamanı yapılandırması (build adımı yok).
   Landing statik olarak Vercel'de, API ayrı sunucuda çalışır.
   [VERIFY] API alan adı kesinleşince üretim satırı güncellenir. */
(function () {
  var host = location.hostname || "";
  var isLocal = host === "localhost" || host === "127.0.0.1" || host === "";
  window.MENURISK_API_BASE = isLocal
    ? "http://127.0.0.1:8000"
    : "https://api.menurisk.ai2eo.com";
  window.MENURISK_CONTACT = "info@ai2eo.com";
  window.MENURISK_FORMSPREE_SCAN = "https://formspree.io/f/mppwblpg";
})();
