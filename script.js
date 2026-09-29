/* Menü Risk landing — form + sonuç ekranı + GA4 eventleri.
   Kural: kullanıcı verisi asla innerHTML ile basılmaz; tüm metin textContent ile
   yazılır (XSS yüzeyi yok). Analitiğe PII gönderilmez (menü içeriği/e-posta yok). */
(function () {
  "use strict";

  var API_BASE = (window.MENURISK_API_BASE || "").replace(/\/$/, "");
  var CONTACT = window.MENURISK_CONTACT || "";
  var FORMSPREE_SCAN = window.MENURISK_FORMSPREE_SCAN || "https://formspree.io/f/mppwblpg";

  /* Formspree fallback: API kapali/5xx iken lead kaybolmaz, kuyruga alinir.
     Trust deseniyle ayni: JSON + Accept header, sade konu, honeypot.
     2 asamali: once fetch (sayfada kalir), olmazsa native form POST (CORS/adblock deler). */
  function formspreeBody(payload) {
    return {
      email: payload.email,
      message: (payload.csv || payload.text || "").slice(0, 4000),
      source: payload.source || "menurisk-scan-form"
    };
  }

  function nativeFormspreeSubmit(payload) {
    var form = document.createElement("form");
    form.method = "POST";
    form.action = FORMSPREE_SCAN;
    form.target = "_blank";
    form.style.display = "none";
    var body = formspreeBody(payload);
    [["email", body.email],
     ["message", body.message],
     ["source", body.source]]
    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
  }

  function postFormspreeFallback(payload) {
    return fetch(FORMSPREE_SCAN, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(formspreeBody(payload))
    }).then(function (response) {
      if (!response.ok) throw new Error("fallback failed (" + response.status + ")");
      return true;
    });
  }

  function track(name, params) {
    try {
      if (typeof window.gtag === "function") window.gtag("event", name, params || {});
      if (window.dataLayer && window.dataLayer.push) window.dataLayer.push({ event: name });
    } catch (e) { /* analitik hatası dönüşümü engellemez */ }
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null && text !== "") node.textContent = String(text);
    return node;
  }

  function fmtDate(value) {
    return value ? value : "n/a";
  }

  function riskLabel(risk) {
    var map = {
      CRITICAL: "Check today",
      HIGH: "Review today",
      MEDIUM: "Review when you can",
      LOW: "Recorded for traceability"
    };
    return map[risk] || "Review";
  }

  /* --- ingredient list helpers ------------------------------------------ */

  function countItems(text) {
    return (text || "")
      .split(/\r?\n/)
      .map(function (line) { return line.trim(); })
      .filter(function (line) { return line && line.charAt(0) !== "#"; })
      .length;
  }

  /* --- API --------------------------------------------------------------- */

  function api(path, body) {
    return fetch(API_BASE + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (response) {
      return response.json().catch(function () { return null; }).then(function (data) {
        if (!response.ok) {
          var message = data && data.error && data.error.message
            ? data.error.message
            : "Something went wrong on our side (" + response.status + "). Try again in a moment.";
          throw new Error(message);
        }
        return data;
      });
    });
  }

  /* --- result rendering -------------------------------------------------- */

  function statCard(label, value) {
    var wrap = el("dl", "res-stat");
    wrap.appendChild(el("dt", null, label));
    wrap.appendChild(el("dd", null, value));
    return wrap;
  }

  function defList(rows) {
    var dl = el("dl", "alert-body");
    rows.forEach(function (row) {
      if (!row[1]) return;
      dl.appendChild(el("dt", null, row[0]));
      var dd = el("dd", null, row[1]);
      if (row[2]) dd.className = "mono";
      dl.appendChild(dd);
    });
    return dl;
  }

  function matchCard(match, index) {
    var recall = match.recall || {};
    var card = el("article", "card res-match risk-" + String(match.risk || "").toLowerCase());
    var head = el("header", "alert-head");
    head.appendChild(el("span", "pill pill-" + String(match.risk || "").toLowerCase(),
      "POTENTIAL MATCH · " + match.risk));
    head.appendChild(el("span", "sample-tag", riskLabel(match.risk)));
    card.appendChild(head);

    card.appendChild(defList([
      ["Ingredient", match.ingredient],
      ["Normalized", match.normalized === match.ingredient ? "" : match.normalized],
      ["Recall product", recall.product_name],
      ["Recalling firm", recall.firm],
      ["Classification", (recall["class"] || "n/a") + " · " + (recall.status || "n/a")],
      ["Match level", match.level + " (confidence " + match.confidence + ")"],
      ["Reason", recall.reason],
      ["Lot / code info", recall.lot_code_info],
      ["Recall date", fmtDate(recall.recall_date)],
      ["Report date", fmtDate(recall.report_date)],
      ["Distribution", recall.distribution],
      ["Why it matched", match.why]
    ]));

    var next = el("p", "next-step");
    next.appendChild(el("strong", null, "Next step: "));
    next.appendChild(document.createTextNode(riskLabel(match.risk) + " — verify the lot/date code on the product you have and confirm with your supplier. This is a signal for human review, not a determination."));
    card.appendChild(next);

    if (recall.source_url) {
      var source = el("p", "hint");
      source.appendChild(el("strong", null, "Source: "));
      var link = el("a", "mono", recall.source_url);
      link.href = recall.source_url;
      link.rel = "noopener nofollow";
      link.target = "_blank";
      link.addEventListener("click", function () {
        track("source_link_click", { index: index, outbound_domain: "api.fda.gov" });
      });
      source.appendChild(link);
      source.appendChild(document.createTextNode("  ·  pulled " + fmtDate(recall.retrieved_at)));
      card.appendChild(source);
    }
    return card;
  }

  function renderScan(payload, container) {
    container.innerHTML = "";
    container.hidden = false;

    var counts = payload.risk_counts || {};
    var matches = payload.matches || [];
    var head = el("div", "res-head");
    head.appendChild(el("h3", null, matches.length
      ? "Scan complete — " + matches.length + " item(s) worth reviewing"
      : "Scan complete — no potential matches found"));
    var actions = el("div", "res-actions");
    var copyBtn = el("button", "btn btn-secondary btn-sm", "Copy result link");
    copyBtn.type = "button";
    copyBtn.addEventListener("click", function () {
      var url = payload.result_url || location.href;
      var done = function () { copyBtn.textContent = "Link copied"; };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(done, done);
      } else {
        var tmp = document.createElement("textarea");
        tmp.value = url;
        document.body.appendChild(tmp);
        tmp.select();
        try { document.execCommand("copy"); } catch (e) { /* yoksay */ }
        document.body.removeChild(tmp);
        done();
      }
    });
    actions.appendChild(copyBtn);
    head.appendChild(actions);
    container.appendChild(head);

    var meta = el("p", "hint");
    meta.appendChild(document.createTextNode(
      "Checked " + (payload.ingredients_checked || 0) + " of " +
      (payload.ingredients_total || 0) + " items against " +
      (payload.recalls_considered || 0) + " active US recall record(s). Data pulled "
    ));
    meta.appendChild(el("span", "mono", fmtDate(payload.recalls_retrieved_at)));
    meta.appendChild(document.createTextNode(". Scan id "));
    meta.appendChild(el("span", "mono", payload.scan_id || ""));
    container.appendChild(meta);

    if (payload.email_status === "sent") {
      var sent = el("p", "hint", "We emailed the result link to " + (payload.org_email || "your address") + ".");
      container.appendChild(sent);
    } else if (payload.email_status === "dry_run") {
      container.appendChild(el("p", "hint", "Email is in test mode on this server, so no message was sent — use \"Copy result link\" to keep this result."));
    } else if (payload.email_status === "failed") {
      container.appendChild(el("p", "hint", "We couldn't send the email. Your result is here on screen — copy the link if you want to keep it."));
    }

    (payload.warnings || []).forEach(function (warning) {
      container.appendChild(el("div", "res-warning", warning));
    });

    var stats = el("div", "res-stats");
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"].forEach(function (risk) {
      stats.appendChild(statCard(risk, counts[risk] || 0));
    });
    container.appendChild(stats);

    var generics = payload.skipped_generic_terms || [];
    if (generics.length) {
      var block = el("div", "card");
      block.appendChild(el("h3", null, "Needs a more specific name"));
      block.appendChild(el("p", "hint", "These entries are single generic categories, so no match was produced. Rename them and re-scan for a reliable check."));
      var list = el("ul", "res-generics");
      generics.forEach(function (term) {
        var item = el("li");
        item.appendChild(el("span", "pill pill-none", term));
        list.appendChild(item);
      });
      block.appendChild(list);
      container.appendChild(block);
    }

    if (matches.length) {
      matches.forEach(function (match, index) {
        container.appendChild(matchCard(match, index));
      });
    } else {
      var empty = el("div", "res-empty");
      empty.appendChild(el("h3", null, "No potential recall matches were identified in this scan."));
      empty.appendChild(el("p", null, "That is a snapshot, not an all-clear: new recall events are published after every scan, and a match can appear next week that isn't in this result."));
      var detail = el("p", "hint");
      detail.appendChild(document.createTextNode("Checked " + (payload.ingredients_checked || 0) + " items · Source: FDA openFDA food enforcement · Pulled "));
      detail.appendChild(el("span", "mono", fmtDate(payload.recalls_retrieved_at)));
      empty.appendChild(detail);
      container.appendChild(empty);
    }

    var foot = el("p", "fineprint", "This is a risk signal for human review — not a determination, not legal advice, and not a compliance guarantee. US recalls only.");
    container.appendChild(foot);
  }

  /* --- free scan form ---------------------------------------------------- */

  function initScanForm() {
    var form = document.getElementById("scan-form");
    if (!form) return;
    var textarea = document.getElementById("ingredients");
    var fileInput = document.getElementById("csv");
    var emailInput = document.getElementById("email");
    var errorBox = document.getElementById("form-error");
    var okBox = document.getElementById("form-ok");
    var submit = document.getElementById("scan-submit");
    var counter = document.getElementById("items-count");
    var result = document.getElementById("result");
    var started = false;

    function showError(message) {
      errorBox.textContent = message;
      errorBox.hidden = false;
    }
    function clearError() {
      errorBox.hidden = true;
      errorBox.textContent = "";
      if (okBox) { okBox.hidden = true; okBox.textContent = ""; }
    }
    function showQueued(via, source) {
      clearError();
      if (okBox) {
        okBox.textContent = "Your request was sent — we'll email you the result shortly.";
        okBox.hidden = false;
      }
      track("scan_queued", { source: source, via: via });
    }

    textarea.addEventListener("input", function () {
      var count = countItems(textarea.value);
      counter.textContent = count + " item(s) detected";
      if (!started && textarea.value.trim()) {
        started = true;
        track("scan_start", { entry_point: "form" });
      }
    });

    fileInput.addEventListener("change", function () {
      if (fileInput.files && fileInput.files.length) {
        track("upload_start", { input_method: "csv" });
      }
    });

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      clearError();

      var email = (emailInput.value || "").trim();
      if (!email || email.indexOf("@") < 1) {
        emailInput.setAttribute("aria-invalid", "true");
        emailInput.focus();
        showError("That email address doesn't look right. Check it and try again.");
        return;
      }
      emailInput.removeAttribute("aria-invalid");

      var submitPayload = { email: email, text: "", csv: "", filename: "", source: "landing" };

      var send = function () {
        if (!submitPayload.csv.trim() && !submitPayload.text.trim()) {
          showError("Add at least one ingredient — one per line works fine.");
          textarea.setAttribute("aria-invalid", "true");
          textarea.focus();
          submit.disabled = false;
          submit.textContent = "Scan my menu";
          return;
        }
        track("email_submit", {
          has_file: !!submitPayload.csv,
          item_count: countItems(submitPayload.csv || submitPayload.text)
        });
        api("/api/v1/scan/free", submitPayload)
          .then(function (payload) {
            track("scan_complete", {
              scan_id: payload.scan_id,
              matches_found: (payload.matches || []).length,
              risk_counts: payload.risk_counts || {},
              duration_ms: payload.duration_ms || 0
            });
            renderScan(payload, result);
            track("result_view", {
              scan_id: payload.scan_id,
              is_no_match: !(payload.matches || []).length,
              top_risk: (payload.matches && payload.matches[0] && payload.matches[0].risk) || "NONE"
            });
            result.scrollIntoView({ behavior: "smooth", block: "start" });
          })
          .catch(function (error) {
            var hint = CONTACT ? " You can also email " + CONTACT + " and we'll run it manually." : "";
            postFormspreeFallback(submitPayload).then(function () {
              showQueued("fetch", submitPayload.source || "landing");
            }, function () {
              /* fetch de engellendiyse (adblock/CORS/file://): native POST her turlu gider */
              try {
                nativeFormspreeSubmit(submitPayload);
                showQueued("native", submitPayload.source || "landing");
              } catch (e) {
                showError(error.message + hint);
              }
            });
          })
          .then(function () {
            submit.disabled = false;
            submit.textContent = "Scan my menu";
          });
      };

      submit.disabled = true;
      submit.textContent = "Scanning…";

      if (fileInput.files && fileInput.files.length) {
        var file = fileInput.files[0];
        if (file.size > 1000000) {
          submit.disabled = false;
          submit.textContent = "Scan my menu";
          showError("That file is larger than 1 MB. Split it, or paste the list as text.");
          return;
        }
        var reader = new FileReader();
        reader.onload = function () {
          submitPayload.csv = String(reader.result || "");
          submitPayload.filename = file.name;
          submitPayload.source = "landing_csv";
          track("upload_complete", {
            file_kind: "csv",
            item_count: countItems(submitPayload.csv)
          });
          send();
        };
        reader.onerror = function () {
          submit.disabled = false;
          submit.textContent = "Scan my menu";
          showError("We couldn't read that file. Save it as UTF-8 CSV and try again.");
        };
        reader.readAsText(file);
        return;
      }

      submitPayload.text = textarea.value || "";
      send();
    });
  }

  /* --- monitoring early access ------------------------------------------ */

  function initInterestForm() {
    var form = document.getElementById("interest-form");
    if (!form) return;
    var emailInput = document.getElementById("interest-email");
    var errorBox = document.getElementById("interest-error");
    var okBox = document.getElementById("interest-ok");
    var submit = document.getElementById("interest-submit");

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      errorBox.hidden = true;
      okBox.hidden = true;
      var email = (emailInput.value || "").trim();
      if (!email || email.indexOf("@") < 1) {
        errorBox.textContent = "That email address doesn't look right. Check it and try again.";
        errorBox.hidden = false;
        emailInput.focus();
        return;
      }
      submit.disabled = true;
      submit.textContent = "Adding…";
      api("/api/v1/monitoring-interest", { email: email, source: "landing" })
        .then(function (payload) {
          okBox.textContent = payload.already_registered
            ? "You're already on the list — we'll email you when monitoring opens."
            : "You're on the list. One email when monitoring opens, nothing else.";
          okBox.hidden = false;
          track("early_access_submit", {});
          form.reset();
        })
        .catch(function (error) {
          /* API yoksa Formspree'ye duser, liste kaybolmaz (scan formundaki desen). */
          fetch(FORMSPREE_SCAN, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ email: email, message: "Early-access request for daily monitoring.", source: "menurisk-early-access" })
          }).then(function (response) {
            if (!response.ok) throw new Error("fallback failed");
            okBox.textContent = "You're on the list. One email when monitoring opens, nothing else.";
            okBox.hidden = false;
            track("early_access_submit", { via: "formspree" });
            form.reset();
          }, function () {
            errorBox.textContent = error.message;
            errorBox.hidden = false;
          });
        })
        .then(function () {
          submit.disabled = false;
          submit.textContent = "Join the early-access list";
        });
    });
  }

  /* --- result page (result.html) ---------------------------------------- */

  function initResultPage() {
    var container = document.getElementById("result");
    if (!container || !container.dataset.resultPage) return;
    var params = new URLSearchParams(location.search);
    var id = params.get("id") || "";
    var token = params.get("token") || "";
    if (!id || !token) {
      container.hidden = false;
      container.appendChild(el("div", "res-warning", "This link is incomplete. Run a new free scan to get a fresh result link."));
      return;
    }
    fetch(API_BASE + "/api/v1/scan/" + encodeURIComponent(id) + "?token=" + encodeURIComponent(token))
      .then(function (response) {
        return response.json().catch(function () { return null; }).then(function (data) {
          if (!response.ok) {
            var message = data && data.error && data.error.message
              ? data.error.message
              : "We couldn't load this result.";
            throw new Error(message);
          }
          return data;
        });
      })
      .then(function (payload) {
        renderScan(payload, container);
        track("result_view", { scan_id: payload.scan_id, from_email: true });
      })
      .catch(function (error) {
        container.hidden = false;
        container.appendChild(el("div", "res-warning", error.message));
      });
  }

  function initReveal() {
    var targets = document.querySelectorAll(
      ".step.card, .example-grid .alert-card, .trust-item, #who .card, .hero-visual .result-card"
    );
    if (!targets.length) return;
    if (!("IntersectionObserver" in window)) return; /* no-JS/no-IO: visible */
    targets.forEach(function (node) { node.classList.add("reveal"); });
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("in");
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -6% 0px" });
    targets.forEach(function (node) { observer.observe(node); });
  }

  function init() {
    var year = document.getElementById("year");
    if (year) year.textContent = String(new Date().getFullYear());
    initReveal();
    initScanForm();
    initInterestForm();
    initResultPage();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
