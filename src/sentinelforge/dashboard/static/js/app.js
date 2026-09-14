/* SentinelForge SOC console - shared frontend behaviour (Phase 6).
 *
 * Security rule for every line of JavaScript in this project: telemetry is
 * inserted with textContent, never with innerHTML, insertAdjacentHTML,
 * document.write or a template string assembled into markup. A username, a
 * command line or an AI sentence therefore reaches the DOM as text, and a
 * payload such as <script>alert(1)</script> is displayed rather than executed.
 * The page also ships a Content-Security-Policy without 'unsafe-inline', so
 * even a mistake here cannot become a working injection.
 */
(function () {
  "use strict";

  /** Bounded, shared SSE connection. Pages subscribe to topics they render. */
  var Stream = {
    source: null,
    handlers: {},
    paused: false,

    connect: function (topics) {
      if (this.source) { return this.source; }
      var url = "/api/stream" + (topics && topics.length ? "?topics=" + encodeURIComponent(topics.join(",")) : "");
      var source = new EventSource(url);
      var self = this;

      source.addEventListener("open", function () { setStatus("live", "live"); });
      source.addEventListener("connected", function () { setStatus("live", "live"); });
      source.addEventListener("error", function () {
        // EventSource retries on its own; report the gap rather than hiding it.
        setStatus("error", "reconnecting");
      });
      source.addEventListener("dropped", function (event) {
        var data = parse(event.data);
        if (data && typeof data.dropped === "number") {
          var note = document.getElementById("live-dropped");
          if (note) { note.textContent = data.dropped + " message(s) dropped: this browser fell behind."; }
        }
      });

      (topics || ["event_received", "alert_created", "incident_created", "incident_updated",
                  "ai_analysis_completed", "sensor_status_changed"]).forEach(function (topic) {
        source.addEventListener(topic, function (event) {
          if (self.paused) { return; }
          var message = parse(event.data);
          if (!message) { return; }
          (self.handlers[topic] || []).forEach(function (handler) {
            try { handler(message); } catch (error) { /* one bad handler must not kill the stream */ }
          });
          (self.handlers["*"] || []).forEach(function (handler) {
            try { handler(message); } catch (error) { /* as above */ }
          });
        });
      });

      this.source = source;
      return source;
    },

    on: function (topic, handler) {
      if (!this.handlers[topic]) { this.handlers[topic] = []; }
      this.handlers[topic].push(handler);
    },

    setPaused: function (paused) {
      this.paused = paused;
      setStatus(paused ? "paused" : "live", paused ? "paused" : "live");
    }
  };

  function parse(raw) {
    try { return JSON.parse(raw); } catch (error) { return null; }
  }

  function setStatus(state, text) {
    var element = document.getElementById("stream-status");
    if (!element) { return; }
    element.setAttribute("data-state", state);
    var label = element.querySelector(".stream-text");
    if (label) { label.textContent = text; }
  }

  /** Create an element with text content. The only way this file builds DOM. */
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function clockText(value) {
    if (typeof value === "string" && value.length >= 19 && value.indexOf("T") > 0) {
      return value.slice(11, 19);
    }
    var now = new Date();
    return now.toTimeString().slice(0, 8);
  }

  /** Refresh the overview counters from the API (cheap, and never a full reload). */
  function refreshStats() {
    var targets = document.getElementById("stat-active");
    if (!targets) { return; }
    fetch("/api/stats", { headers: { "Accept": "application/json" } })
      .then(function (response) { return response.ok ? response.json() : null; })
      .then(function (data) {
        if (!data) { return; }
        setText("stat-active", data.incidents.active);
        setText("stat-critical", data.incidents.critical);
        setText("stat-high", data.incidents.high);
        setText("stat-alerts", data.live.alerts_created);
        setText("stat-events", data.live.events_received);
        setText("stat-eps", data.live.events_per_second);
      })
      .catch(function () { /* a failed refresh leaves the last known values */ });
  }

  function setText(id, value) {
    var node = document.getElementById(id);
    if (node) { node.textContent = String(value); }
  }

  window.SentinelForge = {
    stream: Stream,
    el: el,
    clockText: clockText,
    refreshStats: refreshStats,
    setText: setText
  };

  document.addEventListener("DOMContentLoaded", function () {
    // Counters update when something actually happens, plus a slow safety net.
    Stream.on("*", function () { throttledStats(); });
    var lastRefresh = 0;
    function throttledStats() {
      var now = Date.now();
      if (now - lastRefresh < 2000) { return; }
      lastRefresh = now;
      refreshStats();
    }
    window.setInterval(refreshStats, 30000);
  });
})();
