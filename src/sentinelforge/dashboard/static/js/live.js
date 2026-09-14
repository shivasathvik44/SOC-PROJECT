/* Live activity feed (Phase 6).
 *
 * Renders bus messages as they arrive. Every value goes through textContent -
 * see the note at the top of app.js. The feed is bounded: old rows are removed
 * from the DOM, so a console left open overnight does not grow a million nodes.
 */
(function () {
  "use strict";

  var MAX_ROWS = 200;

  document.addEventListener("DOMContentLoaded", function () {
    var feed = document.getElementById("live-feed");
    if (!feed) { return; }

    var SF = window.SentinelForge;
    var pauseButton = document.getElementById("live-pause");
    var clearButton = document.getElementById("live-clear");
    var filterInput = document.getElementById("live-filter");
    var countLabel = document.getElementById("live-count");
    var filterText = "";

    SF.stream.connect();

    SF.stream.on("*", function (message) {
      addRow(message);
    });

    if (pauseButton) {
      pauseButton.addEventListener("click", function () {
        var paused = pauseButton.getAttribute("aria-pressed") === "true";
        paused = !paused;
        pauseButton.setAttribute("aria-pressed", paused ? "true" : "false");
        pauseButton.textContent = paused ? "Resume" : "Pause";
        SF.stream.setPaused(paused);
      });
    }

    if (clearButton) {
      clearButton.addEventListener("click", function () {
        while (feed.firstChild) { feed.removeChild(feed.firstChild); }
        updateCount();
      });
    }

    if (filterInput) {
      filterInput.addEventListener("input", function () {
        filterText = filterInput.value.trim().toLowerCase();
        Array.prototype.forEach.call(feed.children, function (row) {
          var haystack = row.getAttribute("data-search") || "";
          row.hidden = filterText !== "" && haystack.indexOf(filterText) === -1;
        });
        updateCount();
      });
    }

    function describe(topic, payload) {
      if (topic === "event_received") {
        return [payload.event_type || "event",
                payload.process, payload.user, payload.src_ip, payload.message]
          .filter(Boolean).join("  ");
      }
      if (topic === "alert_created") {
        return [payload.rule_id, "[" + (payload.severity || "?") + "]",
                payload.source_ip, payload.user, payload.description]
          .filter(Boolean).join("  ");
      }
      if (topic === "incident_created" || topic === "incident_updated") {
        return [payload.incident_id, "[" + (payload.severity || "?") + "]",
                "risk " + (payload.risk_score !== undefined ? payload.risk_score : "?"),
                payload.title].filter(Boolean).join("  ");
      }
      if (topic === "ai_analysis_completed") {
        return [payload.incident_id, payload.assessment,
                payload.confidence !== undefined ? "confidence " + payload.confidence : null,
                payload.is_mock ? "(mock provider)" : null].filter(Boolean).join("  ");
      }
      if (topic === "sensor_status_changed") {
        return [payload.name, payload.state, payload.reason].filter(Boolean).join("  ");
      }
      return JSON.stringify(payload).slice(0, 300);
    }

    function addRow(message) {
      var payload = message.payload || {};
      var topic = message.topic;
      var row = document.createElement("li");

      row.appendChild(SF.el("span", "feed-time", SF.clockText(payload.timestamp)));
      row.appendChild(SF.el("span", "feed-kind feed-kind-" + topic, topicLabel(topic)));

      var text = SF.el("span", "feed-text", describe(topic, payload));
      row.appendChild(text);

      if (payload.demo) { row.appendChild(SF.el("span", "feed-demo", "DEMO")); }

      if (payload.incident_id) {
        var link = document.createElement("a");
        link.href = "/incidents/" + encodeURIComponent(payload.incident_id);
        link.textContent = "open";
        link.className = "feed-link";
        row.appendChild(link);
      }

      row.setAttribute("data-search", (topic + " " + text.textContent).toLowerCase());
      if (filterText && row.getAttribute("data-search").indexOf(filterText) === -1) {
        row.hidden = true;
      }

      feed.insertBefore(row, feed.firstChild);
      while (feed.children.length > MAX_ROWS) {
        feed.removeChild(feed.lastChild);
      }
      updateCount();
    }

    function topicLabel(topic) {
      if (topic === "event_received") { return "EVENT"; }
      if (topic === "alert_created") { return "ALERT"; }
      if (topic === "incident_created") { return "INCIDENT"; }
      if (topic === "incident_updated") { return "INC-UPD"; }
      if (topic === "ai_analysis_completed") { return "AI"; }
      if (topic === "sensor_status_changed") { return "SENSOR"; }
      return topic.toUpperCase().slice(0, 8);
    }

    function updateCount() {
      if (!countLabel) { return; }
      var visible = Array.prototype.filter.call(feed.children, function (row) { return !row.hidden; });
      countLabel.textContent = String(visible.length);
    }
  });
})();
