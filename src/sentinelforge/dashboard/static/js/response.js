/* SentinelForge response panel (Phase 7).
 *
 * The same rule as every other script here: telemetry and operator text reach
 * the DOM through textContent, never through innerHTML or an assembled markup
 * string. A target, a policy reason or a command line read from /proc is
 * displayed as text, and the page's Content-Security-Policy has no
 * 'unsafe-inline', so a mistake here still cannot become a working injection.
 *
 * The flow this file implements is the flow the engine enforces, and it does
 * not shortcut any of it:
 *
 *   preview  ->  explicit confirmation  ->  request  ->  approve  ->  execute
 *
 * Clicking "Request" records an action awaiting approval. It does not contain
 * anything. Approving does not execute. Every one of those is a separate HTTP
 * call that the analyst makes deliberately, and each one is confirmed first.
 */
(function () {
  "use strict";

  var form = document.getElementById("response-form");
  if (!form) { return; }

  var api = form.getAttribute("data-api") || "/api/response";
  var incidentId = form.getAttribute("data-incident-id") || null;
  var panel = document.getElementById("response-preview");
  var message = document.getElementById("response-message");
  var pending = null;

  function post(path, body) {
    return fetch(api + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // Same-origin only: the API refuses anything else, and the browser
      // should not be sending this anywhere but here.
      credentials: "same-origin",
      body: JSON.stringify(body || {})
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (data) {
        return { ok: response.ok, status: response.status, data: data };
      });
    });
  }

  function say(text, kind) {
    if (!message) { return; }
    message.textContent = text;
    message.className = "response-message" + (kind ? " response-" + kind : "");
    message.hidden = false;
  }

  function errorText(result) {
    var error = result && result.data && result.data.error;
    if (error && error.message) { return error.message; }
    return "the request failed (HTTP " + (result ? result.status : "?") + ")";
  }

  function setText(id, text) {
    var node = document.getElementById(id);
    if (node) { node.textContent = text === null || text === undefined ? "-" : String(text); }
  }

  function value(id) {
    var node = document.getElementById(id);
    return node ? node.value.trim() : "";
  }

  function currentRequest() {
    var ttl = value("response-ttl");
    var dryRunBox = document.getElementById("response-dry-run");
    return {
      action_type: value("response-action-type"),
      target: value("response-target"),
      reason: value("response-reason"),
      incident_id: incidentId,
      ttl: ttl === "" ? null : Number(ttl),
      dry_run: !!(dryRunBox && dryRunBox.checked)
    };
  }

  function renderPreview(request, payload) {
    var preview = payload.preview || {};
    var policy = payload.policy || {};
    setText("preview-action", preview.description || preview.action_type);
    setText("preview-target", preview.target);
    setText("preview-reason", request.reason || "(none given)");
    setText("preview-effect", preview.effect);
    setText(
      "preview-duration",
      preview.ttl_seconds ? preview.ttl_seconds + " seconds, then removed automatically"
                          : "until it is rolled back"
    );
    setText("preview-rollback", preview.reversible ? "Available" : "NOT POSSIBLE - this cannot be undone");
    setText(
      "preview-privilege",
      preview.requires_privilege ? (preview.privilege_hint || "administrative privileges required")
                                 : "no elevated privileges needed"
    );
    setText("preview-policy", (policy.allowed ? "ALLOWED: " : "REFUSED: ") + (policy.reason || ""));

    var warnings = document.getElementById("preview-warnings");
    if (warnings) {
      warnings.textContent = "";
      (preview.warnings || []).concat(policy.warnings || []).forEach(function (text) {
        var item = document.createElement("li");
        item.textContent = text;
        warnings.appendChild(item);
      });
    }

    var mode = document.getElementById("preview-mode");
    if (mode) {
      mode.textContent = request.dry_run
        ? "MODE: DRY RUN - this will be recorded, and no system change will be made."
        : "MODE: REAL - requesting records the action. It still has to be approved and executed before anything happens.";
    }

    var confirm = document.getElementById("response-confirm-button");
    if (confirm) {
      confirm.disabled = !payload.would_be_allowed;
      confirm.textContent = request.dry_run ? "Record this dry run" : "Request this action";
    }
    panel.hidden = false;
  }

  document.getElementById("response-preview-button").addEventListener("click", function () {
    var request = currentRequest();
    if (!request.target) { say("Enter a target first.", "error"); return; }
    say("Building a preview. Nothing has been changed.", "info");
    post("/preview", request).then(function (result) {
      if (!result.ok) { panel.hidden = true; say(errorText(result), "error"); return; }
      pending = request;
      renderPreview(request, result.data);
      say("Preview only: nothing has been requested, approved or executed.", "info");
    }).catch(function () { say("the dashboard could not reach the response API", "error"); });
  });

  document.getElementById("response-cancel-button").addEventListener("click", function () {
    pending = null;
    panel.hidden = true;
    say("Cancelled. Nothing was requested.", "info");
  });

  document.getElementById("response-confirm-button").addEventListener("click", function () {
    if (!pending) { return; }
    var request = pending;
    var question = request.dry_run
      ? "Record a dry run of " + request.action_type + " on " + request.target + "? Nothing will be changed."
      : "Request " + request.action_type + " on " + request.target +
        "?\n\nThis records the action for approval. It does NOT carry it out.";
    if (!window.confirm(question)) { return; }
    post("/request", request).then(function (result) {
      if (!result.ok) { say(errorText(result), "error"); return; }
      var action = result.data.action || {};
      panel.hidden = true;
      pending = null;
      say(
        action.dry_run
          ? action.action_id + " recorded as a DRY RUN. No system change was made. Reload to see it in the history."
          : action.action_id + " is awaiting approval. Nothing has been executed. Reload the page, then approve it.",
        "ok"
      );
    }).catch(function () { say("the dashboard could not reach the response API", "error"); });
  });

  Array.prototype.forEach.call(document.querySelectorAll("[data-target-value]"), function (button) {
    button.addEventListener("click", function () {
      var target = document.getElementById("response-target");
      var type = document.getElementById("response-action-type");
      if (target) { target.value = button.getAttribute("data-target-value"); }
      if (type && button.getAttribute("data-target-type")) {
        type.value = button.getAttribute("data-target-type");
      }
      panel.hidden = true;
    });
  });

  /* Approve / execute / reject / cancel / roll back, one deliberate click each. */
  var PROMPTS = {
    approve: "Approve {id}?\n\nThis records your approval. It does NOT execute the action.",
    execute: "EXECUTE {id}?\n\nThis changes this system now. Continue?",
    reject: "Reject {id}? It can never be executed afterwards.",
    cancel: "Cancel {id}?",
    rollback: "Roll back {id}? This removes the containment SentinelForge put in place."
  };

  Array.prototype.forEach.call(document.querySelectorAll("[data-response-action]"), function (button) {
    button.addEventListener("click", function () {
      var operation = button.getAttribute("data-response-action");
      var actionId = button.getAttribute("data-action-id");
      var prompt = (PROMPTS[operation] || "{id}?").replace("{id}", actionId);
      if (!window.confirm(prompt)) { return; }
      button.disabled = true;
      post("/" + operation + "/" + encodeURIComponent(actionId), {}).then(function (result) {
        button.disabled = false;
        if (!result.ok) { say(errorText(result), "error"); return; }
        var action = result.data.action || {};
        say(action.action_id + " is now " + String(action.status).replace(/_/g, " ") +
            (action.verification ? " - " + action.verification : "") + ". Reload to refresh the history.", "ok");
      }).catch(function () {
        button.disabled = false;
        say("the dashboard could not reach the response API", "error");
      });
    });
  });
})();
