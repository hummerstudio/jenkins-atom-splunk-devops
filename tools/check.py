#!/usr/bin/env python3
"""Behaviour checks for the splunk-devops atom.

Nothing here trusts the atom. A fake Splunk HTTP Event Collector records the request exactly as it arrived: method,
path, every header, the raw body (gunzipped when the atom says it compressed) and the parsed JSON. This script then
recomputes, from the atom's inputs and from the plugin's own rules (EventRecord#toMap, EventRecord#getMetaData,
LogEventHelper#buildPost, LoggingRunListener#getCommonBuildInfo, metadata.properties), what the envelope and the event
body must contain, and compares that with what the collector received.

    python3 tools/check.py all --jar dist/splunk-devops/splunk-devops.jar
    python3 tools/check.py run job-event-completed --jar ...
"""
import argparse
import gzip
import http.server
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import traceback

ENDPOINT = "/services/collector/event"
CONTENT_TYPE = "application/json; profile=urn:splunk:event:1.0; charset=utf-8"
CHANNEL_RE = re.compile(r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$")
TIME_RE = re.compile(r"^\d+\.\d{3}$")
STARTED_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{4}$")

DEFAULT_INDEX = {"job_event": "jenkins_statistics", "build_report": "jenkins", "custom": "jenkins"}
DEFAULT_SOURCE = {"job_event": "jenkins/job_event", "build_report": "jenkins/build_report", "custom": "jenkins/build_report"}


# ------------------------------------------------------------------ fake HEC

class Collector:
    """A fake Splunk HEC: records everything, answers with a status the test picks."""

    def __init__(self):
        self.records = []
        self.status = 200
        self.reasons = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
                        404: "Not Found", 503: "Service Unavailable"}
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                record = {
                    "path": self.path,
                    "method": "POST",
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "raw": raw,
                    "compressed": (self.headers.get("Content-Encoding") or "").lower() == "gzip",
                }
                if record["compressed"]:
                    try:
                        record["body"] = gzip.decompress(raw).decode("utf-8")
                    except OSError as e:
                        record["gunzipError"] = str(e)
                        record["body"] = None
                else:
                    record["body"] = raw.decode("utf-8", "replace")
                try:
                    record["json"] = json.loads(record["body"]) if record["body"] else None
                except ValueError:
                    record["json"] = None
                outer.records.append(record)
                status = outer.status
                payload = json.dumps({"text": "ok", "code": 0} if status == 200 else
                                     {"text": outer.reasons.get(status, "error"), "code": status}).encode()
                self.send_response(status, outer.reasons.get(status, ""))
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def url(self):
        return "http://127.0.0.1:%d" % self.server.server_address[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def last(self):
        if not self.records:
            raise AssertionError("the collector received no request at all")
        return self.records[-1]


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# ------------------------------------------------------------------ atom runner

def run_atom(jar, params, secrets=None, env_extra=None):
    jar = os.path.abspath(jar)
    directory = tempfile.mkdtemp(prefix="splunk-")
    json.dump(params, open(os.path.join(directory, "input.json"), "w"), ensure_ascii=False)
    json.dump(secrets if secrets is not None else {}, open(os.path.join(directory, ".secrets.json"), "w"))
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    env.update({"atom_data_dir": directory, "atom_data_input": "input.json",
                "atom_data_output": "output.json", "atom_workspace": directory})
    java = os.path.join(os.environ["JAVA_HOME"], "bin", "java") if os.environ.get("JAVA_HOME") else "java"
    proc = subprocess.run([java, "-cp", jar, "com.jenkinschina.atom.sdk.AtomRunner"], cwd=directory, env=env,
                          capture_output=True, text=True, timeout=180)
    path = os.path.join(directory, "output.json")
    if not os.path.exists(path):
        raise AssertionError("the atom wrote no output.json: %s\n%s" % (proc.returncode, proc.stderr[-2000:]))
    return json.load(open(path)), proc, directory


def data(out, key):
    field = out.get("data", {}).get(key)
    if field is None:
        raise AssertionError("output '%s' is missing; have %s" % (key, list(out.get("data", {}))))
    return field.get("value")


def ok(out, note=""):
    assert out.get("status") == "success", "expected success, got %s: %s" % (out.get("status"), out.get("message"))


def failed(out, note=""):
    assert out.get("status") in ("failure", "error"), "expected a failure, got %s: %s" % (out.get("status"), out.get("message"))


def sent(out, collector):
    """The one request the atom must have made, parsed, plus the atom's own claims about it."""
    record = collector.last()
    assert record["path"] == ENDPOINT, "posted to %s, not %s" % (record["path"], ENDPOINT)
    assert record["json"] is not None, "body is not JSON: %r" % (record["body"] or record.get("gunzipError"))
    claims = data(out, "body")
    return record, record["json"], claims


def check_headers(record, token):
    headers = record["headers"]
    assert headers.get("authorization") == "Splunk " + token, \
        "Authorization is %r, the HEC header is 'Splunk <token>'" % headers.get("authorization")
    assert headers.get("content-type") == CONTENT_TYPE, "Content-Type is %r" % headers.get("content-type")
    channel = headers.get("x-splunk-request-channel")
    assert channel and CHANNEL_RE.match(channel), \
        "x-splunk-request-channel must be an upper-case UUID, got %r" % channel
    return channel


def check_envelope(body, kind, index=None, source=None, sourcetype="json:jenkins", host=None):
    allowed = {"time", "event", "index", "source", "sourcetype", "host"}
    extra = set(body) - allowed
    assert not extra, "envelope has keys the plugin never writes: %s" % sorted(extra)
    assert set(body) >= {"time", "event", "index", "source", "sourcetype"}, \
        "envelope is missing %s" % sorted({"time", "event", "index", "source", "sourcetype"} - set(body))
    assert TIME_RE.match(str(body["time"])), "time must be seconds with three decimals, got %r" % body["time"]
    assert isinstance(body["event"], dict), "event must be a JSON object"
    assert body["index"] == (index or DEFAULT_INDEX[kind]), "index is %r, expected %r" % (body["index"], index or DEFAULT_INDEX[kind])
    assert body["source"] == (source or DEFAULT_SOURCE[kind]), "source is %r, expected %r" % (body["source"], source or DEFAULT_SOURCE[kind])
    assert body["sourcetype"] == sourcetype, "sourcetype is %r" % body["sourcetype"]
    if host:
        assert body.get("host") == host, "host is %r, expected %r" % (body.get("host"), host)
    else:
        assert "host" not in body, "host must be omitted when the input is blank, got %r" % body.get("host")


def check_time(body, timestamp_ms):
    got = float(body["time"])
    want = timestamp_ms / 1000.0
    assert abs(got - want) < 0.0005, "time %s is not %s seconds" % (got, want)


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def base_params(url, token="abc-123", **extra):
    params = {
        "url": url,
        "token": token,
        "jobName": "team/api/build",
        "buildNumber": "42",
        "buildUrl": "job/team/job/api/job/build/42/",
        "node": "linux-01",
        "timestampMs": "1700000000123",
    }
    params.update(extra)
    return params


# ------------------------------------------------------------------ checks

def check_job_event_completed(jar):
    with Collector() as collector:
        params = base_params(
            collector.url(),
            jobEventType="completed",
            jobResult="SUCCESS",
            jobDurationMs="12345",
            jobStartedTimeMs="1700000000000",
            queueId="1701",
            queueTimeSeconds="2.5",
            user="alice",
            triggerBy="Started by user alice",
            upstream="job/team/job/upstream/7/",
            label="", jobType="Freestyle project",
            parameters="BRANCH=main\nTOKEN=abc123\nEMPTY=",
            maskedParameters="TOKEN",
            testsTotal="10", testsFailed="2", testsSkipped="1", testsDurationSeconds="3.25",
        )
        out, _, _ = run_atom(jar, params)
        ok(out)
        record, body, claims = sent(out, collector)
        channel = check_headers(record, "abc-123")
        assert data(out, "channel") == channel, "the atom reported a different channel than it sent"
        check_envelope(body, "job_event")
        check_time(body, 1700000000123)
        assert json.loads(claims) == body, "the reported body is not the body that arrived"

        event = body["event"]
        expect = {
            "event_tag": "job_event", "build_number": 42, "type": "completed", "job_result": "SUCCESS",
            "job_name": "team/api/build", "node": "linux-01", "user": "alice",
            "trigger_by": "Started by user alice", "upstream": "job/team/job/upstream/7/",
            "build_url": "job/team/job/api/job/build/42/", "job_type": "Freestyle project",
            "queue_id": 1701, "queue_time": 2.5,
        }
        for key, value in expect.items():
            assert event.get(key) == value, "event[%r] is %r, expected %r" % (key, event.get(key), value)
        assert is_int(event["build_number"]), "build_number must be a JSON number, not a string"
        assert is_int(event["queue_id"]), "queue_id must be a JSON number"
        assert is_number(event["queue_time"]), "queue_time must be a JSON number"
        assert abs(event["job_duration"] - 12.345) < 0.001, \
            "job_duration must be seconds (12345ms -> 12.345), got %r" % event["job_duration"]
        assert STARTED_RE.match(event["job_started_at"]), "job_started_at format: %r" % event["job_started_at"]
        assert event["metadata"] == {"BRANCH": "main", "TOKEN": "***", "EMPTY": ""}, \
            "metadata is %r (maskedParameters must be written as ***)" % event["metadata"]
        assert event["test_summary"] == {"total": 10, "failures": 2, "passes": 7, "skips": 1, "duration": 3.25}, \
            "test_summary is %r (passes = total - failures - skips)" % event["test_summary"]
        assert "label" not in event, "an empty label must not be sent"
        assert record["compressed"] is False, "a small event must not be gzipped"


def check_job_event_started(jar):
    with Collector() as collector:
        params = base_params(collector.url(), jobEventType="started", queueId="7", queueTimeSeconds="0.25")
        out, _, _ = run_atom(jar, params)
        ok(out)
        record, body, _ = sent(out, collector)
        check_headers(record, "abc-123")
        check_envelope(body, "job_event")
        event = body["event"]
        assert event["type"] == "started"
        assert event["event_tag"] == "job_event"
        assert event["user"] == "anonymous", "no user -> 'anonymous', like getTriggerUserName"
        for key in ("job_duration", "job_result", "test_summary"):
            assert key not in event, "a started event must not carry %s" % key


def check_build_report(jar):
    with Collector() as collector:
        params = base_params(collector.url(), eventKind="build_report", jobResult="FAILURE",
                             parameters="OS=linux")
        out, _, _ = run_atom(jar, params)
        ok(out)
        record, body, _ = sent(out, collector)
        check_headers(record, "abc-123")
        check_envelope(body, "build_report")
        event = body["event"]
        assert event == {"event_tag": "build_report", "user": "anonymous", "job_result": "FAILURE",
                         "build_url": "job/team/job/api/job/build/42/", "metadata": {"OS": "linux"},
                         "build_number": 42, "job_name": "team/api/build"}, "build_report event is %r" % event


def check_custom(jar):
    with Collector() as collector:
        custom = '{"event_tag":"my_report","answer":42,"nested":{"ok":true},"text":"line\\nbreak"}'
        out, _, _ = run_atom(jar, {"url": collector.url(), "token": "t0k", "eventKind": "custom",
                                   "customEvent": custom, "timestampMs": "1700000000000"})
        ok(out)
        record, body, _ = sent(out, collector)
        check_headers(record, "t0k")
        check_envelope(body, "custom")
        assert body["event"] == json.loads(custom), "customEvent must be the event object verbatim: %r" % body["event"]


def check_metadata_overrides(jar):
    with Collector() as collector:
        params = base_params(collector.url(), index="my_index", source="my/source",
                             sourcetype="json:custom", host="jenkins-01")
        out, _, _ = run_atom(jar, params)
        ok(out)
        _, body, _ = sent(out, collector)
        check_envelope(body, "job_event", index="my_index", source="my/source",
                       sourcetype="json:custom", host="jenkins-01")


def check_gzip_large(jar):
    with Collector() as collector:
        big = "x" * 4000
        out, _, _ = run_atom(jar, {"url": collector.url(), "token": "t0k", "eventKind": "custom",
                                   "customEvent": json.dumps({"pad": big}), "timestampMs": "1700000000000"})
        ok(out)
        record, body, claims = sent(out, collector)
        assert record["raw"][:2] == b"\x1f\x8b", "a body over 1KiB must be gzipped (GZIP_THRESHOLD=1024)"
        assert record["headers"].get("content-encoding") == "gzip", "Content-Encoding: gzip is missing"
        assert data(out, "gzipped") == "true"
        assert body["event"]["pad"] == big, "the gunzipped body must still be the same event"
        assert int(data(out, "bytes")) == len(record["raw"]), "the reported byte count is the compressed length"
        assert json.loads(claims) == body


def check_gzip_disabled(jar):
    with Collector() as collector:
        big = "y" * 4000
        out, _, _ = run_atom(jar, {"url": collector.url(), "token": "t0k", "eventKind": "custom",
                                   "customEvent": json.dumps({"pad": big}), "compress": "false",
                                   "timestampMs": "1700000000000"})
        ok(out)
        record, _, _ = sent(out, collector)
        assert record["compressed"] is False, "compress=false must not gzip"
        assert data(out, "gzipped") == "false"


def check_rejected_401(jar):
    with Collector() as collector:
        collector.status = 401
        out, _, _ = run_atom(jar, base_params(collector.url(), token="bad"))
        failed(out)
        message = out.get("message", "")
        assert "token is invalid" in message, "401 must be reported as an invalid token: %r" % message
        assert data(out, "httpStatus") == "401"


def check_rejected_400(jar):
    with Collector() as collector:
        collector.status = 400
        out, _, _ = run_atom(jar, base_params(collector.url()))
        failed(out)
        assert "incorrect index or invalid data format" in out.get("message", ""), out.get("message")


def check_busy_503(jar):
    with Collector() as collector:
        collector.status = 503
        out, _, _ = run_atom(jar, base_params(collector.url()))
        failed(out)
        assert "busy" in out.get("message", "").lower(), out.get("message")


def check_fail_on_error_false(jar):
    with Collector() as collector:
        collector.status = 401
        out, _, _ = run_atom(jar, base_params(collector.url(), failOnError="false"))
        ok(out, "failOnError=false")
        assert data(out, "httpStatus") == "401"
        assert len(collector.records) == 1


def check_unreachable(jar):
    port = free_port()
    out, _, _ = run_atom(jar, {"url": "http://127.0.0.1:%d" % port, "token": "t0k",
                               "jobName": "a", "buildNumber": "1", "timestampMs": "1700000000000"})
    failed(out)
    assert "could not reach" in out.get("message", ""), out.get("message")


def check_dry_run(jar):
    with Collector() as collector:
        out, _, _ = run_atom(jar, base_params(collector.url(), dryRun="true"))
        ok(out)
        assert collector.records == [], "dry run must not send anything"
        body = json.loads(data(out, "body"))
        check_envelope(body, "job_event")
        check_time(body, 1700000000123)


def check_secret_token(jar):
    with Collector() as collector:
        params = base_params(collector.url())
        params.pop("token")
        out, _, _ = run_atom(jar, params, secrets={"token": "from-secret"})
        ok(out)
        record, _, _ = sent(out, collector)
        check_headers(record, "from-secret")


def check_error_paths(jar):
    out, _, _ = run_atom(jar, {"url": "http://127.0.0.1:1", "token": ""})
    failed(out)
    assert "token is required" in out.get("message", ""), out.get("message")
    out, _, _ = run_atom(jar, {"url": "ftp://x", "token": "t"})
    failed(out)
    assert "not an http(s) URL" in out.get("message", ""), out.get("message")
    with Collector() as collector:
        out, _, _ = run_atom(jar, base_params(collector.url(), eventKind="nope"))
        failed(out)
        assert "eventKind" in out.get("message", ""), out.get("message")
        out, _, _ = run_atom(jar, {"url": collector.url(), "token": "t", "jobName": "a",
                                   "buildNumber": "x", "timestampMs": "1700000000000"})
        failed(out)
        assert "buildNumber" in out.get("message", ""), out.get("message")
        out, _, _ = run_atom(jar, {"url": collector.url(), "token": "t", "jobName": "a",
                                   "buildNumber": "1", "eventKind": "custom", "customEvent": "[1,2]"})
        failed(out)
        assert "JSON object" in out.get("message", ""), out.get("message")
        assert collector.records == [], "invalid input must not reach the network"


CHECKS = [
    ("job-event-completed", check_job_event_completed),
    ("job-event-started", check_job_event_started),
    ("build-report", check_build_report),
    ("custom-event", check_custom),
    ("metadata-overrides", check_metadata_overrides),
    ("gzip-large", check_gzip_large),
    ("gzip-disabled", check_gzip_disabled),
    ("reject-401", check_rejected_401),
    ("reject-400", check_rejected_400),
    ("busy-503", check_busy_503),
    ("fail-on-error-false", check_fail_on_error_false),
    ("unreachable", check_unreachable),
    ("dry-run", check_dry_run),
    ("secret-token", check_secret_token),
    ("error-paths", check_error_paths),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["all", "run"])
    parser.add_argument("name", nargs="?")
    parser.add_argument("--jar", default="dist/splunk-devops/splunk-devops.jar")
    args = parser.parse_args()
    checks = CHECKS if args.command == "all" else [(n, f) for n, f in CHECKS if n == args.name]
    if not checks:
        print("unknown check %r; have %s" % (args.name, [n for n, _ in CHECKS]))
        return 2
    failures = 0
    for name, function in checks:
        try:
            function(args.jar)
            print("ok   %s" % name)
        except AssertionError as e:
            failures += 1
            print("FAIL %s: %s" % (name, e))
        except Exception:
            failures += 1
            print("ERROR %s:" % name)
            traceback.print_exc()
    print("%d/%d checks passed" % (len(checks) - failures, len(checks)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
