#!/usr/bin/env python3
"""Plant one bug at a time in the atom and prove the checks catch it.

A green suite means nothing if it stays green for a broken atom. Each mutation is one textual change to the real
source; the mutated tree is rebuilt and the named case must fail. A surviving mutation is a hole in the suite.

    python3 tools/mutations.py
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent.parent
CODE = "splunk-devops"
SOURCE = HERE / "src" / "main" / "java" / "com" / "jenkinschina" / "atom" / "splunkdevops" / "SplunkDevopsAtom.java"

MUTATIONS = [
    ("the Authorization header drops the 'Splunk ' scheme",
     '.header("Authorization", "Splunk " + token)', '.header("Authorization", token)', "job-event-completed"),
    ("the event time is written in milliseconds, not seconds with three decimals",
     'String.format(Locale.US, "%.3f", timestampMs / 1000d)', 'String.format(Locale.US, "%.3f", (double) timestampMs)',
     "job-event-completed"),
    ("the request channel is a lower-case UUID",
     'UUID.randomUUID().toString().toUpperCase(Locale.ROOT)', 'UUID.randomUUID().toString().toLowerCase(Locale.ROOT)',
     "job-event-completed"),
    ("the HEC content type loses its profile",
     'static final String CONTENT_TYPE = "application/json; profile=urn:splunk:event:1.0; charset=utf-8";',
     'static final String CONTENT_TYPE = "application/json";', "job-event-completed"),
    ("events are posted to the raw endpoint instead of the JSON one",
     'static final String JSON_ENDPOINT = "/services/collector/event";',
     'static final String JSON_ENDPOINT = "/services/collector/raw";', "job-event-completed"),
    ("job events land in the build_report index",
     '"job_event", "jenkins_statistics",', '"job_event", "jenkins",', "job-event-completed"),
    ("job events claim the plain jenkins source, without the event suffix",
     'source = DEFAULT_SOURCE_PREFIX + "/" + (kind.equals("custom") ? "build_report" : kind);',
     'source = DEFAULT_SOURCE_PREFIX;', "job-event-completed"),
    ("build_number is serialised as a string",
     'event.put("event_tag", JOB_EVENT_TAG);\n        event.put("build_number", buildNumber);',
     'event.put("event_tag", JOB_EVENT_TAG);\n        event.put("build_number", String.valueOf(buildNumber));',
     "job-event-completed"),
    ("job_duration stays in milliseconds",
     'return durationMs / 1000f;', 'return durationMs;', "job-event-completed"),
    ("queue_time is sent as a string",
     'event.put("queue_time", parseFloat(context, "queueTimeSeconds", context.getParam("queueTimeSeconds", ""), 0f, 40007));',
     'event.put("queue_time", context.getParam("queueTimeSeconds", "0"));', "job-event-completed"),
    ("test passes ignore the skipped tests",
     'summary.put("passes", Math.max(0, totalCount - failed - skipped));',
     'summary.put("passes", Math.max(0, totalCount - failed));', "job-event-completed"),
    ("an empty label is sent anyway",
     'String label = expand(context, context.getParam("label", "")).trim();\n        if (!label.isEmpty()) {\n            event.put("label", label);\n        }',
     'String label = expand(context, context.getParam("label", "")).trim();\n        event.put("label", label);',
     "job-event-completed"),
    ("no user becomes an empty string instead of anonymous",
     'user = "anonymous";', 'user = "";', "job-event-started"),
    ("a started event also carries job_duration",
     'event.put("type", eventType);\n        if (eventType.equals("completed")) {',
     'event.put("type", eventType);\n        if (true) {', "job-event-started"),
    ("the custom event is wrapped instead of sent verbatim",
     'event.putAll(object);', 'event.put("value", object);', "custom-event"),
    ("a body over 1KiB is not gzipped",
     'static final int GZIP_THRESHOLD = 1024;', 'static final int GZIP_THRESHOLD = 1 << 20;', "gzip-large"),
    ("gzip is used but Content-Encoding is left out",
     'request.header("Content-Encoding", "gzip");', '// Content-Encoding lost', "gzip-large"),
    ("a 401 is reported as a generic error, losing the token hint",
     'message = reason + ", http event collector token is invalid";', 'message = reason;', "reject-401"),
    ("failOnError=false still fails the step",
     'if (!failOnError) {\n            context.log("[splunk] " + message + " (failOnError=false, continuing)");',
     'if (false) {\n            context.log("[splunk] " + message + " (failOnError=false, continuing)");',
     "fail-on-error-false"),
    ("dry run sends the event anyway",
     'if (dryRun) {', 'if (false) {', "dry-run"),
]


def sdk_jar():
    env = os.environ.get("SDK_JAR")
    if env:
        return env
    candidates = sorted((HERE.parent / "jenkins-atom-sdk" / "target").glob("jenkins-atom-sdk-*.jar"))
    if not candidates:
        raise SystemExit("build the SDK first: cd ../jenkins-atom-sdk && ./build.sh")
    return str(candidates[-1])


def build(tree):
    env = dict(os.environ)
    env["SDK_JAR"] = sdk_jar()
    proc = subprocess.run(["bash", "build.sh"], cwd=tree, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        return None, proc.stderr[-1500:]
    return tree / "dist" / CODE / (CODE + ".jar"), proc.stdout


def main():
    failures = 0
    for index, (name, old, new, case) in enumerate(MUTATIONS, 1):
        tree = pathlib.Path(tempfile.mkdtemp(prefix=CODE + "-mut-")) / "atom"
        shutil.copytree(HERE, tree, ignore=shutil.ignore_patterns("dist", ".git", "__pycache__"))
        source = tree / SOURCE.relative_to(HERE)
        text = source.read_text()
        if old not in text:
            print("SKIP  %s: the mutation no longer matches the source" % name)
            failures += 1
            continue
        source.write_text(text.replace(old, new, 1))
        jar, output = build(tree)
        if jar is None:
            print("SKIP  %s: the mutated atom does not build: %s" % (name, output))
            failures += 1
            continue
        proc = subprocess.run([sys.executable, "tools/check.py", "run", case, "--jar", str(jar)],
                              cwd=tree, capture_output=True, text=True)
        if proc.returncode == 0:
            print("SURVIVED %-2d %s (case %s stayed green)" % (index, name, case))
            failures += 1
        else:
            print("caught   %-2d %s" % (index, name))
    print("\n%d/%d mutations caught" % (len(MUTATIONS) - failures, len(MUTATIONS)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
