# splunk-devops

Sends this build's event to Splunk's HTTP Event Collector - the HEC half of the
[splunk-devops](https://plugins.jenkins.io/splunk-devops/) plugin (`com.splunk.splunkins:splunk-devops` 1.11.2).

## What the plugin actually sends

`LogEventHelper#buildPost` wraps whatever the listeners produced in `EventRecord#toMap` and posts it:

- the envelope is `{"time": "<seconds>.<millis>", "event": {...}, "index": ..., "source": ..., "sourcetype": ...}`
  plus `host` when one is configured; `time` is `String.format(Locale.US, "%.3f", time / 1000d)` - seconds with
  exactly three decimals, not milliseconds;
- the request goes to `<scheme>://<host>:<port>/services/collector/event` with
  `Authorization: Splunk <token>`, a fresh upper-case UUID in `x-splunk-request-channel`, and the content type
  `application/json; profile=urn:splunk:event:1.0; charset=utf-8`;
- a body over `GZIP_THRESHOLD` (1 KiB) is gzipped and `Content-Encoding: gzip` is set;
- metadata defaults come from `metadata.properties`: `source=jenkins`, `sourcetype=json:jenkins`,
  `job_event.index=jenkins_statistics`, `build_report.index=jenkins`, and `getMetadataSource(suffix)` joins the
  source and the event name with `/` (`jenkins/job_event`, `jenkins/build_report`).

Two event shapes are reproduced here, both from the plugin:

**`job_event`** - `LoggingRunListener` on start (`type=started`) and completion (`type=completed`). Fields:
`event_tag=job_event`, `build_number`, `trigger_by`, `user` (`anonymous` when no cause names one), `queue_time`
(seconds, `0` when unknown), `queue_id`, `build_url`, `upstream`, `job_started_at`, `job_name`, `metadata` (build
parameters), `job_type`, `label` (omitted when empty), `node`, and on completion `job_duration` (seconds,
`run.getDuration()/1000f`), `job_result` and `test_summary` (`total`, `failures`, `passes`, `skips`, `duration`, where
`passes = total - failures - skips`, only when there are test results).

**`build_report`** - `RunDelegate#getBuildEvent`, used by the report DSL and by the test/coverage senders:
`event_tag=build_report`, `user`, `job_result`, `build_url`, `metadata`, `build_number`, `job_name`.

A third kind, **`custom`**, posts a caller-supplied JSON object as `event` with the `build_report` metadata, which is
what the plugin's DSL does.

## Differences worth knowing

- **A rejected event fails the step by default.** In the plugin a worker thread logs 400/401/403 and moves on, so the
  build stays green while nothing arrives. `failOnError` is true here.
- **Nothing is retried.** The plugin retries IO errors and 503 after 15 seconds out of a 131072-slot queue; a step is
  one process, so it sends once and reports.
- **`host` has no default.** The plugin falls back to `JenkinsLocationConfiguration`'s URL; a step cannot read the
  controller's location, so an empty `host` means the field is omitted (Splunk then uses the sender's address).
- **Sensitive parameters are named, not discovered.** `ParametersAction` knows which values are secret; an atom only
  sees strings, so `maskedParameters` lists the keys to replace with `***`.
- **`job_started_at` is rendered here.** The plugin calls `run.getTimestampString2()`, which is not on `Run` in core;
  the atom formats `jobStartedTimeMs` with the plugin's `LOG_TIME_FORMAT` (`yyyy-MM-dd'T'HH:mm:ss.SSSZ`).
- **Not ported:** console-log streaming (raw endpoint, `TeeConsoleLogFilter`), queue/agent/config/audit events,
  artifact and file uploads, JUnit/Coverage payloads beyond the summary, and the global Groovy DSL. The raw endpoint
  is a different wire format (text with metadata in the query string) and is not what this atom sends.

## Verification

`tools/check.py` starts a fake HEC that records the method, path, headers and raw body, gunzips when the atom says it
compressed, and parses the JSON. It then recomputes from the inputs what the envelope and the event must contain -
the three-decimal timestamp, the default index/source per event type, the field types (`build_number` and `queue_id`
as numbers, `job_duration` in seconds), the masked `metadata`, `passes = total - failures - skips`, which fields a
`started` event must not carry - and compares that with what arrived. The failure paths assert the HEC-specific
messages: 401/403 "token is invalid", 400 "incorrect index or invalid data format", 503 "server is busy", connection
refused, and that invalid inputs never reach the network.

15 checks, and `tools/mutations.py` plants 20 bugs (drops the `Splunk` scheme, sends milliseconds, lower-cases the
channel, loses the content-type profile, posts to `/raw`, wrong default index, string `build_number`, milliseconds
`job_duration`, passes ignoring skips, sends empty labels, no `anonymous` default, `started` with a duration, wrapped
custom event, no gzip, gzip without `Content-Encoding`, generic 401, `failOnError=false` still failing, dry run
sending) - all 20 are caught.

## Inputs

`url`, `token`, `eventKind` (`job_event` | `build_report` | `custom`), `jobEventType` (`started` | `completed`), the
build fields (`jobName`, `buildNumber`, `buildUrl`, `jobResult`, `jobDurationMs`, `jobStartedTimeMs`, `queueId`,
`queueTimeSeconds`, `user`, `triggerBy`, `upstream`, `node`, `label`, `jobType`, `parameters`, `maskedParameters`,
`testsTotal`/`testsFailed`/`testsSkipped`/`testsDurationSeconds`), `customEvent`, the metadata overrides (`index`,
`source`, `sourcetype`, `host`), `timestampMs`, `compress`, `dryRun`, `failOnError`, `timeoutSeconds`. `${VAR}` in an
input is expanded from the build environment, the same way the runner does it for every atom.

Outputs: `eventKind`, `endpoint`, `httpStatus`, `channel`, `bytes`, `gzipped`, `body` (the exact JSON posted, also the
only product of a dry run).
