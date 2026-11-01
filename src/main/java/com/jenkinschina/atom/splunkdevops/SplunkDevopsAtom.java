package com.jenkinschina.atom.splunkdevops;

import com.jenkinschina.atom.sdk.AtomContext;
import com.jenkinschina.atom.sdk.AtomResult;
import com.jenkinschina.atom.sdk.AtomTask;
import com.jenkinschina.atom.sdk.ErrorType;
import com.jenkinschina.atom.sdk.Json;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPOutputStream;

/**
 * Send a Jenkins build event to Splunk's HTTP Event Collector as JSON - the HEC half of the
 * {@code splunk-devops} plugin (com.splunk.splunkins:splunk-devops 1.11.2).
 *
 * <p>The plugin never builds its own HTTP: {@code LogEventHelper#buildPost} wraps the event map in an
 * {@code EventRecord#toMap} envelope ({@code time}, {@code event}, and the metadata keys {@code index}, {@code source},
 * {@code sourcetype}, {@code host}) and posts it to {@code /services/collector/event} with
 * {@code Authorization: Splunk <token>} and an upper-case {@code x-splunk-request-channel} UUID. The timestamp is
 * {@code String.format(Locale.US, "%.3f", ms / 1000d)}, i.e. seconds with exactly three decimals. Bodies over 1 KiB are
 * gzipped ({@code GZIP_THRESHOLD}), and the content type carries the HEC profile
 * {@code application/json; profile=urn:splunk:event:1.0; charset=utf-8}.
 *
 * <p>The event itself is one of three shapes the plugin sends: the {@code job_event} of
 * {@code LoggingRunListener} (started/completed), the {@code build_report} of {@code RunDelegate#getBuildEvent}, or a
 * caller-supplied JSON object. Defaults for index and source follow {@code metadata.properties}: job events go to
 * {@code jenkins_statistics} with source {@code jenkins/job_event}, build reports to {@code jenkins} with source
 * {@code jenkins/build_report}, and the sourcetype of a JSON event is {@code json:jenkins}.
 *
 * <p>Deliberate differences from the plugin, all because a step is one process rather than a queue worker: nothing is
 * retried, a rejected event fails the step (the plugin's worker only logs it), the event is sent once instead of being
 * held in a 131072-entry queue, and host defaults to unset instead of the Jenkins root URL (a step cannot read the
 * controller's location configuration).
 */
public class SplunkDevopsAtom implements AtomTask {

    /** com.splunk.splunkjenkins.Constants#JSON_ENDPOINT */
    static final String JSON_ENDPOINT = "/services/collector/event";
    /** LogEventHelper#updateContent's content type for JSON events. */
    static final String CONTENT_TYPE = "application/json; profile=urn:splunk:event:1.0; charset=utf-8";
    /** Constants#GZIP_THRESHOLD */
    static final int GZIP_THRESHOLD = 1024;
    /** Constants#MASK_PASSWORD */
    static final String MASK = "***";
    /** Constants#JOB_EVENT_TAG_NAME */
    static final String JOB_EVENT_TAG = "job_event";

    /** metadata.properties: per-event-type index, then the global fallback (jenkins_statistics). */
    static final Map<String, String> DEFAULT_INDEX = Map.of(
            "job_event", "jenkins_statistics",
            "build_report", "jenkins",
            "custom", "jenkins");
    /** metadata.properties: sourcetype for structured events. */
    static final String DEFAULT_SOURCETYPE = "json:jenkins";
    /** metadata.properties: source=jenkins, and getMetadataSource(suffix) joins with '/'. */
    static final String DEFAULT_SOURCE_PREFIX = "jenkins";

    static final Set<String> KINDS = Set.of("job_event", "build_report", "custom");

    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US).withZone(ZoneOffset.UTC);

    @Override
    public AtomResult run(AtomContext context) throws Exception {
        String rawUrl = expand(context, context.getParam("url", "")).trim();
        String token = firstNonEmpty(context.getSecret("token"), expand(context, context.getParam("token", ""))).trim();
        String kind = expand(context, context.getParam("eventKind", "job_event")).trim().toLowerCase(Locale.ROOT);
        String eventType = expand(context, context.getParam("jobEventType", "completed")).trim().toLowerCase(Locale.ROOT);
        int timeoutSeconds = Math.max(5, Math.min(context.getIntParam("timeoutSeconds", 30), 300));
        boolean dryRun = context.getBooleanParam("dryRun", false);
        boolean failOnError = context.getBooleanParam("failOnError", true);
        boolean compressParam = context.getBooleanParam("compress", true);

        if (rawUrl.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40001,
                    "url is required: the Splunk HTTP Event Collector base URL, e.g. https://splunk.example.com:8088");
        }
        URI endpoint = endpoint(rawUrl);
        if (endpoint == null) {
            return AtomResult.error(ErrorType.USER, 40001, "url is not an http(s) URL: " + rawUrl);
        }
        if (token.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40002,
                    "token is required: HEC tokens are sent as 'Authorization: Splunk <token>'");
        }
        if (!KINDS.contains(kind)) {
            return AtomResult.error(ErrorType.USER, 40003,
                    "eventKind must be job_event, build_report or custom, not '" + kind + "'");
        }
        if (!eventType.equals("started") && !eventType.equals("completed")) {
            return AtomResult.error(ErrorType.USER, 40003,
                    "jobEventType must be started or completed, not '" + eventType + "'");
        }

        String index = expand(context, context.getParam("index", "")).trim();
        String source = expand(context, context.getParam("source", "")).trim();
        String sourcetype = expand(context, context.getParam("sourcetype", "")).trim();
        String host = expand(context, context.getParam("host", "")).trim();

        if (index.isEmpty()) {
            index = DEFAULT_INDEX.getOrDefault(kind, "jenkins_statistics");
        }
        if (source.isEmpty()) {
            source = DEFAULT_SOURCE_PREFIX + "/" + (kind.equals("custom") ? "build_report" : kind);
        }
        if (sourcetype.isEmpty()) {
            sourcetype = DEFAULT_SOURCETYPE;
        }

        // ------------------------------------------------------------------ the event body
        Map<String, Object> event;
        try {
            event = buildEvent(context, kind, eventType);
        } catch (IllegalArgumentException e) {
            return AtomResult.error(ErrorType.USER, 40004, e.getMessage());
        }

        long timestampMs = parseLong(context, "timestampMs", context.getParam("timestampMs", ""),
                System.currentTimeMillis(), 40005);
        if (timestampMs < 0) {
            return AtomResult.error(ErrorType.USER, 40005, "timestampMs must be a non-negative epoch millisecond value");
        }

        // EventRecord#toMap: time first, event second, then whatever metadata is configured. Empty values are dropped
        // by UrlQueryBuilder#putIfAbsent (nonEmpty), and Gson (no serializeNulls) omits nulls.
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("time", String.format(Locale.US, "%.3f", timestampMs / 1000d));
        body.put("event", event);
        body.put("index", index);
        body.put("source", source);
        body.put("sourcetype", sourcetype);
        if (!host.isEmpty()) {
            body.put("host", host);
        }
        String json = Json.write(body);

        // A channel id is a HEC acknowledgement channel; the plugin sends a fresh upper-case UUID per request.
        String channel = UUID.randomUUID().toString().toUpperCase(Locale.ROOT);

        if (dryRun) {
            context.log("[splunk] dry run, would POST " + json.length() + " bytes to " + endpoint);
            return AtomResult.success("dry run: built the HEC event but sent nothing")
                    .data("eventKind", kind)
                    .data("endpoint", endpoint.getPath())
                    .data("channel", channel)
                    .data("bytes", String.valueOf(json.getBytes(StandardCharsets.UTF_8).length))
                    .data("gzipped", "false")
                    .data("body", json);
        }

        // ------------------------------------------------------------------ send it
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);
        boolean gzipped = compressParam && payload.length > GZIP_THRESHOLD;
        if (gzipped) {
            payload = gzip(payload);
        }

        HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .header("Content-Type", CONTENT_TYPE)
                .header("Authorization", "Splunk " + token)
                .header("x-splunk-request-channel", channel)
                .POST(HttpRequest.BodyPublishers.ofByteArray(payload));
        if (gzipped) {
            request.header("Content-Encoding", "gzip");
        }

        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(timeoutSeconds)).build();
        HttpResponse<String> response;
        try {
            response = client.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            String message = "could not reach Splunk HEC at " + endpoint + ": " + e;
            return failed(context, failOnError, message, kind, endpoint, channel, json, gzipped, -1);
        }

        int status = response.statusCode();
        String responseBody = response.body() == null ? "" : response.body().trim();
        if (status != 200) {
            String reason = reasonPhrase(status);
            String message;
            if (status == 401 || status == 403) {
                message = reason + ", http event collector token is invalid";
            } else if (status == 400) {
                message = reason + ", incorrect index or invalid data format";
            } else if (status == 503) {
                message = "Server is busy, maybe caused by blocked queue (HTTP 503)";
            } else {
                message = "Splunk HEC answered HTTP " + status + " " + reason;
            }
            if (!responseBody.isEmpty()) {
                message = message + ": " + abbreviate(responseBody);
            }
            return failed(context, failOnError, message, kind, endpoint, channel, json, gzipped, status);
        }

        context.log("[splunk] sent one " + kind + " event to " + endpoint.getPath()
                + " (HTTP 200, " + payload.length + " bytes" + (gzipped ? ", gzip" : "") + ")");
        return AtomResult.success("sent one " + kind + " event to Splunk HEC")
                .data("eventKind", kind)
                .data("endpoint", endpoint.getPath())
                .data("httpStatus", String.valueOf(status))
                .data("channel", channel)
                .data("bytes", String.valueOf(payload.length))
                .data("gzipped", String.valueOf(gzipped))
                .data("body", json);
    }

    // ------------------------------------------------------------------ event shapes

    private Map<String, Object> buildEvent(AtomContext context, String kind, String eventType) {
        Map<String, Object> event = new LinkedHashMap<>();

        if (kind.equals("custom")) {
            String custom = expand(context, context.getParam("customEvent", "")).trim();
            if (custom.isEmpty()) {
                throw new IllegalArgumentException("customEvent is required when eventKind=custom: a JSON object");
            }
            Object parsed;
            try {
                parsed = Json.parse(custom);
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("customEvent is not valid JSON: " + e.getMessage());
            }
            if (!(parsed instanceof Map)) {
                throw new IllegalArgumentException("customEvent must be a JSON object, not " + parsed.getClass().getSimpleName());
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> object = (Map<String, Object>) parsed;
            event.putAll(object);
            return event;
        }

        String jobName = expand(context, context.getParam("jobName", "${JOB_NAME}")).trim();
        if (jobName.isEmpty() || jobName.contains("${")) {
            throw new IllegalArgumentException("jobName is required (the plugin uses run.getParent().getFullName())");
        }
        int buildNumber = parseNonNegative(context, "buildNumber",
                expand(context, context.getParam("buildNumber", "${BUILD_NUMBER}")), 40006);
        if (buildNumber < 0) {
            throw new IllegalArgumentException("buildNumber must be a non-negative integer, not '"
                    + expand(context, context.getParam("buildNumber", "${BUILD_NUMBER}")) + "'");
        }

        String buildUrl = expand(context, context.getParam("buildUrl", "")).trim();
        String user = expand(context, context.getParam("user", "")).trim();
        if (user.isEmpty()) {
            // LogEventHelper#getTriggerUserName: "anonymous" when no cause names a user
            user = "anonymous";
        }
        Map<String, Object> parameters = parameters(context);

        if (kind.equals("build_report")) {
            // RunDelegate#getBuildEvent, used by sendTestReport/sendCoverageReport and the report DSL
            String result = expand(context, context.getParam("jobResult", "${BUILD_STATUS}")).trim().toUpperCase(Locale.ROOT);
            event.put("event_tag", "build_report");
            event.put("user", user);
            if (!result.isEmpty() && !result.contains("${")) {
                event.put("job_result", result);
            }
            event.put("build_url", buildUrl);
            if (!parameters.isEmpty()) {
                event.put("metadata", parameters);
            }
            event.put("build_number", buildNumber);
            event.put("job_name", jobName);
            return event;
        }

        // LoggingRunListener#getCommonBuildInfo
        event.put("event_tag", JOB_EVENT_TAG);
        event.put("build_number", buildNumber);
        event.put("trigger_by", expand(context, context.getParam("triggerBy", "")).trim());
        event.put("user", user);
        event.put("queue_time", parseFloat(context, "queueTimeSeconds", context.getParam("queueTimeSeconds", ""), 0f, 40007));
        event.put("queue_id", parseLong(context, "queueId", context.getParam("queueId", ""), 0L, 40007));
        event.put("build_url", buildUrl);
        event.put("upstream", expand(context, context.getParam("upstream", "")).trim());
        String startedAt = expand(context, context.getParam("jobStartedAt", "")).trim();
        if (startedAt.isEmpty()) {
            // run.getTimestampString2() is not on Run in core; the atom renders the start instant in the plugin's
            // LOG_TIME_FORMAT instead of guessing at that helper's private format.
            long startedMs = parseLong(context, "jobStartedTimeMs", context.getParam("jobStartedTimeMs", ""), 0L, 40007);
            startedAt = startedMs > 0 ? TIMESTAMP.format(Instant.ofEpochMilli(startedMs)) : "";
        }
        event.put("job_started_at", startedAt);
        event.put("job_name", jobName);
        if (!parameters.isEmpty()) {
            event.put("metadata", parameters);
        }
        String jobType = expand(context, context.getParam("jobType", "")).trim();
        if (!jobType.isEmpty()) {
            event.put("job_type", jobType);
        }
        String label = expand(context, context.getParam("label", "")).trim();
        if (!label.isEmpty()) {
            event.put("label", label);
        }
        event.put("node", expand(context, context.getParam("node", "${NODE_NAME}")).trim());

        event.put("type", eventType);
        if (eventType.equals("completed")) {
            float duration = runDuration(context);
            event.put("job_duration", duration);
            String result = expand(context, context.getParam("jobResult", "${BUILD_STATUS}")).trim().toUpperCase(Locale.ROOT);
            if (result.isEmpty() || result.contains("${")) {
                return event;
            }
            event.put("job_result", result);
            Map<String, Object> testSummary = testSummary(context);
            if (!testSummary.isEmpty()) {
                event.put("test_summary", testSummary);
            }
        }
        return event;
    }

    /**
     * LogEventHelper#getRunDuration: run.getDuration()/1000f, or (now - start)/1000f when the duration is under
     * 10ms or the run is still building. Here the duration is a step input; a zero falls back to now - start.
     */
    private float runDuration(AtomContext context) {
        long durationMs = parseLong(context, "jobDurationMs", context.getParam("jobDurationMs", ""), 0L, 40007);
        if (durationMs >= 10) {
            return durationMs / 1000f;
        }
        long startedMs = parseLong(context, "jobStartedTimeMs", context.getParam("jobStartedTimeMs", ""), 0L, 40007);
        if (startedMs > 0) {
            return Math.max(0f, (System.currentTimeMillis() - startedMs) / 1000f);
        }
        return 0f;
    }

    /** TestCaseResultUtils#getSummary: failures/passes/skips/total/duration, and only when there are results. */
    private Map<String, Object> testSummary(AtomContext context) {
        Map<String, Object> summary = new LinkedHashMap<>();
        String total = expand(context, context.getParam("testsTotal", "")).trim();
        if (total.isEmpty()) {
            return summary;
        }
        int totalCount = parseInt(context, "testsTotal", total, 0, 40008);
        int failed = parseInt(context, "testsFailed", context.getParam("testsFailed", ""), 0, 40008);
        int skipped = parseInt(context, "testsSkipped", context.getParam("testsSkipped", ""), 0, 40008);
        if (totalCount < 0 || failed < 0 || skipped < 0) {
            return summary;
        }
        summary.put("total", totalCount);
        summary.put("failures", failed);
        summary.put("passes", Math.max(0, totalCount - failed - skipped));
        summary.put("skips", skipped);
        summary.put("duration", parseFloat(context, "testsDurationSeconds", context.getParam("testsDurationSeconds", ""), 0f, 40008));
        return summary;
    }

    /** The {@code metadata} map: build parameters, with the named ones masked the way ParametersAction does. */
    private Map<String, Object> parameters(AtomContext context) {
        Map<String, Object> values = new LinkedHashMap<>();
        String text = expand(context, context.getParam("parameters", ""));
        if (text == null || text.isEmpty()) {
            return values;
        }
        Set<String> masked = new java.util.LinkedHashSet<>();
        for (String name : expand(context, context.getParam("maskedParameters", "")).split(",")) {
            if (!name.trim().isEmpty()) {
                masked.add(name.trim());
            }
        }
        for (String line : text.split("\\r?\\n")) {
            String row = line.trim();
            if (row.isEmpty() || row.startsWith("#")) {
                continue;
            }
            int eq = row.indexOf('=');
            if (eq <= 0) {
                throw new IllegalArgumentException("parameters must be key=value lines, got: " + row);
            }
            String key = row.substring(0, eq).trim();
            String value = row.substring(eq + 1).trim();
            values.put(key, masked.contains(key) ? MASK : value);
        }
        return values;
    }

    // ------------------------------------------------------------------ HTTP helpers

    private AtomResult failed(AtomContext context, boolean failOnError, String message, String kind, URI endpoint,
                              String channel, String json, boolean gzipped, int status) {
        if (!failOnError) {
            context.log("[splunk] " + message + " (failOnError=false, continuing)");
            return AtomResult.success(message)
                    .data("eventKind", kind)
                    .data("endpoint", endpoint.getPath())
                    .data("httpStatus", status < 0 ? "" : String.valueOf(status))
                    .data("channel", channel)
                    .data("bytes", String.valueOf(json.getBytes(StandardCharsets.UTF_8).length))
                    .data("gzipped", String.valueOf(gzipped))
                    .data("body", json);
        }
        return AtomResult.error(ErrorType.THIRD_PART, 40010, message)
                .data("eventKind", kind)
                .data("endpoint", endpoint.getPath())
                .data("httpStatus", status < 0 ? "" : String.valueOf(status))
                .data("channel", channel)
                .data("bytes", String.valueOf(json.getBytes(StandardCharsets.UTF_8).length))
                .data("gzipped", String.valueOf(gzipped))
                .data("body", json);
    }

    static URI endpoint(String rawUrl) {
        String trimmed = rawUrl.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
            return null;
        }
        if (!trimmed.endsWith("/services/collector/event") && !trimmed.contains("/services/collector/")) {
            trimmed = trimmed + JSON_ENDPOINT;
        }
        try {
            URI uri = URI.create(trimmed);
            if (uri.getHost() == null || uri.getHost().isEmpty()) {
                return null;
            }
            return uri;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** HttpResponse has no reason phrase in java.net.http, so the HEC statuses the plugin names are spelled here. */
    static String reasonPhrase(int status) {
        switch (status) {
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 409: return "Conflict";
            case 429: return "Too Many Requests";
            case 500: return "Internal Server Error";
            case 503: return "Service Unavailable";
            default: return "HTTP " + status;
        }
    }

    private static byte[] gzip(byte[] input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(input);
        }
        return out.toByteArray();
    }

    // ------------------------------------------------------------------ input helpers

    static String expand(AtomContext context, String value) {
        if (value == null || value.indexOf("${") < 0) {
            return value == null ? "" : value;
        }
        Matcher matcher = Pattern.compile("\\$\\{([A-Za-z_][A-Za-z0-9_]*)}").matcher(value);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String name = matcher.group(1);
            String replacement = context.getParam(name);
            if (replacement == null) {
                replacement = System.getenv(name);
            }
            matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement == null ? matcher.group() : replacement));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private static String firstNonEmpty(String a, String b) {
        if (a != null && !a.isEmpty()) {
            return a;
        }
        return b == null ? "" : b;
    }

    private static int parseNonNegative(AtomContext context, String name, String raw, int errorCode) {
        if (raw == null || raw.trim().isEmpty()) {
            return -1;
        }
        try {
            int value = Integer.parseInt(raw.trim());
            return value < 0 ? -1 : value;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static int parseInt(AtomContext context, String name, String raw, int fallback, int errorCode) {
        if (raw == null || raw.trim().isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " must be an integer, not '" + raw + "'");
        }
    }

    private static long parseLong(AtomContext context, String name, String raw, long fallback, int errorCode) {
        if (raw == null || raw.trim().isEmpty()) {
            return fallback;
        }
        try {
            return Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " must be an integer, not '" + raw + "'");
        }
    }

    private static float parseFloat(AtomContext context, String name, String raw, float fallback, int errorCode) {
        if (raw == null || raw.trim().isEmpty()) {
            return fallback;
        }
        try {
            return Float.parseFloat(raw.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " must be a number, not '" + raw + "'");
        }
    }

    private static String abbreviate(String text) {
        String oneLine = text.replace('\n', ' ').replace('\r', ' ').trim();
        return oneLine.length() <= 400 ? oneLine : oneLine.substring(0, 400) + "...";
    }
}
