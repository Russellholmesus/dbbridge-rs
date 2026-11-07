use super::Metrics;
use std::time::Duration;

#[test]
fn spec_event_metrics_use_bounded_labels_and_real_buckets() {
    let m = Metrics::new();
    m.record_session_event("ingress", "resume", "success", "ws", "http-sse");
    m.record_session_event(
        "secret-role",
        "secret-event",
        "secret-reason",
        "secret-from",
        "secret-to",
    );
    m.observe_operation("ingress", "barrier", Duration::from_millis(20));
    let mut s = String::new();
    m.write_session_events(&mut s);
    m.write_operation_durations(&mut s);
    for want in [
        r#"event="resume""#,
        r#"from="ws",to="http-sse""#,
        r#"phase="barrier",le="0.05""#,
        "dbb_operation_duration_seconds_count",
    ] {
        assert!(s.contains(want), "missing {want} in:\n{s}");
    }
    assert!(!s.contains("secret-"), "unbounded labels leaked:\n{s}");
}
