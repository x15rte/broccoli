//! Default invariants: the DNS screen's serveExpiredTTL editor
//! cap stays >= the model default (a raised default must never become
//! un-editable). The expectation derives from the compiled defaults — no
//! literals — so changing either side alone fails.

use broccoli::model::DnsCfg;
use broccoli::model::dns::{DEFAULT_SERVE_EXPIRED_TTL, MAX_SERVE_EXPIRED_TTL};

#[test]
fn serve_expired_ttl_editor_cap_covers_the_model_default() {
    // The DNS screen edits serveExpiredTTL in the range 0..=MAX; if the cap
    // ever fell below the model default, a fresh install would load with an
    // un-editable value. Compile-time guard: the build fails, not the suite.
    const { assert!(MAX_SERVE_EXPIRED_TTL >= DEFAULT_SERVE_EXPIRED_TTL) }
    // The model default must be the canonical const, so a re-default cannot
    // silently dodge the guard above.
    assert_eq!(
        DnsCfg::default().serve_expired_ttl,
        Some(DEFAULT_SERVE_EXPIRED_TTL),
        "DnsCfg::default must seed the canonical DEFAULT_SERVE_EXPIRED_TTL"
    );
    // And the default sits inside the editor's range.
    assert!(
        (0..=MAX_SERVE_EXPIRED_TTL).contains(&DEFAULT_SERVE_EXPIRED_TTL),
        "model default {DEFAULT_SERVE_EXPIRED_TTL} must sit inside the editor range 0..={MAX_SERVE_EXPIRED_TTL}"
    );
}
