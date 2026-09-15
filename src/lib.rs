pub mod assessment;
pub mod changes;
pub mod dashboard;
pub mod deep_validation;
pub mod evidence;
pub mod findings;
pub mod io;
pub mod models;
pub mod normalize;
pub mod public_checks;
pub mod scoring;
pub mod validation_mapping;

use std::collections::BTreeMap;

pub type Row = BTreeMap<String, String>;

pub fn text(row: &Row, field: &str) -> String {
    row.get(field).cloned().unwrap_or_default()
}

pub fn is_true(row: &Row, field: &str) -> bool {
    text(row, field).eq_ignore_ascii_case("true")
}

pub fn int_value(row: &Row, field: &str) -> i64 {
    text(row, field).trim().parse().unwrap_or(0)
}
