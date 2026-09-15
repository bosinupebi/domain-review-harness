use crate::Row;
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

pub fn read_csv(path: impl AsRef<Path>) -> Result<Vec<Row>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut reader =
        csv::Reader::from_path(path).with_context(|| format!("open CSV {}", path.display()))?;
    let headers = reader.headers()?.clone();
    let mut rows = Vec::new();
    for record in reader.records() {
        let record = record?;
        rows.push(
            headers
                .iter()
                .zip(record.iter())
                .map(|(key, value)| (key.to_string(), value.trim().to_string()))
                .collect(),
        );
    }
    Ok(rows)
}

pub fn write_csv(path: impl AsRef<Path>, rows: &[Row]) -> Result<()> {
    write_csv_with_fields(path, rows, &[])
}

pub fn write_csv_with_fields(
    path: impl AsRef<Path>,
    rows: &[Row],
    preferred_fields: &[&str],
) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let all_fields: BTreeSet<String> = rows.iter().flat_map(|row| row.keys().cloned()).collect();
    let mut fields: Vec<String> = preferred_fields
        .iter()
        .filter(|field| all_fields.contains(**field) || rows.is_empty())
        .map(|field| (*field).to_string())
        .collect();
    fields.extend(
        all_fields
            .into_iter()
            .filter(|field| !preferred_fields.contains(&field.as_str())),
    );
    let mut writer = csv::WriterBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .from_path(path)?;
    writer.write_record(fields.iter())?;
    for row in rows {
        writer.write_record(
            fields
                .iter()
                .map(|field| row.get(field).map(String::as_str).unwrap_or("")),
        )?;
    }
    writer.flush()?;
    Ok(())
}

pub fn write_jsonl<T: serde::Serialize>(path: impl AsRef<Path>, rows: &[T]) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut writer = BufWriter::new(File::create(path)?);
    for row in rows {
        serde_json::to_writer(&mut writer, row)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}
