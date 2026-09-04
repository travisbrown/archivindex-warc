//! The `graph` command.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use archivindex_warc::parse::raw;
use archivindex_warc_ops::header::{REFERENCE_FIELDS, normalize_id};

/// Stable, distinguishable colors for the standard record types.
const TYPE_COLORS: [(&str, &str); 8] = [
    ("warcinfo", "#F4A261"),
    ("response", "#8ECAE6"),
    ("resource", "#FFD166"),
    ("request", "#90BE6D"),
    ("metadata", "#CDB4DB"),
    ("revisit", "#FFADAD"),
    ("conversion", "#B8C0FF"),
    ("continuation", "#A8DADC"),
];

/// Space between the diagram and the edge of its SVG viewport.
const DIAGRAM_PADDING: i64 = 40;

/// Font size for record IDs and key entries.
const GRAPH_FONT_SIZE: usize = 20;

/// Font size for relationship labels, kept smaller so labels fit between nodes.
const EDGE_FONT_SIZE: usize = 18;

/// What the command drew.
#[derive(Debug)]
pub struct GraphSummary {
    /// Number of record nodes.
    pub records: usize,
    /// Number of resolved record-reference arrows.
    pub references: usize,
}

/// The graph-relevant part of a raw record.
#[derive(Debug)]
struct Record {
    warc_type: String,
    id: Option<Vec<u8>>,
    references: Vec<Reference>,
}

impl Record {
    /// The graph's view of a record, taken from its header block alone.
    fn from_header(header: &raw::RecordHeader) -> Self {
        let warc_type = value(header, "WARC-Type")
            .map_or_else(|| "unknown".to_owned(), |value| value.to_ascii_lowercase());
        let id = header
            .get("WARC-Record-ID")
            .map(normalize_id)
            .filter(|id| !id.is_empty())
            .map(<[u8]>::to_vec);
        let references = REFERENCE_FIELDS
            .iter()
            .flat_map(|field| {
                header.get_all(field).map(|target| Reference {
                    field,
                    target: normalize_id(target).to_vec(),
                })
            })
            .collect();

        Self {
            warc_type,
            id,
            references,
        }
    }
}

/// One header field pointing from its record to another record ID.
#[derive(Debug)]
struct Reference {
    field: &'static str,
    target: Vec<u8>,
}

impl Reference {
    /// The field name without its `WARC-` prefix, in lower case.
    fn label(&self) -> String {
        self.field[5..].to_ascii_lowercase()
    }
}

/// Draw the records from `input`, writing the SVG or opening it in the default viewer.
///
/// The viewer reads the SVG after this returns, so without `output` the SVG is written to
/// [`viewer_path`], which each invocation replaces.
pub fn graph(input: &Path, output: Option<&Path>) -> Result<GraphSummary> {
    let records = read_records(input)?;
    let (source, references) = source(&records);
    let svg = render(&source)?;
    let path = output.map_or_else(viewer_path, Path::to_path_buf);

    fs::write(&path, svg).with_context(|| format!("cannot write {}", path.display()))?;
    if output.is_none() {
        open(&path)?;
    }

    Ok(GraphSummary {
        records: records.len(),
        references,
    })
}

/// The SVG file opened in a viewer: one per user, in the runtime directory where the platform
/// has one and the temporary directory otherwise.
fn viewer_path() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map_or_else(std::env::temp_dir, PathBuf::from)
        .join("archivindex-warc-graph.svg")
}

/// Render D2 source with enough viewport padding to keep it away from a browser window's edges.
fn render(source: &str) -> Result<Vec<u8>> {
    let options = d2_little::CompileOptions {
        pad: Some(DIAGRAM_PADDING),
        ..d2_little::CompileOptions::default()
    };
    let (_, svg) = d2_little::compile(source, &options)
        .map_err(|error| anyhow::anyhow!("cannot render record graph: {error}"))?;

    Ok(svg)
}

/// Read the records and retain just the header fields needed by the graph.
///
/// Every record is taken from its header block and then refused, so no body is buffered and
/// the iteration yields only read errors.
fn read_records(path: &Path) -> Result<Vec<Record>> {
    let mut records = Vec::new();
    let refused = archivindex_warc_ops::file::open(path)?
        .filter_raw_records(|header| {
            records.push(Record::from_header(header));
            false
        })
        .records();

    for result in refused {
        result.with_context(|| format!("cannot read {}", path.display()))?;
    }

    Ok(records)
}

/// Turn the records into D2 source, one column of records in file order, and count the
/// relationships that resolve within the file.
fn source(records: &[Record]) -> (String, usize) {
    let labels = labels(records);
    let colors = colors(records);
    let mut source =
        String::from("grid-rows: 1\ngrid-gap: 60\nrecords: {\n  label: \"\"\n  grid-columns: 1\n");

    for (index, record) in records.iter().enumerate() {
        let color = colors
            .get(&record.warc_type)
            .expect("invariant violation: every record type has a color");
        write!(
            source,
            "  record_{index}: \"{}\" {{\n    style.fill: \"{color}\"\n    style.font-size: {GRAPH_FONT_SIZE}\n  }}\n",
            escape(&labels[index])
        )
        .expect("invariant violation: writing to a String");
    }
    source.push_str("}\nkey: {\n  label: \"\"\n  grid-columns: 1\n");
    for (index, (record_type, color)) in colors.iter().enumerate() {
        write!(
            source,
            "  type_{index}: \"{}\" {{\n    style.fill: \"{color}\"\n    style.font-size: {GRAPH_FONT_SIZE}\n  }}\n",
            escape(record_type)
        )
        .expect("invariant violation: writing to a String");
    }
    source.push_str("}\n");

    let targets: HashMap<&[u8], usize> = records
        .iter()
        .enumerate()
        .filter_map(|(index, record)| record.id.as_deref().map(|id| (id, index)))
        .collect();
    let mut reference_count = 0;
    for (source_index, record) in records.iter().enumerate() {
        for reference in &record.references {
            if let Some(target_index) = targets.get(reference.target.as_slice()) {
                write!(
                    source,
                    "{} -> {}: \"{}\" {{\n  style.font-size: {EDGE_FONT_SIZE}\n}}\n",
                    node_path(source_index),
                    node_path(*target_index),
                    reference.label()
                )
                .expect("invariant violation: writing to a String");
                reference_count += 1;
            } else {
                log::warn!(
                    "not drawing {} reference to absent record {}",
                    reference.label(),
                    String::from_utf8_lossy(&reference.target)
                );
            }
        }
    }

    (source, reference_count)
}

/// The D2 path of a record.
fn node_path(index: usize) -> String {
    format!("records.record_{index}")
}

/// Labels derived from record IDs, with UUID prefixes extended when eight characters collide.
fn labels(records: &[Record]) -> Vec<String> {
    let uuid_parts: Vec<Option<&str>> = records
        .iter()
        .map(|record| record.id.as_deref().and_then(uuid_part))
        .collect();
    let mut sorted: Vec<&str> = uuid_parts.iter().flatten().copied().collect();
    sorted.sort_unstable();
    sorted.dedup();

    records
        .iter()
        .enumerate()
        .map(
            |(index, record)| match (uuid_parts[index], record.id.as_deref()) {
                (Some(uuid), _) => unique_prefix(uuid, &sorted).to_owned(),
                (None, Some(id)) => shorten(&String::from_utf8_lossy(id)),
                (None, None) => format!("record {} (no ID)", index + 1),
            },
        )
        .collect()
}

/// The shortest prefix of at least eight characters that no other UUID begins with.
///
/// `sorted` holds every UUID once, in order, so the UUIDs sharing the longest prefix with `uuid`
/// are its neighbors there.
fn unique_prefix<'uuid>(uuid: &'uuid str, sorted: &[&str]) -> &'uuid str {
    let position = sorted
        .binary_search(&uuid)
        .expect("invariant violation: every UUID is in the sorted list");
    let shared = [position.checked_sub(1), Some(position + 1)]
        .into_iter()
        .flatten()
        .filter_map(|neighbor| sorted.get(neighbor))
        .map(|other| {
            uuid.bytes()
                .zip(other.bytes())
                .take_while(|(left, right)| left == right)
                .count()
        })
        .max()
        .unwrap_or(0);

    &uuid[..uuid.len().min((shared + 1).max(8))]
}

/// A color for every record type present, in key order.
fn colors(records: &[Record]) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let mut generated: u16 = 0;

    for record in records {
        result.entry(record.warc_type.clone()).or_insert_with(|| {
            TYPE_COLORS
                .iter()
                .find_map(|(record_type, color)| {
                    (*record_type == record.warc_type).then(|| (*color).to_owned())
                })
                .unwrap_or_else(|| {
                    let hue = (generated * 137 + 25) % 360;
                    generated += 1;
                    hsl_color(hue)
                })
        });
    }

    result
}

/// Convert a moderately saturated, light HSL hue to a D2-compatible RGB color.
///
/// The hue is a degree in `0..360`. Every channel is a rounded value in `0.0..=255.0`, so it
/// converts to `u8` unchanged.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "every channel is a rounded value in `0.0..=255.0`"
)]
fn hsl_color(hue: u16) -> String {
    let chroma = 0.45_f64;
    let sector = f64::from(hue) / 60.0;
    let intermediate = chroma * (1.0 - (sector.rem_euclid(2.0) - 1.0).abs());
    let (red, green, blue) = match hue / 60 {
        0 => (chroma, intermediate, 0.0),
        1 => (intermediate, chroma, 0.0),
        2 => (0.0, chroma, intermediate),
        3 => (0.0, intermediate, chroma),
        4 => (intermediate, 0.0, chroma),
        _ => (chroma, 0.0, intermediate),
    };
    let offset = 0.775 - chroma / 2.0;
    let channel = |value: f64| ((value + offset) * 255.0).round() as u8;

    format!(
        "#{:02X}{:02X}{:02X}",
        channel(red),
        channel(green),
        channel(blue)
    )
}

/// The trimmed text value of a header field.
fn value(header: &raw::RecordHeader, name: &str) -> Option<String> {
    header
        .get(name)
        .map(<[u8]>::trim_ascii)
        .filter(|value| !value.is_empty())
        .map(|value| String::from_utf8_lossy(value).into_owned())
}

/// The UUID portion of a `urn:uuid` record ID.
fn uuid_part(id: &[u8]) -> Option<&str> {
    let id = std::str::from_utf8(id).ok()?;
    let prefix = id.get(..9)?;

    (prefix.eq_ignore_ascii_case("urn:uuid:") && id[9..].is_ascii()).then(|| &id[9..])
}

/// Keep short identifiers whole and both ends of long identifiers.
fn shorten(id: &str) -> String {
    const MAX: usize = 28;
    const START: usize = 17;
    const END: usize = 8;

    if id.chars().count() <= MAX {
        return id.to_owned();
    }

    let start: String = id.chars().take(START).collect();
    let end: String = id
        .chars()
        .rev()
        .take(END)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{start}…{end}")
}

/// Escape a D2 double-quoted label.
fn escape(label: &str) -> String {
    label.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Open a file in the platform's default graphical viewer.
fn open(path: &Path) -> Result<()> {
    for mut command in viewer_commands(path) {
        if command.status().is_ok_and(|status| status.success()) {
            return Ok(());
        }
    }

    anyhow::bail!("cannot open {} in a viewer window", path.display())
}

#[cfg(target_os = "macos")]
fn viewer_commands(path: &Path) -> Vec<Command> {
    let mut command = Command::new("open");
    command.arg("-n").arg(path);
    vec![command]
}

#[cfg(target_os = "windows")]
fn viewer_commands(path: &Path) -> Vec<Command> {
    let mut command = Command::new("explorer.exe");
    command.arg(path);
    vec![command]
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn viewer_commands(path: &Path) -> Vec<Command> {
    let mut firefox = Command::new("firefox");
    firefox.arg("--new-window").arg(path);

    let mut default = Command::new("xdg-open");
    default.arg(path);

    vec![firefox, default]
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST: &str = "urn:uuid:12345678-a000-4000-8000-000000000000";
    const SECOND: &str = "urn:uuid:12345678-b000-4000-8000-000000000000";

    fn record(warc_type: &str, id: Option<&str>, references: &[(&'static str, &str)]) -> Record {
        Record {
            warc_type: warc_type.to_owned(),
            id: id.map(|id| id.as_bytes().to_vec()),
            references: references
                .iter()
                .map(|(field, target)| Reference {
                    field,
                    target: target.as_bytes().to_vec(),
                })
                .collect(),
        }
    }

    #[test]
    fn uuid_labels_expand_past_collisions() {
        let records = [
            record("request", Some(FIRST), &[]),
            record("response", Some(SECOND), &[]),
        ];

        assert_eq!(labels(&records), ["12345678-a", "12345678-b"]);
    }

    #[test]
    fn repeated_uuids_do_not_expand_each_other() {
        let records = [
            record("request", Some(FIRST), &[]),
            record("response", Some(FIRST), &[]),
        ];

        assert_eq!(labels(&records), ["12345678", "12345678"]);
    }

    #[test]
    fn source_has_colored_key_and_directed_references() {
        let records = [
            record("request", Some(FIRST), &[("WARC-Concurrent-To", SECOND)]),
            record("response", Some(SECOND), &[("WARC-Warcinfo-ID", "absent")]),
        ];

        let (source, count) = source(&records);

        assert!(source.contains("records: {\n  label: \"\""));
        assert!(source.contains("key: {\n  label: \"\""));
        assert!(source.starts_with("grid-rows: 1"));
        assert!(source.contains("records: {\n  label: \"\"\n  grid-columns: 1"));
        assert!(!source.contains("style.opacity"));
        assert!(source.contains("\"request\" {\n    style.fill: \"#90BE6D\""));
        assert!(source.contains("\"response\" {\n    style.fill: \"#8ECAE6\""));
        assert!(source.contains("records.record_0 -> records.record_1: \"concurrent-to\""));
        assert!(!source.contains("warcinfo-id\"\n"));
        assert_eq!(count, 1);
    }

    #[test]
    fn generated_source_renders_as_svg() {
        let records = [
            record("request", Some(FIRST), &[("WARC-Concurrent-To", SECOND)]),
            record("response", Some(SECOND), &[]),
        ];
        let (source, _) = source(&records);

        let svg = render(&source).unwrap();

        assert!(svg.windows(4).any(|window| window == b"<svg"));
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    #[test]
    fn linux_prefers_a_separate_firefox_window() {
        let commands = viewer_commands(Path::new("graph.svg"));

        assert_eq!(commands[0].get_program(), "firefox");
        assert_eq!(
            commands[0].get_args().collect::<Vec<_>>(),
            ["--new-window", "graph.svg"]
        );
        assert_eq!(commands[1].get_program(), "xdg-open");
    }
}
