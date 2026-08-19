//! The `graph` command.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use archivindex_warc::io::read::WarcReader;
use archivindex_warc::parse::raw;
use flate2::bufread::MultiGzDecoder;

/// Header fields whose values identify another WARC record.
const REFERENCE_FIELDS: [(&str, &str); 4] = [
    ("WARC-Concurrent-To", "concurrent-to"),
    ("WARC-Warcinfo-ID", "warcinfo-id"),
    ("WARC-Refers-To", "refers-to"),
    ("WARC-Segment-Origin-ID", "segment-origin-id"),
];

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
    record_type: String,
    id: Option<Vec<u8>>,
    references: Vec<Reference>,
}

/// One header field pointing from its record to another record ID.
#[derive(Debug)]
struct Reference {
    label: &'static str,
    target: Vec<u8>,
}

/// Draw the records from `input`, writing the SVG or opening it in the default viewer.
pub fn graph(input: &Path, output: Option<&Path>) -> Result<GraphSummary> {
    let records = read_records(input)?;
    let (source, references) = source(&records);
    let svg = render(&source)?;

    if let Some(output) = output {
        fs::write(output, svg).with_context(|| format!("cannot write {}", output.display()))?;
    } else {
        let mut temporary = tempfile::Builder::new()
            .prefix("archivindex-warc-")
            .suffix(".svg")
            .tempfile()
            .context("cannot create a temporary SVG")?;
        temporary
            .write_all(&svg)
            .context("cannot write the temporary SVG")?;
        let (_, path) = temporary
            .keep()
            .context("cannot preserve the temporary SVG for the viewer")?;
        open(&path)?;
    }

    Ok(GraphSummary {
        records: records.len(),
        references,
    })
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
fn read_records(path: &Path) -> Result<Vec<Record>> {
    let mut records = Vec::new();

    for result in open_warc(path)?.iter_raw_records() {
        let record = result.with_context(|| format!("cannot read {}", path.display()))?;
        let header = record.header;
        let record_type = value(&header, "WARC-Type")
            .map_or_else(|| "unknown".to_owned(), |value| value.to_ascii_lowercase());
        let id = header
            .get("WARC-Record-ID")
            .map(normalize_id)
            .filter(|id| !id.is_empty())
            .map(<[u8]>::to_vec);
        let references = REFERENCE_FIELDS
            .iter()
            .flat_map(|(field, label)| {
                header.get_all(field).map(move |target| Reference {
                    label,
                    target: normalize_id(target).to_vec(),
                })
            })
            .collect();

        records.push(Record {
            record_type,
            id,
            references,
        });
    }

    Ok(records)
}

/// Turn the records into D2 source and count the relationships that resolve within the file.
fn source(records: &[Record]) -> (String, usize) {
    let labels = labels(records);
    let colors = colors(records);
    let mut source =
        String::from("grid-rows: 1\ngrid-gap: 60\nrecords: {\n  label: \"\"\n  direction: down\n");

    for (index, record) in records.iter().enumerate() {
        let color = colors
            .get(&record.record_type)
            .expect("invariant violation: every record type has a color");
        source.push_str(&format!(
            "  record_{index}: \"{}\" {{\n    style.fill: \"{color}\"\n    style.font-size: {GRAPH_FONT_SIZE}\n  }}\n",
            escape(&labels[index])
        ));
    }
    for index in 1..records.len() {
        source.push_str(&format!(
            "  record_0 -> record_{index}: {{\n    style.opacity: 0\n  }}\n"
        ));
    }
    source.push_str("}\nkey: {\n  label: \"\"\n  grid-columns: 1\n");
    for (index, (record_type, color)) in colors.iter().enumerate() {
        source.push_str(&format!(
            "  type_{index}: \"{}\" {{\n    style.fill: \"{color}\"\n    style.font-size: {GRAPH_FONT_SIZE}\n  }}\n",
            escape(record_type)
        ));
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
                source.push_str(&format!(
                    "{} -> {}: \"{}\" {{\n  style.font-size: {EDGE_FONT_SIZE}\n}}\n",
                    node_path(source_index),
                    node_path(*target_index),
                    reference.label
                ));
                reference_count += 1;
            } else {
                log::warn!(
                    "not drawing {} reference to absent record {}",
                    reference.label,
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

    records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            if let Some(uuid) = uuid_parts[index] {
                let mut length = uuid.len().min(8);
                while length < uuid.len()
                    && uuid_parts.iter().enumerate().any(|(other_index, other)| {
                        other_index != index
                            && other.is_some_and(|other| {
                                other != uuid && other.starts_with(&uuid[..length])
                            })
                    })
                {
                    length += 1;
                }
                uuid[..length].to_owned()
            } else if let Some(id) = record.id.as_deref() {
                shorten(&String::from_utf8_lossy(id))
            } else {
                format!("record {} (no ID)", index + 1)
            }
        })
        .collect()
}

/// A color for every record type present, in key order.
fn colors(records: &[Record]) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let mut generated = 0;

    for record in records {
        result.entry(record.record_type.clone()).or_insert_with(|| {
            TYPE_COLORS
                .iter()
                .find_map(|(record_type, color)| {
                    (*record_type == record.record_type).then(|| (*color).to_owned())
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
fn hsl_color(hue: usize) -> String {
    let chroma = 0.45_f64;
    let sector = hue as f64 / 60.0;
    let intermediate = chroma * (1.0 - (sector.rem_euclid(2.0) - 1.0).abs());
    let (red, green, blue) = match sector as usize {
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

/// A record identifier without surrounding white space or angle brackets.
fn normalize_id(value: &[u8]) -> &[u8] {
    let value = value.trim_ascii();

    value
        .strip_prefix(b"<")
        .and_then(|inner| inner.strip_suffix(b">"))
        .unwrap_or(value)
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

/// Open a WARC file, decompressing a path ending in `.gz`.
fn open_warc(path: &Path) -> Result<WarcReader<Box<dyn BufRead>>> {
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let file = BufReader::new(file);
    let reader: Box<dyn BufRead> = if is_gzip(path) {
        Box::new(BufReader::new(MultiGzDecoder::new(file)))
    } else {
        Box::new(file)
    };

    Ok(WarcReader::new(reader))
}

/// Whether a path names a gzip-compressed WARC file.
fn is_gzip(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gz"))
}

/// Open a file in the platform's default graphical viewer.
fn open(path: &Path) -> Result<()> {
    for mut command in viewer_commands(path) {
        match command.status() {
            Ok(status) if status.success() => return Ok(()),
            Ok(_) | Err(_) => continue,
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

    fn record(record_type: &str, id: Option<&str>, references: &[(&'static str, &str)]) -> Record {
        Record {
            record_type: record_type.to_owned(),
            id: id.map(|id| id.as_bytes().to_vec()),
            references: references
                .iter()
                .map(|(label, target)| Reference {
                    label,
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
    fn source_has_colored_key_and_directed_references() {
        let records = [
            record("request", Some(FIRST), &[("concurrent-to", SECOND)]),
            record("response", Some(SECOND), &[("warcinfo-id", "absent")]),
        ];

        let (source, count) = source(&records);

        assert!(source.contains("records: {\n  label: \"\""));
        assert!(source.contains("key: {\n  label: \"\""));
        assert!(source.starts_with("grid-rows: 1"));
        assert!(source.contains("records: {\n  label: \"\"\n  direction: down"));
        assert!(source.contains("record_0 -> record_1: {\n    style.opacity: 0"));
        assert!(source.contains("\"request\" {\n    style.fill: \"#90BE6D\""));
        assert!(source.contains("\"response\" {\n    style.fill: \"#8ECAE6\""));
        assert!(source.contains("records.record_0 -> records.record_1: \"concurrent-to\""));
        assert!(!source.contains("warcinfo-id\"\n"));
        assert_eq!(count, 1);
    }

    #[test]
    fn generated_source_renders_as_svg() {
        let records = [
            record("request", Some(FIRST), &[("concurrent-to", SECOND)]),
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
