//! Renderings of a table (`docs/product/architecture.md` §4.3): TSV (a header row, then rows),
//! JSON (an array of objects), TEXT (the human form — aligned columns; a one-column `text` schema
//! prints its cells bare, which is how a function's C or an IR dump travels as a table without the
//! generic dispatcher knowing). The 40-odd bespoke writers of the examples become this one function.

use std::fmt::Write as _;

use crate::error::Result;
use crate::schema::{ColHint, ColType};
use crate::table::Table;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Format {
    Text = 0,
    Tsv = 1,
    Json = 2,
}

/// The schema name whose single `text` column prints bare in TEXT.
pub const TEXT_SCHEMA: &str = "text";

/// One cell as a string, the way TSV and TEXT show it: hex (no `0x`) for a Hex-hinted number,
/// decimal otherwise; `true`/`false`; strings with tabs and newlines escaped; bytes as hex; lists
/// comma-joined.
pub fn cell_text(t: &Table, r: u64, c: u32) -> Result<String> {
    let ty = t.col_type(c).ok_or_else(|| crate::error::Error::NotFound(format!("column {c}")))?;
    let hex = t.col_hint(c) == ColHint::Hex;
    Ok(match ty {
        ColType::U8 | ColType::U16 | ColType::U32 | ColType::U64 => {
            let v = t.u64(r, c)?;
            if hex { format!("{v:x}") } else { v.to_string() }
        }
        ColType::I64 => t.i64(r, c)?.to_string(),
        ColType::F64 => t.f64(r, c)?.to_string(),
        ColType::Bool => t.bool(r, c)?.to_string(),
        ColType::Str => t.str(r, c)?.replace('\\', "\\\\").replace('\t', "\\t").replace('\n', "\\n"),
        ColType::Bytes => t.bytes(r, c)?.iter().map(|b| format!("{b:02x}")).collect(),
        ColType::ListU32 => t.list_u32(r, c)?.map(|v| if hex { format!("{v:x}") } else { v.to_string() }).collect::<Vec<_>>().join(","),
        ColType::ListU64 => t.list_u64(r, c)?.map(|v| if hex { format!("{v:x}") } else { v.to_string() }).collect::<Vec<_>>().join(","),
    })
}

fn cell_json(t: &Table, r: u64, c: u32) -> Result<serde_json::Value> {
    use serde_json::Value;
    let ty = t.col_type(c).ok_or_else(|| crate::error::Error::NotFound(format!("column {c}")))?;
    Ok(match ty {
        ColType::U8 | ColType::U16 | ColType::U32 | ColType::U64 => Value::from(t.u64(r, c)?),
        ColType::I64 => Value::from(t.i64(r, c)?),
        ColType::F64 => serde_json::Number::from_f64(t.f64(r, c)?).map(Value::Number).unwrap_or(Value::Null),
        ColType::Bool => Value::Bool(t.bool(r, c)?),
        ColType::Str => Value::String(t.str(r, c)?.to_string()),
        ColType::Bytes => Value::String(t.bytes(r, c)?.iter().map(|b| format!("{b:02x}")).collect()),
        ColType::ListU32 => Value::Array(t.list_u32(r, c)?.map(Value::from).collect()),
        ColType::ListU64 => Value::Array(t.list_u64(r, c)?.map(Value::from).collect()),
    })
}

pub fn render(t: &Table, format: Format) -> Result<String> {
    let ncols = t.ncols();
    match format {
        Format::Tsv => {
            let mut out = String::new();
            let names: Vec<&str> = (0..ncols).map(|c| t.col_name(c).unwrap_or("")).collect();
            out.push_str(&names.join("\t"));
            out.push('\n');
            for r in 0..t.rows() {
                let cells: Result<Vec<String>> = (0..ncols).map(|c| cell_text(t, r, c)).collect();
                out.push_str(&cells?.join("\t"));
                out.push('\n');
            }
            Ok(out)
        }
        Format::Json => {
            let mut rows = Vec::with_capacity(t.rows() as usize);
            for r in 0..t.rows() {
                let mut obj = serde_json::Map::new();
                for c in 0..ncols {
                    obj.insert(t.col_name(c).unwrap_or("").to_string(), cell_json(t, r, c)?);
                }
                rows.push(serde_json::Value::Object(obj));
            }
            let mut s = serde_json::to_string_pretty(&serde_json::Value::Array(rows)).map_err(|e| crate::error::Error::Internal(e.to_string()))?;
            s.push('\n');
            Ok(s)
        }
        Format::Text => {
            if t.schema().name() == TEXT_SCHEMA && ncols == 1 && t.col_type(0) == Some(ColType::Str) {
                let mut out = String::new();
                for r in 0..t.rows() {
                    out.push_str(t.str(r, 0)?);
                    if !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
                return Ok(out);
            }
            // aligned columns: header, a rule, rows; right-align numbers, left-align text
            let names: Vec<String> = (0..ncols).map(|c| t.col_name(c).unwrap_or("").to_string()).collect();
            let mut cells: Vec<Vec<String>> = Vec::with_capacity(t.rows() as usize);
            for r in 0..t.rows() {
                cells.push((0..ncols).map(|c| cell_text(t, r, c)).collect::<Result<Vec<_>>>()?);
            }
            let widths: Vec<usize> = (0..ncols as usize).map(|c| names[c].chars().count().max(cells.iter().map(|row| row[c].chars().count()).max().unwrap_or(0))).collect();
            let numeric: Vec<bool> = (0..ncols).map(|c| !matches!(t.col_type(c), Some(ColType::Str | ColType::Bytes | ColType::ListU32 | ColType::ListU64))).collect();
            let mut out = String::new();
            let line = |row: &[String], out: &mut String| {
                for (c, cell) in row.iter().enumerate() {
                    if c > 0 {
                        out.push_str("  ");
                    }
                    if numeric[c] {
                        let _ = write!(out, "{:>w$}", cell, w = widths[c]);
                    } else if c + 1 == row.len() {
                        out.push_str(cell);
                    } else {
                        let _ = write!(out, "{:<w$}", cell, w = widths[c]);
                    }
                }
                out.push('\n');
            };
            line(&names, &mut out);
            let rule: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
            line(&rule, &mut out);
            for row in &cells {
                line(row, &mut out);
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Column, Schema};
    use crate::table::builder::TableBuilder;

    static FNS: Schema = Schema { name: "test.fns", version: 1, columns: &[Column::hex("entry", ColType::U64), Column::new("name", ColType::Str), Column::new("blocks", ColType::U32), Column::new("ok", ColType::Bool), Column::hex("callees", ColType::ListU64)] };
    static TEXT: Schema = Schema { name: TEXT_SCHEMA, version: 1, columns: &[Column::new("text", ColType::Str)] };

    fn fns() -> Table {
        let mut b = TableBuilder::new(&FNS);
        b.row().u64(0x1000).str("FUN_00001000").u32(3).bool(true).list_u64(&[0x2000, 0x3000]);
        b.row().u64(0x2000).str("tab\there").u32(12).bool(false).list_u64(&[]);
        b.finish(true)
    }

    /// TSV: the header row, hex for Hex-hinted columns (no 0x), escaped tabs, comma-joined lists.
    #[test]
    fn tsv_header_and_hex_hint() {
        assert_eq!(render(&fns(), Format::Tsv).unwrap(), "entry\tname\tblocks\tok\tcallees\n1000\tFUN_00001000\t3\ttrue\t2000,3000\n2000\ttab\\there\t12\tfalse\t\n");
    }

    /// JSON parses back with the same values: numbers as numbers, lists as arrays, strings raw.
    #[test]
    fn json_parses_back_with_same_values() {
        let s = render(&fns(), Format::Json).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["entry"], serde_json::json!(0x1000));
        assert_eq!(rows[0]["name"], serde_json::json!("FUN_00001000"));
        assert_eq!(rows[0]["callees"], serde_json::json!([0x2000, 0x3000]));
        assert_eq!(rows[1]["name"], serde_json::json!("tab\there"), "raw in JSON");
        assert_eq!(rows[1]["ok"], serde_json::json!(false));
        assert_eq!(rows[1]["callees"], serde_json::json!([]));
    }

    /// TEXT: aligned columns with a rule; the `text` schema prints bare.
    #[test]
    fn text_aligns_and_the_text_schema_prints_bare() {
        let t = render(&fns(), Format::Text).unwrap();
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0].trim_end(), "entry  name          blocks     ok  callees");
        assert!(lines[1].starts_with("-----  ------------  ------  -----  -------"), "{:?}", lines[1]);
        assert_eq!(lines[2], " 1000  FUN_00001000       3   true  2000,3000");
        let mut b = TableBuilder::new(&TEXT);
        b.row().str("int f(void)\n{\n  return 1;\n}\n");
        b.row().str("second unit");
        assert_eq!(render(&b.finish(false), Format::Text).unwrap(), "int f(void)\n{\n  return 1;\n}\nsecond unit\n");
    }
}
