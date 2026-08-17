//! DOM-free projection of Google Takeout's Gemini Apps activity HTML.
//!
//! Takeout does not expose Gemini's native conversation/message identifiers.
//! Each activity card is therefore retained byte-for-byte and addressed by a
//! digest of those exact bytes.  The small tokenizer below only identifies
//! balanced activity cards, their primary content cell, text boundaries, and
//! local asset attributes; it never constructs an HTML tree or reserializes
//! source evidence.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use anybytes::{Bytes, View};
use anyhow::{anyhow, bail, Context, Result};
use hifitime::{Duration, Epoch};
use memchr::{memchr, memmem};
use triblespace::core::inline::TryToInline;
use triblespace::prelude::inlineencodings::NsTAIInterval;
use triblespace::prelude::Inline;

use crate::archive_source::{
    self, ProjectedSource, ProjectionStats, SourceClaims, SourcePart, SourceRecord, Threading,
};
use crate::files;
use crate::schemas::blockdag as schema;

/// Accounting for one explicit HTML export or a recursively scanned Takeout.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionSummary {
    pub files_scanned: usize,
    pub files_ignored: usize,
    pub cards_seen: usize,
    pub records_emitted: usize,
    pub assets_seen: usize,
    pub assets_resolved: usize,
    pub fragments_emitted: usize,
    pub stats: ProjectionStats,
}

#[derive(Clone, Copy, Debug)]
struct Tag {
    start: usize,
    end: usize,
    name_start: usize,
    name_end: usize,
    closing: bool,
    self_closing: bool,
}

#[derive(Clone, Debug)]
struct HtmlAsset {
    pointer: View<str>,
    text_position: usize,
}

#[derive(Default)]
struct RenderedCell {
    text: String,
    assets: Vec<HtmlAsset>,
}

struct ParsedCard {
    raw: Bytes,
    timestamp: Option<Inline<NsTAIInterval>>,
    prompted: bool,
    input: String,
    output: String,
    input_assets: Vec<HtmlAsset>,
    output_assets: Vec<HtmlAsset>,
}

/// Project one activity HTML file, or all Gemini activity files below a Takeout.
pub fn project_path<F>(path: &Path, mut emit: F) -> Result<ProjectionSummary>
where
    F: FnMut(ProjectedSource) -> Result<()>,
{
    let explicit_file = path.is_file();
    let mut paths = Vec::new();
    if path.is_dir() {
        collect_html_files(path, &mut paths)?;
        paths.sort();
    } else {
        paths.push(path.to_path_buf());
    }

    let mut summary = ProjectionSummary::default();
    for source_path in paths {
        let Some((records, file_stats)) = parse_file(&source_path)? else {
            if explicit_file {
                bail!(
                    "{} is not a recognized Gemini Apps activity export",
                    source_path.display()
                );
            }
            summary.files_ignored += 1;
            continue;
        };

        summary.files_scanned += 1;
        summary.cards_seen += file_stats.cards;
        summary.records_emitted += records.len();
        summary.assets_seen += file_stats.assets;
        summary.assets_resolved += file_stats.assets_resolved;
        let stats = archive_source::project_records(
            schema::source_projection::SOURCE_GEMINI,
            &source_path,
            records,
            |projected| {
                summary.fragments_emitted += 1;
                emit(projected)
            },
        )?;
        absorb(&mut summary.stats, stats);
    }

    if summary.files_scanned == 0 {
        bail!("no Gemini Apps activity HTML below {}", path.display());
    }
    Ok(summary)
}

#[derive(Default)]
struct FileStats {
    cards: usize,
    assets: usize,
    assets_resolved: usize,
}

fn collect_html_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
        let entry = entry.context("read Gemini Takeout directory entry")?;
        let entry_path = entry.path();
        let file_type = entry
            .file_type()
            .context("read Gemini Takeout entry type")?;
        if file_type.is_dir() {
            collect_html_files(&entry_path, out)?;
        } else if file_type.is_file()
            && matches!(
                entry_path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .map(str::to_ascii_lowercase)
                    .as_deref(),
                Some("html" | "htm")
            )
        {
            out.push(entry_path);
        }
    }
    Ok(())
}

fn parse_file(path: &Path) -> Result<Option<(Vec<SourceRecord>, FileStats)>> {
    let bytes = archive_source::map_immutable_file(path)?;
    let cards = scan_outer_cards(&bytes)
        .with_context(|| format!("scan Gemini activity cards in {}", path.display()))?;
    let mut parsed = Vec::new();
    for raw in cards {
        if !is_gemini_card(&raw)? {
            continue;
        }
        parsed.push(parse_card(raw.clone())?.unwrap_or(ParsedCard {
            raw,
            timestamp: None,
            prompted: false,
            input: String::new(),
            output: String::new(),
            input_assets: Vec::new(),
            output_assets: Vec::new(),
        }));
    }
    if parsed.is_empty() {
        return Ok(None);
    }

    // Google Activity is newest-first. Normalize the local record sequence
    // before duplicate-occurrence disambiguation. The shared projector still
    // chooses callback order from its canonical ready set, not this vector.
    // Never infer dialogue edges between cards: Takeout exposes no
    // conversation identity that could justify one.
    parsed.reverse();
    let mut duplicate_digests = HashMap::<String, usize>::new();
    let mut records = Vec::new();
    let mut stats = FileStats {
        cards: parsed.len(),
        ..FileStats::default()
    };

    for card in parsed {
        let digest = blake3::hash(card.raw.as_ref()).to_hex().to_string();
        let occurrence = duplicate_digests.entry(digest.clone()).or_default();
        let card_anchor = if *occurrence == 0 {
            format!("activity/{digest}")
        } else {
            format!("activity/{digest}/duplicate/{occurrence}")
        };
        *occurrence += 1;

        if card.prompted {
            let mut local_user = None::<View<str>>;
            let mut input_parts = Vec::new();
            if !card.input.is_empty() {
                input_parts.push(SourcePart::text(
                    schema::content_fact::modality::TEXT,
                    schema::content_fact::direction::IN,
                    archive_source::owned_text(card.input),
                ));
            }
            append_assets(
                path,
                card.input_assets,
                schema::content_fact::direction::IN,
                &mut input_parts,
                &mut stats,
            )?;
            if !input_parts.is_empty() {
                let locator = archive_source::owned_text(format!("{card_anchor}/user"));
                records.push(SourceRecord {
                    locator: locator.clone(),
                    raw_record: card.raw.clone(),
                    predecessors: Vec::new(),
                    block_timestamp: card.timestamp,
                    threading: Threading::Semantic,
                    parts: input_parts,
                    claims: SourceClaims {
                        timestamp: card.timestamp,
                        raw_author: Some(archive_source::owned_text("user")),
                        raw_role: Some(archive_source::owned_text("user")),
                        ..SourceClaims::default()
                    },
                });
                local_user = Some(locator);
            }

            let mut output_parts = Vec::new();
            if !card.output.is_empty() {
                output_parts.push(SourcePart::text(
                    schema::content_fact::modality::TEXT,
                    schema::content_fact::direction::OUT,
                    archive_source::owned_text(card.output),
                ));
            }
            append_assets(
                path,
                card.output_assets,
                schema::content_fact::direction::OUT,
                &mut output_parts,
                &mut stats,
            )?;
            if !output_parts.is_empty() {
                let locator = archive_source::owned_text(format!("{card_anchor}/assistant"));
                records.push(SourceRecord {
                    locator,
                    raw_record: card.raw,
                    predecessors: local_user.into_iter().collect(),
                    block_timestamp: card.timestamp,
                    threading: Threading::Semantic,
                    parts: output_parts,
                    claims: SourceClaims {
                        timestamp: card.timestamp,
                        raw_author: Some(archive_source::owned_text("assistant")),
                        raw_role: Some(archive_source::owned_text("assistant")),
                        raw_model: Some(archive_source::owned_text("Gemini Apps")),
                        ..SourceClaims::default()
                    },
                });
            }
        } else {
            // Non-prompt cards (for example "Created Gemini Canvas") are
            // retained as ambient activity without distorting dialogue edges.
            let mut parts = Vec::new();
            if !card.input.is_empty() {
                parts.push(SourcePart::text(
                    schema::content_fact::modality::EVENT,
                    schema::content_fact::direction::AMBIENT,
                    archive_source::owned_text(card.input),
                ));
            }
            let mut ambient_assets = card.input_assets;
            ambient_assets.extend(card.output_assets);
            append_assets(
                path,
                ambient_assets,
                schema::content_fact::direction::AMBIENT,
                &mut parts,
                &mut stats,
            )?;
            let locator = archive_source::owned_text(format!("{card_anchor}/activity"));
            records.push(SourceRecord {
                locator,
                raw_record: card.raw,
                predecessors: Vec::new(),
                block_timestamp: card.timestamp,
                threading: Threading::Transparent,
                parts,
                claims: SourceClaims {
                    timestamp: card.timestamp,
                    raw_author: Some(archive_source::owned_text("google")),
                    raw_role: Some(archive_source::owned_text("activity")),
                    raw_model: Some(archive_source::owned_text("Gemini Apps")),
                    ..SourceClaims::default()
                },
            });
        }
    }

    Ok(Some((records, stats)))
}

fn append_assets(
    source_path: &Path,
    assets: Vec<HtmlAsset>,
    direction: triblespace::prelude::Id,
    parts: &mut Vec<SourcePart>,
    stats: &mut FileStats,
) -> Result<()> {
    let mut seen = HashSet::<String>::new();
    for asset in assets {
        if !seen.insert(asset.pointer.as_ref().to_owned()) {
            continue;
        }
        stats.assets += 1;
        let resolved = resolve_asset(source_path, asset.pointer.as_ref())?;
        #[cfg(test)]
        if resolved.is_none() && std::env::var_os("GEMINI_REPORT_MISSING_ASSETS").is_some() {
            eprintln!("unresolved Gemini asset: {}", asset.pointer.as_ref());
        }
        if resolved.is_some() {
            stats.assets_resolved += 1;
        }
        let size = resolved
            .as_ref()
            .map(|bytes| u128::try_from(bytes.len()).expect("usize fits u128"));
        let media_type = files::infer_media_type(Path::new(asset.pointer.as_ref()));
        parts.push(SourcePart::Pointer {
            modality: archive_source::modality_for_media_type(media_type),
            direction,
            namespace: schema::source_projection::SOURCE_GEMINI,
            pointer: asset.pointer,
            media_type: Some(archive_source::owned_text(media_type)),
            size,
            resolved,
        });
    }
    Ok(())
}

fn parse_card(raw: Bytes) -> Result<Option<ParsedCard>> {
    let Some(cell) = find_div_inner_by_classes(
        &raw,
        &["content-cell", "mdl-cell--6-col", "mdl-typography--body-1"],
        &["mdl-typography--text-right"],
    )?
    else {
        return Ok(None);
    };
    let rendered = render_cell(&cell)?;
    let Some((timestamp_start, timestamp_end, timestamp)) = find_timestamp(&rendered.text) else {
        let prompted = starts_with_prompted(&rendered.text);
        let input = clean_input(&rendered.text, prompted);
        return Ok(Some(ParsedCard {
            raw,
            timestamp: None,
            prompted,
            input,
            output: String::new(),
            input_assets: rendered.assets,
            output_assets: Vec::new(),
        }));
    };

    let prompted = starts_with_prompted(&rendered.text[..timestamp_start]);
    let input = clean_input(&rendered.text[..timestamp_start], prompted);
    let output = clean_output(&rendered.text[timestamp_end..]);
    let mut input_assets = Vec::new();
    let mut output_assets = Vec::new();
    for asset in rendered.assets {
        if asset.text_position < timestamp_start {
            input_assets.push(asset);
        } else {
            output_assets.push(asset);
        }
    }
    Ok(Some(ParsedCard {
        raw,
        timestamp,
        prompted,
        input,
        output,
        input_assets,
        output_assets,
    }))
}

fn is_gemini_card(card: &Bytes) -> Result<bool> {
    let Some(header) = find_div_inner_by_classes(card, &["header-cell"], &[])? else {
        return Ok(false);
    };
    let title = render_cell(&header)?.text;
    Ok(title
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .contains("Gemini Apps"))
}

fn scan_outer_cards(input: &Bytes) -> Result<Vec<Bytes>> {
    let mut cards = Vec::new();
    let mut position = 0usize;
    let mut div_depth = 0usize;
    let mut current = None::<(usize, usize)>;
    while let Some(tag) = next_tag(input, position)? {
        position = tag.end;
        if !tag_name_is(input, tag, b"div") {
            continue;
        }
        if tag.closing {
            if current.is_some_and(|(_, depth)| depth == div_depth) {
                let (start, _) = current.take().expect("checked current card");
                cards.push(input.slice(start..tag.end));
            }
            div_depth = div_depth.saturating_sub(1);
        } else {
            div_depth += 1;
            if current.is_none()
                && tag_has_classes(
                    input,
                    tag,
                    &["outer-cell", "mdl-cell--12-col", "mdl-shadow--2dp"],
                    &[],
                )?
            {
                current = Some((tag.start, div_depth));
            }
            if tag.self_closing {
                div_depth = div_depth.saturating_sub(1);
            }
        }
    }
    if current.is_some() {
        bail!("unterminated Gemini activity card");
    }
    Ok(cards)
}

fn find_div_inner_by_classes(
    input: &Bytes,
    required: &[&str],
    forbidden: &[&str],
) -> Result<Option<Bytes>> {
    let mut position = 0usize;
    let mut div_depth = 0usize;
    let mut target = None::<(usize, usize)>;
    while let Some(tag) = next_tag(input, position)? {
        position = tag.end;
        if !tag_name_is(input, tag, b"div") {
            continue;
        }
        if tag.closing {
            if target.is_some_and(|(_, depth)| depth == div_depth) {
                let (inner_start, _) = target.expect("checked target element");
                return Ok(Some(input.slice(inner_start..tag.start)));
            }
            div_depth = div_depth.saturating_sub(1);
        } else {
            div_depth += 1;
            if target.is_none() && tag_has_classes(input, tag, required, forbidden)? {
                target = Some((tag.end, div_depth));
            }
            if tag.self_closing {
                div_depth = div_depth.saturating_sub(1);
            }
        }
    }
    Ok(None)
}

fn render_cell(input: &Bytes) -> Result<RenderedCell> {
    let mut rendered = RenderedCell::default();
    let mut position = 0usize;
    while let Some(tag) = next_tag(input, position)? {
        append_decoded(&mut rendered.text, &input.as_ref()[position..tag.start])?;
        position = tag.end;
        let name = tag_name(input, tag);
        if !tag.closing && name.eq_ignore_ascii_case(b"br") {
            push_newline(&mut rendered.text);
        } else if (tag.closing
            && matches_ascii_name(name, &[b"p", b"div", b"li", b"h1", b"h2", b"h3", b"h4"]))
            || (!tag.closing && matches_ascii_name(name, &[b"li", b"h1", b"h2", b"h3", b"h4"]))
        {
            push_newline(&mut rendered.text);
        }

        if !tag.closing && name.eq_ignore_ascii_case(b"a") {
            if let Some(pointer) = html_attribute(input, tag, b"href")? {
                if let Some(pointer) = local_pointer(pointer)? {
                    rendered.assets.push(HtmlAsset {
                        pointer,
                        text_position: rendered.text.len(),
                    });
                }
            }
        } else if !tag.closing && name.eq_ignore_ascii_case(b"img") {
            if let Some(pointer) = html_attribute(input, tag, b"src")? {
                if let Some(pointer) = local_pointer(pointer)? {
                    rendered.assets.push(HtmlAsset {
                        pointer,
                        text_position: rendered.text.len(),
                    });
                }
            }
            if let Some(alt) = html_attribute(input, tag, b"alt")? {
                let alt = decoded_view(alt)?;
                if !alt.as_ref().trim().is_empty() {
                    append_spaced(&mut rendered.text, alt.as_ref().trim());
                }
            }
        }
    }
    append_decoded(&mut rendered.text, &input.as_ref()[position..])?;
    Ok(rendered)
}

fn find_timestamp(text: &str) -> Option<(usize, usize, Option<Inline<NsTAIInterval>>)> {
    let mut start = 0usize;
    for line in text.split_inclusive('\n') {
        let without_newline = line.strip_suffix('\n').unwrap_or(line);
        let trimmed = without_newline.trim();
        if let Some(timestamp) = parse_activity_timestamp(trimmed) {
            return Some((start, start + line.len(), Some(timestamp)));
        }
        start += line.len();
    }
    if start < text.len() {
        let trimmed = text[start..].trim();
        if let Some(timestamp) = parse_activity_timestamp(trimmed) {
            return Some((start, text.len(), Some(timestamp)));
        }
    }
    None
}

fn starts_with_prompted(text: &str) -> bool {
    text.trim_start()
        .strip_prefix("Prompted")
        .is_some_and(|rest| rest.chars().next().is_some_and(char::is_whitespace))
}

fn clean_input(text: &str, prompted: bool) -> String {
    let mut lines = Vec::new();
    let mut attachment_rows = 0usize;
    for (index, raw) in text.lines().enumerate() {
        let mut line = raw.trim();
        if index == 0 && prompted {
            line = line.strip_prefix("Prompted").unwrap_or(line).trim_start();
        }
        if line.is_empty() {
            continue;
        }
        if let Some(count) = attachment_count(line) {
            attachment_rows = count;
            continue;
        }
        if attachment_rows > 0 {
            attachment_rows -= 1;
            continue;
        }
        if generated_asset_summary(line) {
            continue;
        }
        lines.push(line);
    }
    lines.join("\n")
}

fn clean_output(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn attachment_count(line: &str) -> Option<usize> {
    let rest = line.strip_prefix("Attached ")?;
    let (count, tail) = rest.split_once(' ')?;
    (tail == "file." || tail == "files.")
        .then(|| count.parse().ok())
        .flatten()
}

fn generated_asset_summary(line: &str) -> bool {
    let Some((count, tail)) = line.split_once(' ') else {
        return false;
    };
    count.parse::<usize>().is_ok() && matches!(tail, "generated image." | "generated images.")
}

fn parse_activity_timestamp(input: &str) -> Option<Inline<NsTAIInterval>> {
    let (datetime, zone) = input.rsplit_once(' ')?;
    let (date, time) = datetime.split_once(", ")?;
    let mut date_parts = date.split_whitespace();
    let day: u8 = date_parts.next()?.parse().ok()?;
    let month: u8 = match date_parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" | "Sept" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() {
        return None;
    }
    let mut time_parts = time.split(':');
    let hour: u8 = time_parts.next()?.parse().ok()?;
    let minute: u8 = time_parts.next()?.parse().ok()?;
    let second: u8 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() {
        return None;
    }
    let offset_hours = match zone {
        "UTC" | "GMT" => 0.0,
        "CET" => 1.0,
        "CEST" => 2.0,
        "PST" => -8.0,
        "PDT" => -7.0,
        "MST" => -7.0,
        "MDT" => -6.0,
        "CST" => -6.0,
        "CDT" => -5.0,
        "EST" => -5.0,
        "EDT" => -4.0,
        _ => return None,
    };
    let local = Epoch::maybe_from_gregorian_utc(year, month, day, hour, minute, second, 0).ok()?;
    let epoch = local - Duration::from_hours(offset_hours);
    (epoch, epoch).try_to_inline().ok()
}

fn resolve_asset(source_path: &Path, pointer: &str) -> Result<Option<Bytes>> {
    let decoded = percent_decode_path(pointer)?;
    let relative = Path::new(&decoded);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Ok(None);
    }
    let Some(parent) = source_path.parent() else {
        return Ok(None);
    };
    let mut candidates = vec![parent.join(relative)];
    if relative
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "png" | "jpg" | "jpeg" | "webp"
            )
        })
    {
        for extension in ["png", "jpg", "jpeg", "webp"] {
            candidates.push(parent.join(relative).with_extension(extension));
        }
    }
    if relative.extension().is_some() {
        candidates.push(parent.join(relative).with_extension(""));
    }
    candidates.dedup();
    for candidate in candidates {
        if candidate.is_file() {
            return archive_source::map_immutable_file(&candidate).map(Some);
        }
    }
    Ok(None)
}

fn percent_decode_path(pointer: &str) -> Result<String> {
    let pointer = pointer.split(['?', '#']).next().unwrap_or(pointer);
    let bytes = pointer.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = hex_digit(bytes[index + 1]);
            let low = hex_digit(bytes[index + 2]);
            if let (Some(high), Some(low)) = (high, low) {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(out).context("Gemini asset path is not UTF-8")
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn local_pointer(raw: Bytes) -> Result<Option<View<str>>> {
    let pointer = decoded_view(raw)?;
    let lower = pointer.as_ref().trim_start().to_ascii_lowercase();
    if lower.is_empty()
        || lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("mailto:")
        || lower.starts_with("data:")
        || lower.starts_with("javascript:")
        || lower.starts_with('#')
    {
        Ok(None)
    } else {
        Ok(Some(pointer))
    }
}

fn decoded_view(raw: Bytes) -> Result<View<str>> {
    let view = raw
        .clone()
        .view::<str>()
        .map_err(|_| anyhow!("Gemini HTML attribute is not UTF-8"))?;
    if !view.as_ref().contains('&') {
        return Ok(view);
    }
    let mut decoded = String::new();
    append_decoded(&mut decoded, raw.as_ref())?;
    Ok(archive_source::owned_text(decoded))
}

fn append_decoded(out: &mut String, bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("Gemini HTML text is not UTF-8")?;
    let mut rest = text;
    while let Some(index) = rest.find('&') {
        out.push_str(&rest[..index]);
        rest = &rest[index..];
        let Some(end) = rest.find(';') else {
            out.push_str(rest);
            return Ok(());
        };
        let entity = &rest[1..end];
        if let Some(decoded) = decode_entity(entity) {
            out.push(decoded);
            rest = &rest[end + 1..];
        } else {
            out.push('&');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    Ok(())
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "nbsp" => Some(' '),
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" | "#39" => Some('\''),
        "hellip" => Some('…'),
        "ndash" => Some('–'),
        "mdash" => Some('—'),
        "copy" => Some('©'),
        "reg" => Some('®'),
        "trade" => Some('™'),
        _ => entity
            .strip_prefix("#x")
            .or_else(|| entity.strip_prefix("#X"))
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .or_else(|| {
                entity
                    .strip_prefix('#')
                    .and_then(|decimal| decimal.parse().ok())
            })
            .and_then(char::from_u32),
    }
}

fn push_newline(out: &mut String) {
    if !out.ends_with('\n') {
        out.push('\n');
    }
}

fn append_spaced(out: &mut String, text: &str) {
    if !out.is_empty() && !out.chars().next_back().is_some_and(char::is_whitespace) {
        out.push(' ');
    }
    out.push_str(text);
}

fn next_tag(input: &Bytes, from: usize) -> Result<Option<Tag>> {
    let bytes = input.as_ref();
    let Some(relative_start) = memchr(b'<', &bytes[from..]) else {
        return Ok(None);
    };
    let start = from + relative_start;
    if bytes[start..].starts_with(b"<!--") {
        let Some(relative_end) = memmem::find(&bytes[start + 4..], b"-->") else {
            bail!("unterminated HTML comment");
        };
        let end = start + 4 + relative_end + 3;
        return Ok(Some(Tag {
            start,
            end,
            name_start: start + 1,
            name_end: start + 1,
            closing: false,
            self_closing: true,
        }));
    }
    let mut quote = None::<u8>;
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        match quote {
            Some(delimiter) if byte == delimiter => quote = None,
            Some(_) => {}
            None if byte == b'\'' || byte == b'"' => quote = Some(byte),
            None if byte == b'>' => break,
            None => {}
        }
        cursor += 1;
    }
    if cursor == bytes.len() {
        bail!("unterminated HTML tag");
    }
    let end = cursor + 1;
    let mut name_start = start + 1;
    while name_start < cursor && bytes[name_start].is_ascii_whitespace() {
        name_start += 1;
    }
    let closing = bytes.get(name_start).copied() == Some(b'/');
    if closing {
        name_start += 1;
        while name_start < cursor && bytes[name_start].is_ascii_whitespace() {
            name_start += 1;
        }
    }
    let mut name_end = name_start;
    while name_end < cursor
        && !bytes[name_end].is_ascii_whitespace()
        && !matches!(bytes[name_end], b'/' | b'>')
    {
        name_end += 1;
    }
    let mut before_close = cursor;
    while before_close > start && bytes[before_close - 1].is_ascii_whitespace() {
        before_close -= 1;
    }
    Ok(Some(Tag {
        start,
        end,
        name_start,
        name_end,
        closing,
        self_closing: bytes.get(before_close.wrapping_sub(1)).copied() == Some(b'/'),
    }))
}

fn tag_name(input: &Bytes, tag: Tag) -> &[u8] {
    &input.as_ref()[tag.name_start..tag.name_end]
}

fn tag_name_is(input: &Bytes, tag: Tag, expected: &[u8]) -> bool {
    tag_name(input, tag).eq_ignore_ascii_case(expected)
}

fn matches_ascii_name(name: &[u8], choices: &[&[u8]]) -> bool {
    choices
        .iter()
        .any(|choice| name.eq_ignore_ascii_case(choice))
}

fn tag_has_classes(input: &Bytes, tag: Tag, required: &[&str], forbidden: &[&str]) -> Result<bool> {
    let Some(classes) = html_attribute(input, tag, b"class")? else {
        return Ok(required.is_empty());
    };
    let classes = classes
        .view::<str>()
        .map_err(|_| anyhow!("HTML class attribute is not UTF-8"))?;
    let tokens: HashSet<&str> = classes.as_ref().split_whitespace().collect();
    Ok(required.iter().all(|class| tokens.contains(class))
        && forbidden.iter().all(|class| !tokens.contains(class)))
}

fn html_attribute(input: &Bytes, tag: Tag, expected: &[u8]) -> Result<Option<Bytes>> {
    let bytes = input.as_ref();
    let mut cursor = tag.name_end;
    let tag_limit = tag.end.saturating_sub(1);
    while cursor < tag_limit {
        while cursor < tag_limit && (bytes[cursor].is_ascii_whitespace() || bytes[cursor] == b'/') {
            cursor += 1;
        }
        if cursor >= tag_limit {
            break;
        }
        let name_start = cursor;
        while cursor < tag_limit
            && !bytes[cursor].is_ascii_whitespace()
            && !matches!(bytes[cursor], b'=' | b'/' | b'>')
        {
            cursor += 1;
        }
        let name_end = cursor;
        while cursor < tag_limit && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor).copied() != Some(b'=') {
            continue;
        }
        cursor += 1;
        while cursor < tag_limit && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let (value_start, value_end) = match bytes.get(cursor).copied() {
            Some(delimiter @ (b'\'' | b'"')) => {
                cursor += 1;
                let start = cursor;
                while cursor < tag_limit && bytes[cursor] != delimiter {
                    cursor += 1;
                }
                let end = cursor;
                cursor = (cursor + 1).min(tag_limit);
                (start, end)
            }
            Some(_) => {
                let start = cursor;
                while cursor < tag_limit
                    && !bytes[cursor].is_ascii_whitespace()
                    && !matches!(bytes[cursor], b'/' | b'>')
                {
                    cursor += 1;
                }
                (start, cursor)
            }
            None => break,
        };
        if bytes[name_start..name_end].eq_ignore_ascii_case(expected) {
            return Ok(Some(input.slice(value_start..value_end)));
        }
    }
    Ok(None)
}

fn absorb(target: &mut ProjectionStats, source: ProjectionStats) {
    target.records_seen += source.records_seen;
    target.projections_emitted += source.projections_emitted;
    target.content_parts += source.content_parts;
    target.transparent_records += source.transparent_records;
    target.raw_only_records += source.raw_only_records;
    target.missing_predecessors += source.missing_predecessors;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use tempfile::TempDir;
    use triblespace::core::repo::{BlobStore, BlobStoreGet};
    use triblespace::prelude::blobencodings::RawBytes;
    use triblespace::prelude::inlineencodings::Handle;
    use triblespace::prelude::*;

    use super::*;

    const PREFIX: &str = "<html><body><div class=\"mdl-grid\">";
    const SUFFIX: &str = "</div></body></html>";

    fn card(body: &str) -> String {
        format!(
            "<div class=\"outer-cell mdl-cell mdl-cell--12-col mdl-shadow--2dp\"><div class=\"mdl-grid\"><div class=\"header-cell mdl-cell mdl-cell--12-col\"><p>Gemini Apps<br></p></div><div class=\"content-cell mdl-cell mdl-cell--6-col mdl-typography--body-1\">{body}</div><div class=\"content-cell mdl-cell mdl-cell--6-col mdl-typography--body-1 mdl-typography--text-right\"></div></div></div>"
        )
    }

    fn projected_block(fragment: &Fragment) -> Id {
        let projection = fragment.root().expect("projection has one root");
        find!(
            (block: Id),
            pattern!(fragment, [{
                projection @ schema::source_projection::projects_to: ?block
            }])
        )
        .next()
        .map(|(block,)| block)
        .expect("projection names one block")
    }

    fn project_blocks(path: &Path) -> Vec<Id> {
        let mut blocks = Vec::new();
        project_path(path, |projected| {
            blocks.push(projected_block(&projected.fragment));
            Ok(())
        })
        .unwrap();
        blocks
    }

    #[test]
    fn exact_cards_and_semantics_are_recovered_without_a_dom() {
        let first = card("Prompted&nbsp;hello &amp; welcome<br>Attached 1 file.<br>- <a href=\"note%20one.txt\">note.txt</a><br>18 Sept 2025, 12:01:52 CET<br><p>Hi &lt;there&gt;.</p><img src=\"answer.png\">");
        let second =
            card("Created Gemini Canvas titled&nbsp;A thing<br>18 Sept 2025, 12:02:52 CET<br>");
        let html = format!("{PREFIX}{first}{second}{SUFFIX}");
        let bytes = Bytes::from_source(html.clone());
        let cards = scan_outer_cards(&bytes).unwrap();
        assert_eq!(cards.len(), 2);
        assert_eq!(cards[0].as_ref(), first.as_bytes());
        assert_eq!(cards[1].as_ref(), second.as_bytes());

        let parsed = parse_card(cards[0].clone()).unwrap().unwrap();
        assert!(parsed.prompted);
        assert_eq!(parsed.input, "hello & welcome");
        assert_eq!(parsed.output, "Hi <there>.");
        assert_eq!(parsed.input_assets[0].pointer.as_ref(), "note%20one.txt");
        assert_eq!(parsed.output_assets[0].pointer.as_ref(), "answer.png");
        assert!(parsed.timestamp.is_some());
    }

    #[test]
    fn projects_local_assets_and_keeps_activity_transparent() {
        let temp = TempDir::new().unwrap();
        let activity = temp.path().join("My Activity.html");
        fs::write(temp.path().join("note one.txt"), b"note").unwrap();
        fs::write(temp.path().join("answer.png"), b"png").unwrap();
        let newest = card("Prompted&nbsp;hello<br>18 Sept 2025, 12:02:52 CET<br><p>world</p><img src=\"answer.png\">");
        let oldest = card("Created Gemini Canvas titled&nbsp;A thing<br>18 Sept 2025, 12:01:52 CET<br><a href=\"note%20one.txt\">note</a>");
        fs::write(&activity, format!("{PREFIX}{newest}{oldest}{SUFFIX}")).unwrap();

        let mut emitted = 0usize;
        let summary = project_path(&activity, |_| {
            emitted += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.cards_seen, 2);
        assert_eq!(summary.records_emitted, 3);
        assert_eq!(summary.assets_seen, 2);
        assert_eq!(summary.assets_resolved, 2);
        assert_eq!(summary.fragments_emitted, emitted);
        assert_eq!(summary.stats.transparent_records, 1);
    }

    #[test]
    fn prompted_card_has_only_local_user_to_assistant_causality() {
        let temp = TempDir::new().unwrap();
        let activity = temp.path().join("My Activity.html");
        let prompted =
            card("Prompted&nbsp;question<br>18 Sept 2025, 12:02:52 CET<br><p>answer</p>");
        fs::write(&activity, format!("{PREFIX}{prompted}{SUFFIX}")).unwrap();

        let mut emitted = Vec::new();
        let summary = project_path(&activity, |projected| {
            emitted.push(projected.fragment);
            Ok(())
        })
        .unwrap();
        assert_eq!(summary.records_emitted, 2);

        let user = projected_block(&emitted[0]);
        let assistant = projected_block(&emitted[1]);
        assert!(!exists!(pattern!(&emitted[0], [{
            user @ schema::block::previous: _?previous
        }])));
        assert!(exists!(pattern!(&emitted[1], [{
            assistant @ schema::block::previous: user
        }])));
    }

    #[test]
    fn backfilled_unrelated_card_preserves_existing_block_ids() {
        let temp = TempDir::new().unwrap();
        let activity = temp.path().join("My Activity.html");
        let newest =
            card("Prompted&nbsp;new question<br>18 Sept 2025, 12:03:52 CET<br><p>new answer</p>");
        let existing_oldest =
            card("Prompted&nbsp;old question<br>18 Sept 2025, 12:02:52 CET<br><p>old answer</p>");
        fs::write(
            &activity,
            format!("{PREFIX}{newest}{existing_oldest}{SUFFIX}"),
        )
        .unwrap();
        let baseline: BTreeSet<_> = project_blocks(&activity).into_iter().collect();
        assert_eq!(baseline.len(), 4);

        let backfilled = card(
            "Prompted&nbsp;backfilled question<br>18 Sept 2025, 12:01:52 CET<br><p>backfilled answer</p>",
        );
        fs::write(
            &activity,
            format!("{PREFIX}{newest}{existing_oldest}{backfilled}{SUFFIX}"),
        )
        .unwrap();
        let expanded: BTreeSet<_> = project_blocks(&activity).into_iter().collect();

        assert_eq!(expanded.len(), 6);
        assert!(baseline.is_subset(&expanded));
    }

    #[test]
    fn recognized_card_with_unknown_schema_is_retained_exactly_as_raw_only() {
        let temp = TempDir::new().unwrap();
        let activity = temp.path().join("My Activity.html");
        let drifted = "<div class=\"outer-cell mdl-cell mdl-cell--12-col mdl-shadow--2dp\"><div class=\"mdl-grid\"><div class=\"header-cell mdl-cell mdl-cell--12-col\"><p>Gemini Apps<br></p></div><section class=\"future-content-layout\">Prompted&nbsp;not yet understood</section></div></div>";
        fs::write(&activity, format!("{PREFIX}{drifted}{SUFFIX}")).unwrap();

        let mut emitted = Vec::new();
        let summary = project_path(&activity, |projected| {
            emitted.push(projected.fragment);
            Ok(())
        })
        .unwrap();

        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.cards_seen, 1);
        assert_eq!(summary.records_emitted, 1);
        assert_eq!(summary.stats.raw_only_records, 1);
        assert_eq!(summary.stats.transparent_records, 1);
        assert_eq!(emitted.len(), 1);

        let projection = emitted[0].root().expect("projection has one root");
        let raw: Inline<Handle<RawBytes>> = find!(
            raw: Inline<Handle<RawBytes>>,
            pattern!(&emitted[0], [{
                projection @ schema::source_projection::raw_record: ?raw
            }])
        )
        .next()
        .expect("source receipt retains its raw card");
        let reader = emitted[0]
            .blobs_mut()
            .reader()
            .expect("MemoryBlobStore reader construction is infallible");
        let recovered: Bytes = reader.get(raw).unwrap();
        assert_eq!(recovered.as_ref(), drifted.as_bytes());

        let block = projected_block(&emitted[0]);
        assert!(!exists!(pattern!(&emitted[0], [{
            block @ schema::block::contains: _?part
        }])));
    }

    #[test]
    fn malformed_source_timestamp_is_untimed_without_losing_raw_evidence() {
        let temp = TempDir::new().unwrap();
        let activity = temp.path().join("My Activity.html");
        let malformed =
            card("Prompted&nbsp;question<br>31 Feb 2025, 12:02:52 CET<br><p>answer</p>");
        assert!(parse_activity_timestamp("31 Feb 2025, 12:02:52 CET").is_none());
        fs::write(&activity, format!("{PREFIX}{malformed}{SUFFIX}")).unwrap();

        let mut emitted = Vec::new();
        let summary = project_path(&activity, |projected| {
            emitted.push(projected.fragment);
            Ok(())
        })
        .unwrap();

        assert_eq!(summary.cards_seen, 1);
        assert_eq!(summary.records_emitted, 1);
        assert_eq!(summary.stats.content_parts, 1);
        assert_eq!(emitted.len(), 1);

        let block = projected_block(&emitted[0]);
        assert!(!exists!(pattern!(&emitted[0], [{
            block @ schema::block::timestamp: _?timestamp
        }])));

        let projection = emitted[0].root().expect("projection has one root");
        let raw: Inline<Handle<RawBytes>> = find!(
            raw: Inline<Handle<RawBytes>>,
            pattern!(&emitted[0], [{
                projection @ schema::source_projection::raw_record: ?raw
            }])
        )
        .next()
        .expect("source receipt retains its raw card");
        let reader = emitted[0]
            .blobs_mut()
            .reader()
            .expect("MemoryBlobStore reader construction is infallible");
        let recovered: Bytes = reader.get(raw).unwrap();
        assert_eq!(recovered.as_ref(), malformed.as_bytes());
    }

    #[test]
    #[ignore = "set GEMINI_TAKEOUT_FIXTURE to smoke-test a private export"]
    fn private_takeout_fixture_smoke_test() {
        let path = PathBuf::from(
            std::env::var_os("GEMINI_TAKEOUT_FIXTURE")
                .expect("GEMINI_TAKEOUT_FIXTURE must name My Activity.html"),
        );
        let summary = project_path(&path, |_| Ok(())).unwrap();
        eprintln!("{summary:#?}");
        assert!(summary.cards_seen > 0);
        assert_eq!(summary.fragments_emitted, summary.records_emitted);
    }
}
