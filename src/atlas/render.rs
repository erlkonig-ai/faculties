//! Pure text projections shared by Atlas's explicit frontends.

use super::AtlasEntry;

pub(super) fn list_line(row: &AtlasEntry) -> String {
    let tags = if row.tags.is_empty() {
        String::new()
    } else {
        format!(
            " [tags: {}]",
            row.tags
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let grouped_by = if row.members.is_empty() {
        String::new()
    } else {
        format!(
            " [groups: {}]",
            row.members
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let description = (!row.descriptions.is_empty())
        .then(|| format!(" - {}", row.descriptions.join(" / ")))
        .unwrap_or_default();
    let source_module = (!row.source_modules.is_empty())
        .then(|| format!(" @{}", row.source_modules.join(" / ")))
        .unwrap_or_default();
    let variants = (row.names.len() > 1)
        .then(|| format!(" [{} name variants]", row.names.len()))
        .unwrap_or_default();
    format!(
        "{id:x} {name}{variants}{source_module}{tags}{grouped_by}{description}",
        id = row.id,
        name = row.names_label(),
    )
}

pub(super) fn show_lines(row: &AtlasEntry) -> Vec<String> {
    let mut lines = vec![format!("id: {:x}", row.id)];
    lines.extend(row.names.iter().map(|name| format!("name: {name}")));
    lines.extend(
        row.descriptions
            .iter()
            .map(|description| format!("description: {description}")),
    );
    lines.extend(
        row.source_modules
            .iter()
            .map(|module| format!("source_module: {module}")),
    );
    if !row.tags.is_empty() {
        lines.push(format!(
            "tags: {}",
            row.tags
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !row.members.is_empty() {
        lines.push(format!(
            "grouped_by: {}",
            row.members
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    lines
}
