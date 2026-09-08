//! Present already fetched results without rerunning a provider request.
use super::{Provider, SearchReport};
use crate::out::Out;
use anyhow::Result;
pub fn search(report: &SearchReport, out: &mut Out<'_>) -> Result<()> {
    let provider = match report.provider {
        Provider::Auto => "auto",
        Provider::Tavily => "tavily",
        Provider::Exa => "exa",
    };
    out.line(format!("provider: {provider}"))?;
    out.line(format!("query: {}", report.query))?;
    out.line(format!("results: {}", report.results.len()))?;
    out.line("")?;
    for (index, row) in report.results.iter().enumerate() {
        out.line(format!(
            "[{}] {}",
            index + 1,
            row.title.as_deref().unwrap_or("<no title>")
        ))?;
        out.line(format!("url: {}", row.url))?;
        if let Some(snippet) = row.snippet.as_deref().filter(|s| !s.is_empty()) {
            out.line(format!("snippet: {}", snippet.trim()))?;
        }
        out.line("")?;
    }
    Ok(())
}
