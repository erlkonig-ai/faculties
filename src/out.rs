//! Minimal frontend-neutral faculty output.
//!
//! A handler emits prose lines.  Frontends decide where those lines go; the
//! contract deliberately has no transport format, JSON model, or media AST.

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Out {
    lines: Vec<String>,
}

impl Out {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn line(&mut self, line: impl Into<String>) -> &mut Self {
        self.lines.push(line.into());
        self
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn render(&self) -> String {
        let mut rendered = self.lines.join("\n");
        if !rendered.is_empty() {
            rendered.push('\n');
        }
        rendered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_lines_as_cli_prose() {
        let mut output = Out::new();
        output.line("first").line("second");
        assert_eq!(output.render(), "first\nsecond\n");
    }
}
