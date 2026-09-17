//! The extraction law, as pure code.
//!
//! This module names no `Pile`, `Storage`, `Collection` or `TribleSet` in any
//! signature, by rule. Its entry point is [`extract`], which turns one file's
//! text into whatever this build can establish about it, and nothing that
//! happens here reaches a pile except through the fragment constructors in
//! [`crate::code`]. [`Extracted`] is a transient parse result for ONE file,
//! consumed into fragments and dropped; that is a parser's output type, not a
//! catalogue held in memory.
//!
//! A file that does not parse is not an error. It yields a unit carrying the
//! parser's complaint and no items, which keeps it searchable and printable
//! rather than absent. Open world means a reader ingests what it can establish
//! and ignores what it cannot model — never the other way round.

use std::collections::BTreeSet;

use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};
use quote::ToTokens;

use crate::schemas::code::{ItemKind, Language, Visibility};

/// Everything this build could establish about one file.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Extracted {
    /// `//!` module docs for Rust; the whole text for prose languages.
    pub doc: Option<String>,
    /// First segment of every `use` path in this file.
    pub import_roots: BTreeSet<String>,
    /// Declarations, parents before children.
    pub items: Vec<ExtractedItem>,
    /// The parser's complaint, when there was one. Not an error.
    pub parse_error: Option<String>,
}

/// One declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractedItem {
    pub kind: ItemKind,
    pub name: Option<String>,
    /// The normalized token stream. This — and only this — is the identity.
    pub tokens: String,
    pub signature: String,
    pub doc: Option<String>,
    pub visibility: Visibility,
    pub mentions: BTreeSet<String>,
    /// `(start line, start column, end line, end column)`, 1-based lines.
    pub span: (u64, u64, u64, u64),
    /// Index into [`Extracted::items`] of the enclosing declaration.
    pub parent: Option<usize>,
}

/// A signature is for a human to read at the end of a result line.
const MAX_SIGNATURE_CHARS: usize = 240;
/// A banner comment is context, not an essay.
const MAX_BANNER_LINES: usize = 6;

/// Everything this build can establish about `source`.
///
/// Total by construction: there is no failure path, because "I could not parse
/// this" is a fact about the file rather than a refusal to hold it.
pub fn extract(source: &str, language: Language) -> Extracted {
    match language {
        Language::Rust => extract_rust(source),
        Language::Markdown | Language::Toml | Language::Text => Extracted {
            doc: non_empty(source.to_owned()),
            ..Extracted::default()
        },
        Language::Shell => Extracted {
            doc: non_empty(comment_prose(source, "#")),
            ..Extracted::default()
        },
        Language::Typst => Extracted {
            doc: non_empty(comment_prose(source, "//")),
            ..Extracted::default()
        },
    }
}

/// rustc's own rule: a leading `#!` line that is not `#![` is a shebang.
///
/// Keeping the byte offset lets every span stay true to the ORIGINAL file, so
/// a reported line number matches what an editor shows.
fn strip_shebang(source: &str) -> (&str, u64) {
    if source.starts_with("#!") && !source.starts_with("#![") {
        let end = source.find('\n').map(|at| at + 1).unwrap_or(source.len());
        return (&source[end..], 1);
    }
    (source, 0)
}

fn extract_rust(source: &str) -> Extracted {
    let (body, line_offset) = strip_shebang(source);
    let file = match syn::parse_file(body) {
        Ok(file) => file,
        Err(error) => {
            return Extracted {
                doc: non_empty(inner_doc_prose(body)),
                parse_error: Some(error.to_string()),
                ..Extracted::default()
            }
        }
    };

    let lines: Vec<&str> = body.lines().collect();
    let mut context = Context {
        source: body,
        lines: &lines,
        line_offset,
        out: Extracted {
            doc: non_empty(attribute_doc(&file.attrs)),
            ..Extracted::default()
        },
    };
    for item in &file.items {
        context.push_item(item, None);
    }
    context.out
}

struct Context<'a> {
    source: &'a str,
    lines: &'a [&'a str],
    line_offset: u64,
    out: Extracted,
}

impl Context<'_> {
    /// Record one declaration and return its index, so children can name it.
    fn record(
        &mut self,
        kind: ItemKind,
        name: Option<String>,
        visibility: Visibility,
        attrs: &[syn::Attribute],
        tokens: TokenStream,
        span: proc_macro2::Span,
        anchor: proc_macro2::Span,
        parent: Option<usize>,
    ) -> usize {
        let walked = walk(tokens);
        // Two spans, deliberately. `span` covers the whole item INCLUDING its
        // attributes, which is what the signature slice and the end line need.
        // `anchor` is a token inside the declaration proper — the `fn`, the
        // name, the `impl` — because syn's item span begins at the first
        // attribute, and a documented function would otherwise report the line
        // of its `///`. A reported line is for a person to jump to. Deriving it
        // by skipping attribute-looking LINES instead would get a multi-line
        // `#[cfg(all(` wrong, which is why this comes from the grammar.
        let start = anchor.start();
        let end = span.end();
        let declared = start.line;
        let banner = banner_above(self.lines, declared);
        let doc = join_prose([attribute_doc(attrs), banner]);
        let index = self.out.items.len();
        self.out.items.push(ExtractedItem {
            kind,
            name,
            tokens: walked.normalized,
            signature: signature_slice(self.source, span.byte_range()),
            doc: non_empty(doc),
            visibility,
            mentions: walked.mentions,
            span: (
                declared as u64 + self.line_offset,
                start.column as u64,
                end.line as u64 + self.line_offset,
                end.column as u64,
            ),
            parent,
        });
        index
    }

    fn push_item(&mut self, item: &syn::Item, parent: Option<usize>) {
        use syn::Item;
        let span = syn::spanned::Spanned::span(item);
        let tokens = item.to_token_stream();
        match item {
            Item::Fn(node) => {
                self.record(
                    ItemKind::Fn,
                    Some(node.sig.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    spanned(&node.sig),
                    parent,
                );
            }
            Item::Struct(node) => {
                self.record(
                    ItemKind::Struct,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            Item::Enum(node) => {
                self.record(
                    ItemKind::Enum,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            Item::Union(node) => {
                self.record(
                    ItemKind::Union,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            Item::Type(node) => {
                self.record(
                    ItemKind::Type,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            Item::Const(node) => {
                self.record(
                    ItemKind::Const,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            Item::Static(node) => {
                self.record(
                    ItemKind::Static,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            Item::TraitAlias(node) => {
                self.record(
                    ItemKind::Trait,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            Item::ExternCrate(node) => {
                self.record(
                    ItemKind::Extern,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            Item::Use(node) => {
                for root in use_roots(&node.tree) {
                    self.out.import_roots.insert(root);
                }
                self.record(
                    ItemKind::Use,
                    None,
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    spanned(&node.use_token),
                    parent,
                );
            }
            Item::Macro(node) => {
                self.record(
                    ItemKind::Macro,
                    node.ident.as_ref().map(ToString::to_string),
                    Visibility::Private,
                    &node.attrs,
                    tokens,
                    span,
                    spanned(&node.mac.path),
                    parent,
                );
            }
            Item::Mod(node) => {
                let index = self.record(
                    ItemKind::Mod,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
                if let Some((_, children)) = &node.content {
                    for child in children {
                        self.push_item(child, Some(index));
                    }
                }
            }
            Item::Impl(node) => {
                let index = self.record(
                    ItemKind::Impl,
                    impl_name(node),
                    Visibility::Private,
                    &node.attrs,
                    tokens,
                    span,
                    spanned(&node.impl_token),
                    parent,
                );
                for child in &node.items {
                    self.push_impl_item(child, Some(index));
                }
            }
            Item::Trait(node) => {
                let index = self.record(
                    ItemKind::Trait,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
                for child in &node.items {
                    self.push_trait_item(child, Some(index));
                }
            }
            Item::ForeignMod(node) => {
                let index = self.record(
                    ItemKind::Extern,
                    None,
                    Visibility::Private,
                    &node.attrs,
                    tokens,
                    span,
                    spanned(&node.abi),
                    parent,
                );
                for child in &node.items {
                    self.push_foreign_item(child, Some(index));
                }
            }
            // An item this build does not model is SKIPPED, never rejected.
            _ => {}
        }
    }

    fn push_impl_item(&mut self, item: &syn::ImplItem, parent: Option<usize>) {
        use syn::ImplItem;
        let span = syn::spanned::Spanned::span(item);
        let tokens = item.to_token_stream();
        match item {
            ImplItem::Fn(node) => {
                self.record(
                    ItemKind::Fn,
                    Some(node.sig.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    spanned(&node.sig),
                    parent,
                );
            }
            ImplItem::Const(node) => {
                self.record(
                    ItemKind::Const,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            ImplItem::Type(node) => {
                self.record(
                    ItemKind::Type,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            ImplItem::Macro(node) => {
                self.record(
                    ItemKind::Macro,
                    None,
                    Visibility::Private,
                    &node.attrs,
                    tokens,
                    span,
                    spanned(&node.mac.path),
                    parent,
                );
            }
            _ => {}
        }
    }

    fn push_trait_item(&mut self, item: &syn::TraitItem, parent: Option<usize>) {
        use syn::TraitItem;
        let span = syn::spanned::Spanned::span(item);
        let tokens = item.to_token_stream();
        match item {
            TraitItem::Fn(node) => {
                self.record(
                    ItemKind::Fn,
                    Some(node.sig.ident.to_string()),
                    Visibility::Public,
                    &node.attrs,
                    tokens,
                    span,
                    spanned(&node.sig),
                    parent,
                );
            }
            TraitItem::Const(node) => {
                self.record(
                    ItemKind::Const,
                    Some(node.ident.to_string()),
                    Visibility::Public,
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            TraitItem::Type(node) => {
                self.record(
                    ItemKind::Type,
                    Some(node.ident.to_string()),
                    Visibility::Public,
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            TraitItem::Macro(node) => {
                self.record(
                    ItemKind::Macro,
                    None,
                    Visibility::Private,
                    &node.attrs,
                    tokens,
                    span,
                    spanned(&node.mac.path),
                    parent,
                );
            }
            _ => {}
        }
    }

    fn push_foreign_item(&mut self, item: &syn::ForeignItem, parent: Option<usize>) {
        use syn::ForeignItem;
        let span = syn::spanned::Spanned::span(item);
        let tokens = item.to_token_stream();
        match item {
            ForeignItem::Fn(node) => {
                self.record(
                    ItemKind::Fn,
                    Some(node.sig.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    spanned(&node.sig),
                    parent,
                );
            }
            ForeignItem::Static(node) => {
                self.record(
                    ItemKind::Static,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            ForeignItem::Type(node) => {
                self.record(
                    ItemKind::Type,
                    Some(node.ident.to_string()),
                    visibility_of(&node.vis),
                    &node.attrs,
                    tokens,
                    span,
                    node.ident.span(),
                    parent,
                );
            }
            _ => {}
        }
    }
}

/// One grammar node's span, without the attributes syn counts as part of the
/// item it belongs to.
fn spanned<T: syn::spanned::Spanned>(node: &T) -> proc_macro2::Span {
    node.span()
}

fn impl_name(node: &syn::ItemImpl) -> Option<String> {
    last_type_ident(&node.self_ty)
}

fn last_type_ident(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        syn::Type::Reference(reference) => last_type_ident(&reference.elem),
        syn::Type::Group(group) => last_type_ident(&group.elem),
        syn::Type::Paren(paren) => last_type_ident(&paren.elem),
        syn::Type::Slice(slice) => last_type_ident(&slice.elem),
        syn::Type::Array(array) => last_type_ident(&array.elem),
        syn::Type::Ptr(ptr) => last_type_ident(&ptr.elem),
        _ => None,
    }
}

/// Normalize a declared visibility into the closed vocabulary.
///
/// `pub(in crate::a::b::c)` is a real spelling here and would overflow
/// `ShortString`, which panics the encoder rather than truncating.
fn visibility_of(vis: &syn::Visibility) -> Visibility {
    match vis {
        syn::Visibility::Public(_) => Visibility::Public,
        syn::Visibility::Inherited => Visibility::Private,
        syn::Visibility::Restricted(restricted) => {
            if restricted.in_token.is_some() {
                return Visibility::Restricted;
            }
            match restricted
                .path
                .get_ident()
                .map(ToString::to_string)
                .as_deref()
            {
                Some("crate") => Visibility::Crate,
                Some("super") => Visibility::Super,
                Some("self") => Visibility::Private,
                _ => Visibility::Restricted,
            }
        }
    }
}

fn use_roots(tree: &syn::UseTree) -> Vec<String> {
    match tree {
        syn::UseTree::Path(path) => vec![path.ident.to_string()],
        syn::UseTree::Name(name) => vec![name.ident.to_string()],
        syn::UseTree::Rename(rename) => vec![rename.ident.to_string()],
        syn::UseTree::Glob(_) => Vec::new(),
        syn::UseTree::Group(group) => group.items.iter().flat_map(use_roots).collect(),
    }
}

/// The normalized token stream and the identifiers it names.
struct Walked {
    normalized: String,
    mentions: BTreeSet<String>,
}

/// One flattened token, enough to normalize and to rebuild `::` paths.
enum Flat {
    Ident(String),
    Colons,
    Other(String),
    Delimiter(&'static str),
}

/// The law, in code: depth-first over the token tree, a group's delimiters as
/// their literal characters around its contents, every piece joined by one
/// ASCII space.
///
/// Deliberately NOT `TokenStream::to_string()`: that spelling is a library
/// implementation detail, and a version bump would silently fork every item
/// identity in the pile.
fn walk(stream: TokenStream) -> Walked {
    let mut flat = Vec::new();
    flatten(stream, &mut flat);

    let mut normalized = String::new();
    for piece in &flat {
        let text = match piece {
            Flat::Ident(text) | Flat::Other(text) => text.as_str(),
            Flat::Colons => "::",
            Flat::Delimiter(text) => text,
        };
        if text.is_empty() {
            continue;
        }
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.push_str(text);
    }

    Walked {
        normalized,
        mentions: mentions_of(&flat),
    }
}

fn flatten(stream: TokenStream, out: &mut Vec<Flat>) {
    let mut pending_colon = false;
    for tree in stream {
        match tree {
            TokenTree::Group(group) => {
                if pending_colon {
                    out.push(Flat::Other(":".to_owned()));
                    pending_colon = false;
                }
                let (open, close) = match group.delimiter() {
                    Delimiter::Parenthesis => ("(", ")"),
                    Delimiter::Brace => ("{", "}"),
                    Delimiter::Bracket => ("[", "]"),
                    Delimiter::None => ("", ""),
                };
                if !open.is_empty() {
                    out.push(Flat::Delimiter(open));
                }
                flatten(group.stream(), out);
                if !close.is_empty() {
                    out.push(Flat::Delimiter(close));
                }
            }
            TokenTree::Ident(ident) => {
                if pending_colon {
                    out.push(Flat::Other(":".to_owned()));
                    pending_colon = false;
                }
                out.push(Flat::Ident(ident.to_string()));
            }
            TokenTree::Punct(punct) => {
                if pending_colon {
                    pending_colon = false;
                    if punct.as_char() == ':' {
                        out.push(Flat::Colons);
                        continue;
                    }
                    out.push(Flat::Other(":".to_owned()));
                }
                if punct.as_char() == ':' && punct.spacing() == Spacing::Joint {
                    pending_colon = true;
                    continue;
                }
                out.push(Flat::Other(punct.as_char().to_string()));
            }
            TokenTree::Literal(literal) => {
                if pending_colon {
                    out.push(Flat::Other(":".to_owned()));
                    pending_colon = false;
                }
                out.push(Flat::Other(literal.to_string()));
            }
        }
    }
    if pending_colon {
        out.push(Flat::Other(":".to_owned()));
    }
}

/// Every identifier this declaration syntactically names: each path segment,
/// and every `::`-joined prefix of two segments or more.
///
/// Macro bodies are ordinary token trees here, so a path that only ever appears
/// inside `pattern!` or `entity!` is recovered exactly like any other — which
/// is the whole point, since a visitor over the AST sees four `pattern!`
/// invocations in this corpus and this walk sees every identifier inside them.
fn mentions_of(flat: &[Flat]) -> BTreeSet<String> {
    let mut mentions = BTreeSet::new();
    let mut at = 0;
    while at < flat.len() {
        let Flat::Ident(first) = &flat[at] else {
            at += 1;
            continue;
        };
        let mut segments = vec![first.clone()];
        let mut cursor = at + 1;
        while cursor + 1 < flat.len() {
            if !matches!(flat[cursor], Flat::Colons) {
                break;
            }
            let Flat::Ident(next) = &flat[cursor + 1] else {
                break;
            };
            segments.push(next.clone());
            cursor += 2;
        }
        for segment in &segments {
            if is_mentionable(segment) {
                mentions.insert(segment.clone());
            }
        }
        // Every PREFIX of two segments or more, not just the whole path, so
        // `code uses burn::train` is exact even when the spelling in the source
        // was `burn::train::LearnerBuilder`.
        for length in 2..=segments.len() {
            mentions.insert(segments[..length].join("::"));
        }
        at = cursor.max(at + 1);
    }
    mentions
}

/// Rust keywords are `Ident`s to a token walker, and a catalogue in which every
/// item mentions `fn`, `let` and `self` has learned nothing.
const KEYWORDS: &[&str] = &[
    "_", "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum",
    "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move",
    "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true",
    "type", "union", "unsafe", "use", "where", "while", "abstract", "become", "box", "do", "final",
    "macro", "override", "priv", "try", "typeof", "unsized", "virtual", "yield",
];

fn is_mentionable(ident: &str) -> bool {
    !ident.is_empty() && !KEYWORDS.contains(&ident)
}

/// The declaration head, sliced from the source rather than re-printed.
///
/// `quote` mangles spacing, and this string exists so a person can recognise
/// the declaration at the end of a result line.
fn signature_slice(source: &str, range: std::ops::Range<usize>) -> String {
    let end = range.end.min(source.len());
    let start = range.start.min(end);
    // A byte range that does not land on a character boundary would panic the
    // slice and take a whole ingest with it. There is no reason to expect one
    // from a token span, which is exactly why it is worth not betting the run
    // on that expectation.
    let Some(slice) = source.get(start..end) else {
        return String::new();
    };

    let mut head = String::new();
    for line in slice.lines() {
        let trimmed = line.trim();
        // Attributes and doc comments precede the declaration; the head starts
        // at the first line that is neither.
        if head.is_empty()
            && (trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//"))
        {
            continue;
        }
        if !head.is_empty() {
            head.push(' ');
        }
        head.push_str(trimmed);
        if trimmed.contains('{') || trimmed.ends_with(';') {
            break;
        }
    }
    if let Some(at) = head.find('{') {
        head.truncate(at);
    }
    let head = head.trim().trim_end_matches(';').trim().to_owned();
    truncate_chars(head, MAX_SIGNATURE_CHARS)
}

fn truncate_chars(mut text: String, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text;
    }
    let cut = text
        .char_indices()
        .nth(limit)
        .map(|(at, _)| at)
        .unwrap_or(text.len());
    text.truncate(cut);
    text.push('…');
    text
}

/// `///` and `//!` prose carried by attributes, as syn sees it.
fn attribute_doc(attrs: &[syn::Attribute]) -> String {
    let mut prose = String::new();
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        let syn::Meta::NameValue(pair) = &attr.meta else {
            continue;
        };
        let syn::Expr::Lit(literal) = &pair.value else {
            continue;
        };
        let syn::Lit::Str(text) = &literal.lit else {
            continue;
        };
        if !prose.is_empty() {
            prose.push('\n');
        }
        prose.push_str(text.value().trim());
    }
    prose
}

/// Plain `//` banner comments immediately above a declaration.
///
/// syn discards these entirely, and they are exactly the text that says what a
/// block of kernels is FOR — the capability sentence that a doc comment on an
/// individual function never carries.
fn banner_above(lines: &[&str], line: usize) -> String {
    if line == 0 {
        return String::new();
    }
    let mut collected: Vec<String> = Vec::new();
    let mut blanks = 0usize;
    let mut cursor = line - 1; // 1-based line number to 0-based index of the line above
    loop {
        if cursor == 0 {
            break;
        }
        cursor -= 1;
        let trimmed = lines[cursor].trim();
        if trimmed.is_empty() {
            blanks += 1;
            if blanks > 1 || !collected.is_empty() {
                break;
            }
            continue;
        }
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }
        if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
            continue;
        }
        if let Some(text) = trimmed.strip_prefix("//") {
            collected.push(text.trim().to_owned());
            if collected.len() >= MAX_BANNER_LINES {
                break;
            }
            continue;
        }
        break;
    }
    collected.reverse();
    collected.join("\n")
}

/// `//!` prose recovered by reading lines, for a file syn refused.
fn inner_doc_prose(source: &str) -> String {
    let mut prose = String::new();
    for line in source.lines() {
        let trimmed = line.trim();
        let Some(text) = trimmed.strip_prefix("//!") else {
            continue;
        };
        if !prose.is_empty() {
            prose.push('\n');
        }
        prose.push_str(text.trim());
    }
    prose
}

/// Comment prose for a language this build does not parse.
///
/// A leading shebang is an interpreter directive, not prose about the script,
/// and `#!/bin/sh` rendered as the comment "!/bin/sh" would be noise in every
/// search result a shell script ever appeared in.
fn comment_prose(source: &str, marker: &str) -> String {
    let mut prose = String::new();
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if index == 0 && trimmed.starts_with("#!") {
            continue;
        }
        let Some(text) = trimmed.strip_prefix(marker) else {
            continue;
        };
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        if !prose.is_empty() {
            prose.push('\n');
        }
        prose.push_str(text);
    }
    prose
}

fn join_prose(parts: impl IntoIterator<Item = String>) -> String {
    let mut prose = String::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if !prose.is_empty() {
            prose.push('\n');
        }
        prose.push_str(part);
    }
    prose
}

fn non_empty(text: String) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rust(source: &str) -> Extracted {
        extract(source, Language::Rust)
    }

    fn named<'a>(extracted: &'a Extracted, name: &str) -> &'a ExtractedItem {
        extracted
            .items
            .iter()
            .find(|item| item.name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("no item named {name}"))
    }

    #[test]
    fn a_rust_script_shebang_is_stripped_before_parsing() {
        let extracted = rust("#!/usr/bin/env rust-script\nfn main() {}\n");
        assert_eq!(extracted.parse_error, None);
        assert_eq!(extracted.items.len(), 1);
        // The offset keeps the reported line true to the original file.
        assert_eq!(extracted.items[0].span.0, 2);
    }

    #[test]
    fn an_inner_attribute_is_not_mistaken_for_a_shebang() {
        let extracted = rust("#![allow(dead_code)]\nfn main() {}\n");
        assert_eq!(extracted.parse_error, None);
        assert_eq!(extracted.items[0].span.0, 2);
    }

    #[test]
    fn an_unparseable_file_yields_a_unit_with_a_parse_error_and_no_items() {
        let extracted = rust("//! still prose\nfn broken( {\n");
        assert!(extracted.parse_error.is_some());
        assert!(extracted.items.is_empty());
        assert_eq!(extracted.doc.as_deref(), Some("still prose"));
    }

    #[test]
    fn a_banner_comment_above_a_function_becomes_part_of_its_doc() {
        let extracted = rust(
            "// ── GPU force-directed layout kernel ──\n/// One integration step.\npub fn step() {}\n",
        );
        let doc = named(&extracted, "step").doc.clone().unwrap();
        assert!(doc.contains("One integration step."), "{doc}");
        assert!(doc.contains("GPU force-directed layout kernel"), "{doc}");
    }

    #[test]
    fn a_path_inside_a_macro_token_stream_is_recovered_as_a_mention() {
        let extracted = rust("fn q() { pattern!(&facts, [{ ?i @ attrs::mentions: name }]); }\n");
        let mentions = &named(&extracted, "q").mentions;
        assert!(mentions.contains("attrs::mentions"), "{mentions:?}");
        assert!(mentions.contains("attrs"));
        assert!(mentions.contains("mentions"));
        assert!(mentions.contains("pattern"));
    }

    #[test]
    fn a_use_tree_emits_both_its_segments_and_its_joined_path() {
        let extracted = rust("use burn::train::LearnerBuilder;\n");
        assert!(extracted.import_roots.contains("burn"));
        let mentions = &extracted.items[0].mentions;
        assert!(
            mentions.contains("burn::train::LearnerBuilder"),
            "{mentions:?}"
        );
        assert!(mentions.contains("burn::train"));
        assert!(mentions.contains("LearnerBuilder"));
    }

    #[test]
    fn a_keyword_is_not_a_mention() {
        let extracted = rust("pub fn f(x: u8) -> u8 { let y = x; y }\n");
        let mentions = &named(&extracted, "f").mentions;
        assert!(!mentions.contains("let"));
        assert!(!mentions.contains("pub"));
        assert!(!mentions.contains("fn"));
        assert!(mentions.contains("u8"));
    }

    #[test]
    fn token_normalization_ignores_whitespace_but_not_doc_comments() {
        let spaced = rust("pub   fn   f( )   {   }\n");
        let tight = rust("pub fn f(){}\n");
        assert_eq!(spaced.items[0].tokens, tight.items[0].tokens);

        let documented = rust("/// prose\npub fn f(){}\n");
        assert_ne!(documented.items[0].tokens, tight.items[0].tokens);
    }

    #[test]
    fn two_byte_identical_functions_normalize_to_the_same_token_string() {
        let here = rust("mod a { pub fn arc_points() -> u8 { 1 } }\n");
        let there = rust("mod b {\n    pub fn arc_points() -> u8 {\n        1\n    }\n}\n");
        assert_eq!(
            named(&here, "arc_points").tokens,
            named(&there, "arc_points").tokens
        );
    }

    #[test]
    fn a_restricted_visibility_normalizes_to_a_closed_vocabulary_value() {
        let extracted = rust("pub(in crate::a::b::c) fn deep() {}\npub(crate) fn near() {}\n");
        assert_eq!(named(&extracted, "deep").visibility, Visibility::Restricted);
        assert_eq!(named(&extracted, "near").visibility, Visibility::Crate);
        for item in &extracted.items {
            assert!(item.visibility.name().len() <= 32);
        }
    }

    #[test]
    fn an_impl_is_named_for_its_self_type_and_holds_its_methods() {
        let extracted =
            rust("struct Learner;\nimpl Learner { pub fn new() -> Self { Learner } }\n");
        let outer = extracted
            .items
            .iter()
            .position(|item| item.kind == ItemKind::Impl)
            .unwrap();
        assert_eq!(extracted.items[outer].name.as_deref(), Some("Learner"));
        let method = named(&extracted, "new");
        assert_eq!(method.parent, Some(outer));
    }

    #[test]
    fn a_signature_is_the_source_head_without_its_attributes() {
        let extracted = rust("/// prose\n#[inline]\npub fn f(x: u8) -> u8 { x }\n");
        assert_eq!(named(&extracted, "f").signature, "pub fn f(x: u8) -> u8");
    }

    #[test]
    fn a_prose_file_is_ingested_as_its_own_text_with_no_items() {
        let extracted = extract("# Title\n\nbody text\n", Language::Markdown);
        assert!(extracted.items.is_empty());
        assert_eq!(extracted.parse_error, None);
        assert!(extracted.doc.unwrap().contains("body text"));
    }

    #[test]
    fn a_shell_script_keeps_its_comment_prose() {
        let extracted = extract(
            "#!/bin/sh\n# take the lock first\nexit 0\n",
            Language::Shell,
        );
        assert_eq!(extracted.doc.as_deref(), Some("take the lock first"));
    }

    #[test]
    fn a_turbofish_does_not_swallow_the_following_type() {
        let extracted = rust("fn f() { let v = Vec::<u8>::new(); }\n");
        let mentions = &named(&extracted, "f").mentions;
        assert!(mentions.contains("Vec"), "{mentions:?}");
        assert!(mentions.contains("u8"));
    }
}
