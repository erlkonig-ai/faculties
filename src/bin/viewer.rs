//! GORBIE-backed viewer for a faculties pile.
//!
//! Composes the faculty dashboard widgets against a single shared
//! pile — the GUI counterpart to the CLI faculties in the repo root.
//!
//! Usage:
//! ```sh
//! cargo install faculties --features widgets
//! viewer ./self.pile
//! # or set PILE=./self.pile in the environment; anything passed
//! # on the command line (--pile <path> or positional) beats it
//! ```
//!
//! `examples/pile_inspector.rs` is a smaller source reference for
//! library users composing their own notebook layouts.

use std::path::PathBuf;

use faculties::widgets::{
    AtlasViewer, BranchTimeline, CompassBoard, DecidePanel, DiscordViewer, FilesViewer,
    GaugeViewer, HeadspaceViewer, MailViewer, MemoryViewer, MessagesPanel, PlannerViewer,
    RelationsViewer, SourceKey, StatusViewer, StorageState, TeamsViewer, TimelineSource,
    TriageViewer, WikiViewer,
};
use GORBIE::notebook;
use GORBIE::prelude::*;

fn resolve_pile_path() -> PathBuf {
    // Handled before anything else so `--version` works without a pile,
    // a display, or any other argument. Prints crate version + baked git
    // hash — the stale-binary question, answerable in one flag.
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!(
            "{} {} ({})",
            env!("CARGO_BIN_NAME"),
            env!("CARGO_PKG_VERSION"),
            env!("FACULTIES_GIT_VERSION"),
        );
        std::process::exit(0);
    }
    faculties::widgets::resolve_pile_path(std::env::args().skip(1), std::env::var("PILE").ok())
}

#[notebook]
fn main(nb: &mut NotebookCtx) {
    let path = resolve_pile_path();

    let storage = nb.state("storage", StorageState::new(path), |ctx, st| {
        // Dashboard-style notebook: every widget section starts
        // collapsed so the initial view is a scannable list of
        // section headers instead of kilometres of open cards. A
        // user's toggle is persisted per section and wins over this
        // default on later runs; headless captures ignore it and
        // always render sections open.
        ctx.set_default_section_open(false);
        st.top_bar(ctx);
    });

    nb.state("status", StatusViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let sources = st.context();
        let Some(view) = sources.dataset(SourceKey::Status) else {
            return;
        };
        panel.render(ctx, view, sources.dataset(SourceKey::Relations));
    });

    nb.state(
        "headspace",
        HeadspaceViewer::default(),
        move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let sources = st.context();
            let Some(headspace) = sources.dataset(SourceKey::Headspace) else {
                return;
            };
            let Some(secrets) = sources.secrets() else {
                return;
            };
            panel.render(ctx, headspace, secrets);
        },
    );

    nb.state(
        "timeline",
        BranchTimeline::multi(vec![
            TimelineSource::Compass {
                key: SourceKey::Compass,
                label: "goals".to_owned(),
            },
            TimelineSource::LocalMessages {
                key: SourceKey::Messages,
                label: "local".to_owned(),
            },
            TimelineSource::Wiki {
                key: SourceKey::Wiki,
                label: "wiki".to_owned(),
            },
            TimelineSource::Reason {
                key: SourceKey::Reason,
                label: "reason".to_owned(),
            },
            TimelineSource::Archive {
                key: SourceKey::Archive,
                label: "archive".to_owned(),
            },
        ]),
        move |ctx, tl| {
            let mut st = storage.read_mut(ctx);
            let sources = st.context();
            tl.render(ctx, &sources);
        },
    );

    nb.state("gauge", GaugeViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(view) = st.context().dataset(SourceKey::Wiki) else {
            return;
        };
        panel.render(ctx, view);
    });

    nb.state("wiki", WikiViewer::default(), move |ctx, wiki| {
        let mut st = storage.read_mut(ctx);
        let sources = st.context();
        let Some(view) = sources.dataset(SourceKey::Wiki) else {
            return;
        };
        wiki.render(ctx, view, sources.dataset(SourceKey::Files));
    });

    nb.state("compass", CompassBoard::default(), move |ctx, compass| {
        let mut st = storage.read_mut(ctx);
        let Some(view) = st.context().dataset(SourceKey::Compass) else {
            return;
        };
        compass.render(ctx, view);
    });

    nb.state("decide", DecidePanel::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(view) = st.context().dataset(SourceKey::Decide) else {
            return;
        };
        panel.render(ctx, view);
    });

    nb.state("mail", MailViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let sources = st.context();
        let Some(view) = sources.dataset(SourceKey::Mail) else {
            return;
        };
        panel.render(ctx, view, sources.dataset(SourceKey::Relations));
    });

    nb.state("planner", PlannerViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let sources = st.context();
        let Some(view) = sources.dataset(SourceKey::Planner) else {
            return;
        };
        panel.render(ctx, view, sources.dataset(SourceKey::Relations));
    });

    nb.state("messages", MessagesPanel::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let sources = st.context();
        let Some(view) = sources.dataset(SourceKey::Messages) else {
            return;
        };
        panel.render(ctx, view, sources.dataset(SourceKey::Relations));
    });

    nb.state("discord", DiscordViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(view) = st.context().dataset(SourceKey::Discord) else {
            return;
        };
        panel.render(ctx, view);
    });

    nb.state("teams", TeamsViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(view) = st.context().dataset(SourceKey::Teams) else {
            return;
        };
        panel.render(ctx, view);
    });

    nb.state(
        "relations",
        RelationsViewer::default(),
        move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let Some(view) = st.context().dataset(SourceKey::Relations) else {
                return;
            };
            panel.render(ctx, view);
        },
    );

    nb.state("memory", MemoryViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(view) = st.context().dataset(SourceKey::Memory) else {
            return;
        };
        panel.render(ctx, view);
    });

    nb.state("files", FilesViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(view) = st.context().dataset(SourceKey::Files) else {
            return;
        };
        panel.render(ctx, view);
    });

    nb.state("triage", TriageViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let sources = st.context();
        let Some(cognition) = sources.dataset(SourceKey::Triage) else {
            return;
        };
        let Some(headspace) = sources.dataset(SourceKey::Headspace) else {
            return;
        };
        let Some(secrets) = sources.secrets() else {
            return;
        };
        let Some(relations) = sources.dataset(SourceKey::Relations) else {
            return;
        };
        let Some(messages) = sources.dataset(SourceKey::Messages) else {
            return;
        };
        panel.render(ctx, cognition, headspace, secrets, relations, messages);
    });

    nb.state("atlas", AtlasViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(view) = st.context().dataset(SourceKey::Atlas) else {
            return;
        };
        panel.render(ctx, view);
    });
}
