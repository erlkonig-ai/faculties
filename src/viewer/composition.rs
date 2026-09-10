//! One shared composition for the dashboard, focused CLI wrappers and MCP.

use super::{Target, Viewer};
use crate::widgets::{
    AtlasViewer, BranchTimeline, CompassBoard, DecidePanel, DiscordViewer, FilesViewer,
    GaugeViewer, HeadspaceViewer, MailViewer, MemoryViewer, MessagesPanel, PlannerViewer,
    RelationsViewer, SourceKey, StatusViewer, StorageState, TeamsViewer, TimelineSource,
    TriageViewer, WikiViewer,
};
use GORBIE::prelude::*;

impl Target {
    pub(crate) fn sources(self) -> &'static [SourceKey] {
        match self {
            Self::Dashboard => &SourceKey::ALL,
            Self::Atlas => &[SourceKey::Atlas],
            Self::Discord => &[SourceKey::Discord],
            Self::Files => &[SourceKey::Files],
            Self::Gauge => &[SourceKey::Wiki],
            Self::Headspace => &[SourceKey::Headspace],
            Self::Memory => &[SourceKey::Memory],
            Self::Messages => &[SourceKey::Messages],
            Self::Planner => &[SourceKey::Planner],
            Self::Status => &[SourceKey::Status],
            Self::Teams => &[SourceKey::Teams],
            Self::Triage => &[SourceKey::Triage],
        }
    }
}

/// Add the original ordered cards against the same shared lazy storage state.
/// Arguments are native values; no argv, environment or process exit is read
/// here. Storage retains its frozen observation and dependency closure rules.
pub fn compose(nb: &mut NotebookCtx, viewer: &Viewer, target: Target) {
    let storage = nb.state(
        "storage",
        StorageState::with_storage(viewer.storage.clone(), target.sources().iter().copied()),
        move |ctx, st| {
            if target == Target::Dashboard {
                ctx.set_default_section_open(false);
            }
            st.top_bar(ctx);
        },
    );

    if target == Target::Dashboard || target == Target::Status {
        nb.state("status", StatusViewer::default(), move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let sources = st.context();
            let Some(view) = sources.dataset(SourceKey::Status) else {
                return;
            };
            panel.render(ctx, view, sources.dataset(SourceKey::Relations));
        });
    }

    if target == Target::Dashboard || target == Target::Headspace {
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
    }

    if target == Target::Dashboard {
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
    }

    if target == Target::Dashboard || target == Target::Gauge {
        nb.state("gauge", GaugeViewer::default(), move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let Some(view) = st.context().dataset(SourceKey::Wiki) else {
                return;
            };
            panel.render(ctx, view);
        });
    }

    if target == Target::Dashboard {
        nb.state("wiki", WikiViewer::default(), move |ctx, wiki| {
            let mut st = storage.read_mut(ctx);
            let sources = st.context();
            let Some(view) = sources.dataset(SourceKey::Wiki) else {
                return;
            };
            wiki.render(ctx, view, sources.dataset(SourceKey::Files));
        });
    }

    if target == Target::Dashboard {
        nb.state("compass", CompassBoard::default(), move |ctx, compass| {
            let mut st = storage.read_mut(ctx);
            let Some(view) = st.context().dataset(SourceKey::Compass) else {
                return;
            };
            compass.render(ctx, view);
        });
    }

    if target == Target::Dashboard {
        nb.state("decide", DecidePanel::default(), move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let Some(view) = st.context().dataset(SourceKey::Decide) else {
                return;
            };
            panel.render(ctx, view);
        });
    }

    if target == Target::Dashboard {
        nb.state("mail", MailViewer::default(), move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let sources = st.context();
            let Some(view) = sources.dataset(SourceKey::Mail) else {
                return;
            };
            panel.render(ctx, view, sources.dataset(SourceKey::Relations));
        });
    }

    if target == Target::Dashboard || target == Target::Planner {
        nb.state("planner", PlannerViewer::default(), move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let sources = st.context();
            let Some(view) = sources.dataset(SourceKey::Planner) else {
                return;
            };
            panel.render(ctx, view, sources.dataset(SourceKey::Relations));
        });
    }

    if target == Target::Dashboard || target == Target::Messages {
        nb.state("messages", MessagesPanel::default(), move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let sources = st.context();
            let Some(view) = sources.dataset(SourceKey::Messages) else {
                return;
            };
            panel.render(ctx, view, sources.dataset(SourceKey::Relations));
        });
    }

    if target == Target::Dashboard || target == Target::Discord {
        nb.state("discord", DiscordViewer::default(), move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let Some(view) = st.context().dataset(SourceKey::Discord) else {
                return;
            };
            panel.render(ctx, view);
        });
    }

    if target == Target::Dashboard || target == Target::Teams {
        nb.state("teams", TeamsViewer::default(), move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let Some(view) = st.context().dataset(SourceKey::Teams) else {
                return;
            };
            panel.render(ctx, view);
        });
    }

    if target == Target::Dashboard {
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
    }

    if target == Target::Dashboard || target == Target::Memory {
        nb.state("memory", MemoryViewer::default(), move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let Some(view) = st.context().dataset(SourceKey::Memory) else {
                return;
            };
            panel.render(ctx, view);
        });
    }

    if target == Target::Dashboard || target == Target::Files {
        nb.state("files", FilesViewer::default(), move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let Some(view) = st.context().dataset(SourceKey::Files) else {
                return;
            };
            panel.render(ctx, view);
        });
    }

    if target == Target::Dashboard || target == Target::Triage {
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
    }

    if target == Target::Dashboard || target == Target::Atlas {
        nb.state("atlas", AtlasViewer::default(), move |ctx, panel| {
            let mut st = storage.read_mut(ctx);
            let Some(view) = st.context().dataset(SourceKey::Atlas) else {
                return;
            };
            panel.render(ctx, view);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focused_inputs_keep_the_original_roots_and_storage_owns_dependencies() {
        assert_eq!(Target::Dashboard.sources(), &SourceKey::ALL);
        for (target, source) in [
            (Target::Atlas, SourceKey::Atlas),
            (Target::Discord, SourceKey::Discord),
            (Target::Files, SourceKey::Files),
            (Target::Gauge, SourceKey::Wiki),
            (Target::Headspace, SourceKey::Headspace),
            (Target::Memory, SourceKey::Memory),
            (Target::Messages, SourceKey::Messages),
            (Target::Planner, SourceKey::Planner),
            (Target::Status, SourceKey::Status),
            (Target::Teams, SourceKey::Teams),
            (Target::Triage, SourceKey::Triage),
        ] {
            assert_eq!(target.sources(), &[source]);
        }
    }
}
