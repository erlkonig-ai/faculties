//! The aggregate native faculty catalogue, independent of its transport.
//!
//! A launcher supplies trusted configuration explicitly. Construction and tool
//! discovery do not read environment variables, open a pile or signing key,
//! load a model, or contact an external service.

use std::path::PathBuf;

use super::Faculty;
use crate::{
    archive, atlas, body, bootstrap, cognition, compass, decide, discord, duplex, files, gauge,
    habits, headspace, hear, imagine, linkedin, mail, memory, message, orient, patience, planner,
    posture, reason, relations, secrets, status, teams, triage, viewer, voice, web, wiki,
};

/// Trusted launcher configuration, never supplied as MCP tool arguments.
/// Credentials are deliberately not included in a derived debug formatter.
pub struct Config {
    pub pile: PathBuf,
    pub key: Option<PathBuf>,
    pub discord_token: Option<String>,
    pub linkedin_token: Option<String>,
    pub duplex_session: Option<PathBuf>,
    pub hear: Option<hear::ModelConfig>,
}

impl Config {
    /// Configure one pile, leaving optional credentials and model assets unset.
    /// Neither defaults nor construction consult the process environment.
    pub fn new(pile: impl Into<PathBuf>) -> Self {
        Self {
            pile: pile.into(),
            key: None,
            discord_token: None,
            linkedin_token: None,
            duplex_session: None,
            hear: None,
        }
    }
}

/// Owned native adapters in the aggregate's stable registration order.
/// Protocol/session state belongs to a transport's [`super::Server`], not here.
pub struct Catalog {
    faculties: Vec<Box<dyn Faculty>>,
}

impl Catalog {
    pub fn new(config: Config) -> Self {
        let Config {
            pile,
            key,
            discord_token,
            linkedin_token,
            duplex_session,
            hear: hear_config,
        } = config;
        let discord = discord::mcp::Discord::new(pile.clone(), key.clone());
        let discord = match discord_token {
            Some(token) => discord.with_token(token),
            None => discord,
        };
        let linkedin = linkedin::mcp::LinkedIn::new(pile.clone(), key.clone());
        let linkedin = match linkedin_token {
            Some(token) => linkedin.with_token(token),
            None => linkedin,
        };
        let faculties: Vec<Box<dyn Faculty>> = vec![
            Box::new(archive::mcp::Archive::new(pile.clone(), key.clone())),
            Box::new(atlas::mcp::Atlas::new(pile.clone(), key.clone())),
            Box::new(body::mcp::Body::new(pile.clone(), key.clone())),
            Box::new(bootstrap::mcp::Bootstrap::new(pile.clone(), key.clone())),
            Box::new(cognition::mcp::Cognition::new(pile.clone(), key.clone())),
            Box::new(compass::mcp::Compass::new(pile.clone(), key.clone())),
            Box::new(decide::mcp::Decide::new(pile.clone(), key.clone())),
            Box::new(discord),
            Box::new(duplex::mcp::Duplex::new(duplex_session)),
            Box::new(files::mcp::Files::new(pile.clone(), key.clone())),
            Box::new(gauge::mcp::Gauge::new(pile.clone(), key.clone())),
            Box::new(habits::mcp::Habits::new(pile.clone(), key.clone())),
            Box::new(headspace::mcp::Headspace::new(pile.clone(), key.clone())),
            Box::new(hear::mcp::Hear::new(hear_config)),
            Box::new(imagine::mcp::Imagine::new(pile.clone(), key.clone())),
            Box::new(linkedin),
            Box::new(mail::mcp::Mail::new(pile.clone(), key.clone())),
            Box::new(memory::mcp::Memory::new(pile.clone(), key.clone())),
            Box::new(message::mcp::Message::new(pile.clone(), key.clone())),
            Box::new(orient::mcp::Orient::new(pile.clone(), key.clone())),
            Box::new(patience::mcp::Patience::new(pile.clone(), key.clone())),
            Box::new(planner::mcp::Planner::new(pile.clone(), key.clone())),
            Box::new(posture::mcp::Posture::new(pile.clone(), key.clone())),
            Box::new(reason::mcp::Reason::new(pile.clone(), key.clone())),
            Box::new(relations::mcp::Relations::new(pile.clone(), key.clone())),
            Box::new(secrets::mcp::Secrets::new(pile.clone(), key.clone())),
            Box::new(status::mcp::Status::new(pile.clone(), key.clone())),
            Box::new(teams::mcp::Teams::new(pile.clone(), key.clone())),
            Box::new(triage::mcp::Triage::new(pile.clone(), key.clone())),
            Box::new(viewer::mcp::Viewer::new(pile.clone(), key.clone())),
            Box::new(voice::mcp::Voice::new(pile.clone(), key.clone())),
            Box::new(web::mcp::Web::new(pile.clone(), key.clone())),
            Box::new(wiki::mcp::Wiki::new(pile, key)),
        ];
        Self { faculties }
    }

    /// Borrow the same adapters for a stdio connection or an HTTP listener.
    pub fn registrations(&self) -> Vec<&dyn Faculty> {
        self.faculties
            .iter()
            .map(|faculty| faculty.as_ref())
            .collect()
    }
}
