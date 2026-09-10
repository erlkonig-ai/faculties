//! The aggregate native faculty catalogue, independent of its transport.
//!
//! A launcher supplies trusted configuration explicitly. Construction and tool
//! discovery do not read environment variables, open a pile or signing key,
//! load a model, or contact an external service.

use anyhow::Result;
use std::path::PathBuf;

use super::Faculty;
use crate::storage::Storage;
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
    storage: Storage,
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
        let storage = Storage::shared(pile, key);
        let discord = discord::mcp::Discord::with_storage(storage.clone());
        let discord = match discord_token {
            Some(token) => discord.with_token(token),
            None => discord,
        };
        let linkedin = linkedin::mcp::LinkedIn::with_storage(storage.clone());
        let linkedin = match linkedin_token {
            Some(token) => linkedin.with_token(token),
            None => linkedin,
        };
        let faculties: Vec<Box<dyn Faculty>> = vec![
            Box::new(archive::mcp::Archive::with_storage(storage.clone())),
            Box::new(atlas::mcp::Atlas::with_storage(storage.clone())),
            Box::new(body::mcp::Body::with_storage(storage.clone())),
            Box::new(bootstrap::mcp::Bootstrap::with_storage(storage.clone())),
            Box::new(cognition::mcp::Cognition::with_storage(storage.clone())),
            Box::new(compass::mcp::Compass::with_storage(storage.clone())),
            Box::new(decide::mcp::Decide::with_storage(storage.clone())),
            Box::new(discord),
            Box::new(duplex::mcp::Duplex::new(duplex_session)),
            Box::new(files::mcp::Files::with_storage(storage.clone())),
            Box::new(gauge::mcp::Gauge::with_storage(storage.clone())),
            Box::new(habits::mcp::Habits::with_storage(storage.clone())),
            Box::new(headspace::mcp::Headspace::with_storage(storage.clone())),
            Box::new(hear::mcp::Hear::new(hear_config)),
            Box::new(imagine::mcp::Imagine::with_storage(storage.clone())),
            Box::new(linkedin),
            Box::new(mail::mcp::Mail::with_storage(storage.clone())),
            Box::new(memory::mcp::Memory::with_storage(storage.clone())),
            Box::new(message::mcp::Message::with_storage(storage.clone())),
            Box::new(orient::mcp::Orient::with_storage(storage.clone())),
            Box::new(patience::mcp::Patience::with_storage(storage.clone())),
            Box::new(planner::mcp::Planner::with_storage(storage.clone())),
            Box::new(posture::mcp::Posture::with_storage(storage.clone())),
            Box::new(reason::mcp::Reason::with_storage(storage.clone())),
            Box::new(relations::mcp::Relations::with_storage(storage.clone())),
            Box::new(secrets::mcp::Secrets::with_storage(storage.clone())),
            Box::new(status::mcp::Status::with_storage(storage.clone())),
            Box::new(teams::mcp::Teams::with_storage(storage.clone())),
            Box::new(triage::mcp::Triage::with_storage(storage.clone())),
            Box::new(viewer::mcp::Viewer::with_storage(storage.clone())),
            Box::new(voice::mcp::Voice::with_storage(storage.clone())),
            Box::new(web::mcp::Web::with_storage(storage.clone())),
            Box::new(wiki::mcp::Wiki::with_storage(storage.clone())),
        ];
        Self { faculties, storage }
    }

    /// Flush and close the application-owned store after transport shutdown.
    /// Protocol session expiry does not close this shared owner.
    pub fn close(&self) -> Result<()> {
        self.storage.close()
    }

    /// Close storage without losing a transport's error, if it also failed.
    pub fn finish<T>(&self, result: Result<T>) -> Result<T> {
        self.storage.finish(result)
    }

    /// Borrow the same adapters for a stdio connection or an HTTP listener.
    pub fn registrations(&self) -> Vec<&dyn Faculty> {
        self.faculties
            .iter()
            .map(|faculty| faculty.as_ref())
            .collect()
    }
}
