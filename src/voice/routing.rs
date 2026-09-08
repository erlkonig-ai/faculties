//! Pure route resolution; say never resolves to a public output.

/// What a device means for the privacy contract.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceClass {
    /// In-ear / headphone — a PRIVATE listening device. The only class `say` may
    /// ever play through.
    Private,
    /// The Reachy Mini's own speaker — a public, in-the-room device (NOT
    /// private), reachable through the daemon.
    Reachy,
    /// Any other output: laptop / display / room speakers. Public, audible.
    Speaker,
}

impl DeviceClass {
    pub fn label(self) -> &'static str {
        match self {
            DeviceClass::Private => "private",
            DeviceClass::Reachy => "reachy",
            DeviceClass::Speaker => "speaker",
        }
    }
}

/// Classify a device by its name. This is the load-bearing privacy gate: only
/// names that read as personal listening hardware return `Private`. Anything not
/// recognised as private is treated as public — fail-closed, never fail-open.
pub fn classify(name: &str) -> DeviceClass {
    let n = name.to_lowercase();
    // Room-speaker markers beat brand hints: a "Beats Pill" is a speaker even
    // though "beats" reads as headphone-brand. Checked FIRST so a brand
    // substring can never launder a speaker into Private (fail-closed).
    const SPEAKER_MARKERS: &[&str] = &["pill", "speaker", "soundlink", "sonos", "homepod"];
    if SPEAKER_MARKERS.iter().any(|h| n.contains(h)) {
        return DeviceClass::Speaker;
    }
    const PRIVATE_HINTS: &[&str] = &[
        "airpods",
        "headphone",
        "headset",
        "earbud",
        "earphone",
        "earpod",
        "ear pod",
        "in-ear",
        "beats",
        "buds",
        " wf-",
        " wh-",
        "powerbeats",
    ];
    if PRIVATE_HINTS.iter().any(|h| n.contains(h)) {
        return DeviceClass::Private;
    }
    if n.contains("reachy") {
        return DeviceClass::Reachy;
    }
    DeviceClass::Speaker
}

#[derive(Clone, Debug)]
pub struct AudioDevice {
    pub name: String,
    pub is_default_output: bool,
}

impl AudioDevice {
    pub fn class(&self) -> DeviceClass {
        classify(&self.name)
    }
}

/// Connected devices whose name contains `pat` (case-insensitive), in
/// enumeration order — a pattern can ladder several devices ("AirPods"
/// matches the Max and the Pro; the router keeps them all as fallbacks).
fn connected_matches<'a>(
    pat: &str,
    devices: &'a [AudioDevice],
) -> impl Iterator<Item = &'a AudioDevice> {
    let needle = pat.to_lowercase();
    devices
        .iter()
        .filter(move |d| d.name.to_lowercase().contains(&needle))
}

/// The outcome of resolving a channel's routing against the live devices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Routed {
    /// Play through the Reachy robot speaker (daemon upload + play).
    Reachy,
    /// Play through the native sink on the first OPENABLE device of this
    /// non-empty ladder (candidates in priority order; a device that fails to
    /// open falls loudly to the next). For `say` every entry is PRIVATE.
    Devices(Vec<String>),
    /// Do NOT play — print the text instead (the `say` private fallback).
    Text(String),
}

impl Routed {
    pub fn describe(&self) -> String {
        match self {
            Routed::Reachy => "Reachy speaker (daemon)".to_string(),
            Routed::Devices(ladder) => {
                let (first, rest) = ladder.split_first().expect("ladder is never empty");
                if rest.is_empty() {
                    format!("{first} (native sink)")
                } else {
                    format!("{first} (native sink; fallbacks: {})", rest.join(" → "))
                }
            }
            Routed::Text(why) => format!("TEXT fallback — {why}"),
        }
    }
}

/// Resolve the PRIVATE `say` channel. This function bakes in the invariant:
/// the ladder it returns contains ONLY devices proven PRIVATE (the playback
/// sink re-asserts each name before sound as defense in depth). The only
/// non-private outcome is `Routed::Text` (silent, on-screen). There is
/// deliberately NO branch that ladders a speaker — not even as a fallback.
pub fn route_say(prefs: &[String], devices: &[AudioDevice]) -> Routed {
    let mut ladder: Vec<String> = Vec::new();
    for pat in prefs {
        for dev in connected_matches(pat, devices) {
            if dev.class() == DeviceClass::Private && !ladder.contains(&dev.name) {
                ladder.push(dev.name.clone());
            }
            // matched a non-private device: skip it — never play here.
        }
    }
    if ladder.is_empty() {
        Routed::Text("no connected private (in-ear/headphone) device".into())
    } else {
        Routed::Devices(ladder)
    }
}

/// Resolve the PUBLIC `shout` channel — broadcasting is the point, so it
/// builds the whole audible ladder: every connected policy match in priority
/// order, with the default output appended as the last resort. Reachy
/// short-circuits when it is the FIRST connected match and the daemon is up
/// (its sink is the whole-file daemon upload, not the streaming device sink);
/// when the daemon is down it is skipped and the ladder keeps going.
pub fn route_shout(prefs: &[String], devices: &[AudioDevice], daemon_up: bool) -> Routed {
    let mut ladder: Vec<String> = Vec::new();
    for pat in prefs {
        for dev in connected_matches(pat, devices) {
            match dev.class() {
                DeviceClass::Reachy if daemon_up && ladder.is_empty() => return Routed::Reachy,
                // Reachy below a local device (or daemon down): not a
                // streaming-sink candidate — keep walking the ladder.
                DeviceClass::Reachy => continue,
                _ => {
                    if !ladder.contains(&dev.name) {
                        ladder.push(dev.name.clone());
                    }
                }
            }
        }
    }
    // Last resort: the default output (audible), even if no policy entry matched.
    if let Some(default) = devices.iter().find(|d| d.is_default_output) {
        if !ladder.contains(&default.name) {
            ladder.push(default.name.clone());
        }
    }
    if ladder.is_empty() {
        Routed::Text("no audible output device connected".into())
    } else {
        Routed::Devices(ladder)
    }
}
