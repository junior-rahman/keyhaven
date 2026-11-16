// crates/kh-vault/src/policy.rs
use crate::item::{Ask, ItemPayload};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Search,
    ReadMeta,
    Create,
    Update,
    Fill,
    Totp,
    Reveal, // also covers copying a secret to the clipboard
}

/// What must happen before the action runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Open,     // nothing more
    Presence, // an approval prompt plus Windows Hello, both run by the core itself
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deny {
    Locked,
    Scope,
    AiOff,
    NotFound,
    Policy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caller {
    Owner,                                                    // a click inside the Keyhaven window
    Extension,                                                // your click in the paired browser extension
    Cli { console_grant: bool }, // `kh` in a terminal; a grant covers one console and expires
    Ai { read: bool, write: bool, fill: bool, reveal: bool }, // a paired MCP client and its scopes
}

pub struct Settings {
    pub locked: bool,
    pub strict: bool, // Strict protection: Windows Hello for every secret, even your own clicks
    pub ai_enabled: bool,
    pub ai_reveal_enabled: bool,
}

pub fn decide(caller: Caller, item: Option<&ItemPayload>, action: Action, s: &Settings) -> Result<Gate, Deny> {
    use Action::*;
    if s.locked {
        return Err(Deny::Locked);
    }
    let releases_secret = matches!(action, Fill | Totp | Reveal);
    match caller {
        // You, in the app or the extension: free in Standard mode, behind Windows Hello in Strict mode.
        Caller::Owner | Caller::Extension => Ok(if releases_secret && s.strict { Gate::Presence } else { Gate::Open }),

        // A terminal is not proof that it is you: an AI agent with a shell can run `kh` as well.
        Caller::Cli { console_grant } => {
            Ok(if releases_secret || !console_grant { Gate::Presence } else { Gate::Open })
        }

        Caller::Ai { read, write, fill, reveal } => {
            if !s.ai_enabled {
                return Err(Deny::AiOff);
            }
            let in_scope = match action {
                Search | ReadMeta => read,
                Create | Update => write,
                Fill | Totp => fill,
                Reveal => reveal,
            };
            if !in_scope {
                return Err(Deny::Scope);
            }
            if item.is_some_and(|i| !i.ai.visible) {
                return Err(Deny::NotFound); // invisible means nonexistent
            }
            let if_item_allows = |allowed: bool| if allowed { Ok(Gate::Presence) } else { Err(Deny::Policy) };
            match action {
                Search | ReadMeta | Create => Ok(Gate::Open), // creates are rate-limited by the core
                Update => Ok(Gate::Presence),
                Fill => if_item_allows(item.is_some_and(|i| i.ai.fill == Ask::Ask)),
                Totp => if_item_allows(item.is_some_and(|i| i.ai.totp == Ask::Ask)),
                Reveal => if_item_allows(s.ai_reveal_enabled && item.is_some_and(|i| i.ai.reveal == Ask::Ask)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Action::*;

    const AI: Caller = Caller::Ai { read: true, write: true, fill: true, reveal: true };
    const STD: Settings = Settings { locked: false, strict: false, ai_enabled: true, ai_reveal_enabled: false };

    fn item(json: &str) -> ItemPayload {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn decision_table() {
        let bank = item(r#"{"type":"login","title":"Chase","password":"x"}"#); // not visible to AI
        let gh = item(r#"{"type":"login","title":"GitHub","password":"x","ai":{"visible":true}}"#);
        let open_all = item(r#"{"type":"login","title":"Lab","ai":{"visible":true,"totp":"ask","reveal":"ask"}}"#);
        let strict = Settings { strict: true, ..STD };
        let reveal_on = Settings { ai_reveal_enabled: true, ..STD };
        let ai_off = Settings { ai_enabled: false, ..STD };
        let locked = Settings { locked: true, ..STD };
        let cli = Caller::Cli { console_grant: false };
        let cli_granted = Caller::Cli { console_grant: true };
        let read_only = Caller::Ai { read: true, write: false, fill: false, reveal: false };

        let cases: &[(Caller, Option<&ItemPayload>, Action, &Settings, Result<Gate, Deny>)] = &[
            // AI clients
            (AI, None, Search, &STD, Ok(Gate::Open)),
            (AI, Some(&bank), ReadMeta, &STD, Err(Deny::NotFound)),
            (AI, Some(&bank), Fill, &STD, Err(Deny::NotFound)),
            (AI, Some(&gh), ReadMeta, &STD, Ok(Gate::Open)),
            (AI, Some(&gh), Fill, &STD, Ok(Gate::Presence)),
            (AI, Some(&gh), Totp, &STD, Err(Deny::Policy)),
            (AI, Some(&gh), Reveal, &reveal_on, Err(Deny::Policy)),
            (AI, Some(&open_all), Totp, &STD, Ok(Gate::Presence)),
            (AI, Some(&open_all), Reveal, &STD, Err(Deny::Policy)), // global switch still off
            (AI, Some(&open_all), Reveal, &reveal_on, Ok(Gate::Presence)),
            (AI, Some(&gh), Update, &STD, Ok(Gate::Presence)),
            (AI, None, Create, &STD, Ok(Gate::Open)),
            (AI, None, Search, &ai_off, Err(Deny::AiOff)),
            (read_only, Some(&gh), Fill, &STD, Err(Deny::Scope)),
            (read_only, None, Create, &STD, Err(Deny::Scope)),
            // the terminal: never a free pass to a secret
            (cli, None, Search, &STD, Ok(Gate::Presence)),
            (cli_granted, None, Search, &STD, Ok(Gate::Open)),
            (cli_granted, Some(&bank), Reveal, &STD, Ok(Gate::Presence)),
            (cli_granted, Some(&bank), Totp, &STD, Ok(Gate::Presence)),
            // you
            (Caller::Owner, Some(&bank), Reveal, &STD, Ok(Gate::Open)),
            (Caller::Owner, Some(&bank), Reveal, &strict, Ok(Gate::Presence)),
            (Caller::Extension, Some(&bank), Fill, &STD, Ok(Gate::Open)),
            (Caller::Extension, Some(&bank), Fill, &strict, Ok(Gate::Presence)),
            (Caller::Owner, Some(&bank), Update, &strict, Ok(Gate::Open)),
            // locked beats everything
            (Caller::Owner, Some(&bank), ReadMeta, &locked, Err(Deny::Locked)),
            (AI, None, Search, &locked, Err(Deny::Locked)),
        ];
        for (i, (caller, it, action, s, want)) in cases.iter().enumerate() {
            assert_eq!(decide(*caller, *it, *action, s), *want, "case {i}: {caller:?} {action:?}");
        }
    }

    #[test]
    fn no_ai_or_cli_path_reaches_a_secret_without_presence() {
        let all_open =
            item(r#"{"type":"login","title":"x","ai":{"visible":true,"fill":"ask","totp":"ask","reveal":"ask"}}"#);
        for strict in [false, true] {
            for ai_reveal_enabled in [false, true] {
                let s = Settings { locked: false, strict, ai_enabled: true, ai_reveal_enabled };
                for caller in [AI, Caller::Cli { console_grant: true }, Caller::Cli { console_grant: false }] {
                    for action in [Fill, Totp, Reveal] {
                        assert_ne!(
                            decide(caller, Some(&all_open), action, &s),
                            Ok(Gate::Open),
                            "{caller:?} {action:?}"
                        );
                    }
                }
            }
        }
    }
}
