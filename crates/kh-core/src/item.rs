// crates/kh-vault/src/item.rs
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A secret string: wiped from memory when dropped, and printed as "[hidden]",
/// so it cannot reach a log, an error message or an audit entry by accident.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    /// The only way to read the value; easy to search for in code review.
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[hidden]")
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Match {
    #[default]
    Site, // same registrable domain, private suffixes such as github.io included
    Host,  // exact hostname
    Exact, // same origin: scheme, host and port
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SiteRule {
    pub url: String,
    #[serde(default, rename = "match")]
    pub matching: Match,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ask {
    Never,
    Ask,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AiPolicy {
    pub visible: bool, // false: the item does not exist for AI clients
    pub fill: Ask,
    pub totp: Ask,
    pub reveal: Ask,
}
impl Default for AiPolicy {
    fn default() -> Self {
        Self { visible: false, fill: Ask::Ask, totp: Ask::Never, reveal: Ask::Never }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Creator {
    #[default]
    You,
    Ai, // shown with a "created by AI, review it" badge until you open and confirm it
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OldPassword {
    pub password: Secret,
    pub changed_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ItemPayload {
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub ai: AiPolicy,
    #[serde(default)]
    pub created_by: Creator,
    #[serde(flatten)]
    pub kind: Kind,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Kind {
    Login {
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<Secret>,
        #[serde(default)]
        sites: Vec<SiteRule>,
        #[serde(default)]
        totp: Option<Secret>, // an otpauth:// URI
        #[serde(default)]
        history: Vec<OldPassword>,
    },
    ApiKey {
        key: Secret,
        #[serde(default)]
        service: Option<String>,
    },
    Note {},
    // Stored from day one so the format never has to change; passkey sign-in ships after 1.0.
    Passkey {
        rp_id: String,
        credential_id: String,
        user_handle: String,
        private_key: Secret,
        sign_count: u32,
    },
}

impl ItemPayload {
    pub fn validate(&self) -> Result<(), &'static str> {
        let len = self.title.chars().count();
        if len == 0 || len > 200 {
            return Err("title must be 1 to 200 characters");
        }
        if self.tags.len() > 30 || self.notes.as_ref().is_some_and(|n| n.len() > 20_000) {
            return Err("too many tags or notes too long");
        }
        if let Kind::Login { sites, history, .. } = &self.kind {
            if sites.len() > 20 || history.len() > 20 {
                return Err("too many sites or history entries");
            }
            if sites.iter().any(|s| !s.url.starts_with("https://")) {
                return Err("saved sites must use https");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_wire_shape() {
        let item: ItemPayload =
            serde_json::from_str(r#"{"type":"login","title":"GitHub","sites":[{"url":"https://github.com"}]}"#).unwrap();
        assert!(item.validate().is_ok());
        assert_eq!(item.ai, AiPolicy { visible: false, fill: Ask::Ask, totp: Ask::Never, reveal: Ask::Never });
        assert_eq!(item.created_by, Creator::You);
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["type"], "login"); // flat shape: the type tag sits beside the title
        assert_eq!(json["sites"][0]["match"], "site");
    }

    #[test]
    fn secrets_never_print() {
        let item: ItemPayload = serde_json::from_str(
            r#"{"type":"login","title":"Bank","password":"CANARY-7f3a9c","totp":"otpauth://totp/x?secret=CANARY-7f3a9c"}"#,
        )
        .unwrap();
        assert!(!format!("{item:?}").contains("CANARY"));
        assert!(format!("{item:?}").contains("[hidden]"));
        let Kind::Login { password: Some(p), .. } = &item.kind else { panic!() };
        assert_eq!(p.expose(), "CANARY-7f3a9c");
    }

    #[test]
    fn http_sites_and_unknown_types_are_rejected() {
        let http: ItemPayload =
            serde_json::from_str(r#"{"type":"login","title":"x","sites":[{"url":"http://github.com"}]}"#).unwrap();
        assert!(http.validate().is_err());
        assert!(serde_json::from_str::<ItemPayload>(r#"{"type":"mystery","title":"x"}"#).is_err());
        assert!(serde_json::from_str::<ItemPayload>(r#"{"type":"passkey","title":"x","rp_id":"github.com","credential_id":"a","user_handle":"b","private_key":"k","sign_count":0}"#).is_ok());
    }
}
