// apps/desktop/src-tauri/src/approvals.rs
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::{timeout, Instant};

#[derive(Clone, Debug)]
pub struct ApprovalRequest {
    pub action: &'static str,           // "fill", "totp", "reveal", "update", "cli", "pair"
    pub peer: String,                   // verified by Windows: program, signer, what launched it
    pub item_title: Option<String>,     // read from the vault, never from the caller
    pub target: Option<String>,         // the browser tab's real origin, or the field name
    pub reason_from_ai: Option<String>, // untrusted; shown as "from the AI, not verified"
}

impl ApprovalRequest {
    /// One line shown inside the Windows Hello dialog itself.
    pub fn summary(&self) -> String {
        let item = self.item_title.as_deref().unwrap_or("Keyhaven");
        match &self.target {
            Some(target) => format!("Approve {} of {} at {} for {}", self.action, item, target, self.peer),
            None => format!("Approve {} of {} for {}", self.action, item, self.peer),
        }
    }
}

/// The approval window. Resolves to true when you click Approve, false on Deny.
pub trait Prompt: Send + Sync {
    fn ask(&self, req: &ApprovalRequest) -> impl Future<Output = bool> + Send;
}

/// Windows Hello on the desktop, BiometricPrompt on Android. Always called by the core itself.
pub trait Presence: Send + Sync {
    fn verify(&self, message: &str) -> impl Future<Output = bool> + Send;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Approved,
    Denied,
    Expired,
    RateLimited,
}

pub struct Limits {
    pub max_pending: usize, // 3
    pub per_window: usize,  // 10
    pub window: Duration,   // 10 minutes
    pub ttl: Duration,      // 45 seconds
}

#[derive(Default)]
struct State {
    pending: usize,
    recent: VecDeque<Instant>,
}

pub struct ApprovalBroker<U: Prompt, P: Presence> {
    ui: U,
    presence: P,
    limits: Limits,
    state: Mutex<State>,
}

impl<U: Prompt, P: Presence> ApprovalBroker<U, P> {
    pub fn new(ui: U, presence: P, limits: Limits) -> Self {
        Self { ui, presence, limits, state: Mutex::new(State::default()) }
    }

    /// Approved only when you clicked Approve in the Keyhaven window and then passed Windows Hello.
    /// Both run inside this process, and no pipe method can settle an approval.
    pub async fn request(&self, req: ApprovalRequest) -> Outcome {
        if !self.admit() {
            return Outcome::RateLimited; // the caller also raises one "burst blocked" alert and logs it
        }
        let clicked = timeout(self.limits.ttl, self.ui.ask(&req)).await;
        self.state.lock().unwrap().pending -= 1;
        match clicked {
            Err(_) => Outcome::Expired,
            Ok(false) => Outcome::Denied,
            Ok(true) if self.presence.verify(&req.summary()).await => Outcome::Approved,
            Ok(true) => Outcome::Denied,
        }
    }

    fn admit(&self) -> bool {
        let mut s = self.state.lock().unwrap();
        let now = Instant::now();
        while s.recent.front().is_some_and(|t| now.duration_since(*t) > self.limits.window) {
            s.recent.pop_front();
        }
        if s.pending >= self.limits.max_pending || s.recent.len() >= self.limits.per_window {
            return false;
        }
        s.pending += 1;
        s.recent.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct Ui(Option<bool>); // None = nobody answers
    impl Prompt for Ui {
        async fn ask(&self, _req: &ApprovalRequest) -> bool {
            match self.0 {
                Some(answer) => answer,
                None => std::future::pending().await,
            }
        }
    }
    struct Hello(bool, Arc<AtomicUsize>);
    impl Presence for Hello {
        async fn verify(&self, _message: &str) -> bool {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0
        }
    }
    fn req() -> ApprovalRequest {
        ApprovalRequest { action: "fill", peer: "Claude (Anthropic, PBC)".into(), item_title: Some("GitHub".into()), target: Some("github.com".into()), reason_from_ai: None }
    }
    fn limits() -> Limits {
        Limits { max_pending: 3, per_window: 10, window: Duration::from_secs(600), ttl: Duration::from_secs(45) }
    }

    #[tokio::test(start_paused = true)]
    async fn approval_needs_the_click_and_the_gesture() {
        let hits = Arc::new(AtomicUsize::new(0));
        let both = ApprovalBroker::new(Ui(Some(true)), Hello(true, hits.clone()), limits());
        assert_eq!(both.request(req()).await, Outcome::Approved);

        let no_gesture = ApprovalBroker::new(Ui(Some(true)), Hello(false, hits.clone()), limits());
        assert_eq!(no_gesture.request(req()).await, Outcome::Denied);

        let before = hits.load(Ordering::SeqCst);
        let denied = ApprovalBroker::new(Ui(Some(false)), Hello(true, hits.clone()), limits());
        assert_eq!(denied.request(req()).await, Outcome::Denied);
        assert_eq!(hits.load(Ordering::SeqCst), before, "Hello is never shown after Deny");

        let ignored = ApprovalBroker::new(Ui(None), Hello(true, hits.clone()), limits());
        assert_eq!(ignored.request(req()).await, Outcome::Expired); // 45 s pass on the paused clock
        assert_eq!(req().summary(), "Approve fill of GitHub at github.com for Claude (Anthropic, PBC)");
    }

    #[tokio::test(start_paused = true)]
    async fn bursts_are_cut_off() {
        let broker = ApprovalBroker::new(Ui(Some(false)), Hello(true, Arc::new(AtomicUsize::new(0))), limits());
        for _ in 0..10 {
            assert_eq!(broker.request(req()).await, Outcome::Denied);
        }
        assert_eq!(broker.request(req()).await, Outcome::RateLimited); // the 11th inside ten minutes
        tokio::time::advance(Duration::from_secs(601)).await;
        assert_eq!(broker.request(req()).await, Outcome::Denied); // the window has moved on
    }
}
