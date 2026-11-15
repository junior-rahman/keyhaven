// crates/kh-vault/src/sites.rs
use crate::item::{Match, SiteRule};
use url::Url;

/// Decides whether a saved login belongs to the page in a browser tab.
/// The tab URL comes from the browser, never from the page or the AI.
pub fn site_matches(rule: &SiteRule, tab_url: &str) -> bool {
    let (Ok(tab), Ok(saved)) = (Url::parse(tab_url), Url::parse(&rule.url)) else {
        return false;
    };
    if tab.scheme() != "https" || saved.scheme() != "https" {
        return false;
    }
    match rule.matching {
        Match::Exact => tab.origin() == saved.origin(),
        Match::Host => tab.host() == saved.host(),
        Match::Site => match (registrable(&tab), registrable(&saved)) {
            (Some(a), Some(b)) => a == b,
            _ => tab.host() == saved.host(), // IP addresses and bare names: the exact host only
        },
    }
}

/// The registrable domain from the Public Suffix List. The list's private section counts too,
/// so alice.github.io and mallory.github.io are different sites.
fn registrable(url: &Url) -> Option<&str> {
    psl::domain_str(url.domain()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(url: &str) -> SiteRule {
        SiteRule { url: url.into(), matching: Match::Site }
    }

    #[test]
    fn matching_rules() {
        // same site, subdomains included
        assert!(site_matches(&site("https://github.com"), "https://gist.github.com/login"));
        assert!(site_matches(&site("https://accounts.google.com"), "https://mail.google.com/"));
        // look-alikes and wrong schemes
        assert!(!site_matches(&site("https://github.com"), "https://github.com.evil.io/"));
        assert!(!site_matches(&site("https://github.com"), "https://g1thub.com/"));
        assert!(!site_matches(&site("https://github.com"), "http://github.com/"));
        assert!(!site_matches(&site("https://github.com"), "not a url"));
        // shared hosting: each customer subdomain is its own site
        assert!(!site_matches(&site("https://alice.github.io"), "https://mallory.github.io/login"));
        assert!(!site_matches(&site("https://myapp.vercel.app"), "https://evil.vercel.app/"));
        assert!(!site_matches(&site("https://shop.myshopify.com"), "https://other.myshopify.com/"));
        assert!(site_matches(&site("https://alice.github.io"), "https://alice.github.io/admin"));
        // multi-part public suffixes
        assert!(site_matches(&site("https://www.bbc.co.uk"), "https://account.bbc.co.uk/"));
        assert!(!site_matches(&site("https://www.bbc.co.uk"), "https://evil.co.uk/"));
        // IP addresses and bare host names fall back to the exact host
        assert!(site_matches(&site("https://192.168.1.1"), "https://192.168.1.1/admin"));
        assert!(!site_matches(&site("https://192.168.1.1"), "https://192.168.1.2/"));
        assert!(site_matches(&site("https://nas"), "https://nas/"));
        // internationalised names compare in their ASCII form
        assert!(site_matches(&site("https://bücher.example"), "https://xn--bcher-kva.example/"));
        // stricter modes
        let host = SiteRule { url: "https://secure.chase.com".into(), matching: Match::Host };
        assert!(site_matches(&host, "https://secure.chase.com/login"));
        assert!(!site_matches(&host, "https://promo.chase.com/"));
        let exact = SiteRule { url: "https://localhost:8443".into(), matching: Match::Exact };
        assert!(site_matches(&exact, "https://localhost:8443/x"));
        assert!(!site_matches(&exact, "https://localhost:9443/x"));
    }
}
