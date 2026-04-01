use std::collections::HashSet;
use std::fs;

pub struct DomainList {
    domains: HashSet<String>,
}

impl DomainList {
    pub fn load(path: &str) -> Result<DomainList, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {}", path, e))?;

        let domains = content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.to_lowercase())
            .collect();

        Ok(DomainList { domains })
    }

    pub fn empty() -> DomainList {
        DomainList {
            domains: HashSet::new(),
        }
    }

    /// Suffix match: "cdn.instagram.com" matches entry "instagram.com"
    pub fn contains(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();

        if self.domains.contains(&domain) {
            return true;
        }

        let mut remaining = domain.as_str();
        loop {
            match remaining.find('.') {
                Some(pos) => {
                    remaining = &remaining[pos + 1..];
                    if self.domains.contains(remaining) {
                        return true;
                    }
                }
                None => return false,
            }
        }
    }

    pub fn len(&self) -> usize {
        self.domains.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_tunnel_list() {
        let list = DomainList::load("testdata/redirect.txt").unwrap();
        assert_eq!(list.len(), 4);
    }

    #[test]
    fn exact_match() {
        let list = DomainList::load("testdata/redirect.txt").unwrap();
        assert!(list.contains("instagram.com"));
        assert!(list.contains("twitter.com"));
        assert!(!list.contains("youtube.com"));
    }

    #[test]
    fn suffix_match() {
        let list = DomainList::load("testdata/redirect.txt").unwrap();
        assert!(list.contains("cdn.instagram.com"));
        assert!(list.contains("edge-chat.instagram.com"));
        assert!(!list.contains("scontent-ams2-1.cdninstagram.com"));
    }

    #[test]
    fn case_insensitive() {
        let list = DomainList::load("testdata/redirect.txt").unwrap();
        assert!(list.contains("Instagram.COM"));
        assert!(list.contains("CDN.INSTAGRAM.COM"));
    }

    #[test]
    fn comments_and_blanks_ignored() {
        let list = DomainList::load("testdata/redirect.txt").unwrap();
        assert_eq!(list.len(), 4);
    }

    #[test]
    fn empty_list() {
        let list = DomainList::empty();
        assert!(!list.contains("anything.com"));
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn load_nonexistent_file() {
        let result = DomainList::load("/nonexistent/path.txt");
        assert!(result.is_err());
    }
}
