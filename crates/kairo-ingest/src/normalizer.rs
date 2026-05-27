use crate::sources::RawAdvisory;
use kairo_core::{Ecosystem, OsvAdvisory};

pub fn normalize_to_osv(advisory: &RawAdvisory) -> OsvAdvisory {
    let severity = advisory.severity.clone().unwrap_or_else(|| {
        match advisory.severity.as_deref() {
            Some("CRITICAL") | Some("critical") => "CRITICAL".to_string(),
            Some("HIGH") | Some("high") => "HIGH".to_string(),
            Some("MEDIUM") | Some("medium") | Some("MODERATE") | Some("moderate") => "MEDIUM".to_string(),
            Some("LOW") | Some("low") => "LOW".to_string(),
            Some("UNKNOWN") | Some("unknown") | None => "UNKNOWN".to_string(),
            _ => "UNKNOWN".to_string(),
        }
    });

    OsvAdvisory {
        id: advisory.id.clone(),
        severity,
        summary: advisory.summary.clone(),
        modified: advisory.modified.clone(),
    }
}

pub fn ecosystem_to_str(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::npm | Ecosystem::pnpm | Ecosystem::yarn | Ecosystem::bun => "npm",
        Ecosystem::pip => "pip",
        Ecosystem::cargo => "crates.io",
        Ecosystem::go => "go",
        Ecosystem::docker => "docker",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_normalization() {
        let advisory = RawAdvisory {
            source: "osv".to_string(),
            id: "TEST-001".to_string(),
            package: "test-package".to_string(),
            ecosystem: "npm".to_string(),
            severity: Some("CRITICAL".to_string()),
            summary: "Test advisory".to_string(),
            details: None,
            references: vec![],
            modified: "2024-01-01T00:00:00Z".to_string(),
            published: None,
            withdrawn: None,
            vulnerable_versions: None,
        };

        let osv = normalize_to_osv(&advisory);
        assert_eq!(osv.severity, "CRITICAL");
    }
}
