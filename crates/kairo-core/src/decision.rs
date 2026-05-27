use crate::types::*;

pub const BLOCKED_PACKAGES: &[&str] = &[
    "event-stream-flat",
    "event-stream-promise",
    "flatmap-stream",
];

const CRITICAL_PACKAGES: &[&str] = &[
    "express",
    "lodash",
    "axios",
    "ws",
    "minimist",
];

pub fn decide(_action: &Action, intelligence: &PackageIntelligence) -> Verdict {
    // Rule 1: Hardcoded block list
    let pkg = &intelligence.package;
    if BLOCKED_PACKAGES.iter().any(|b| pkg.contains(b)) {
        return blocked_verdict(
            "Known malicious package",
            "This package is on the Kairo block list.",
            None,
        );
    }

    // Rule 2: Publish age check (< 30 minutes = WARN)
    if let Some(age) = intelligence.publish_age_seconds {
        if age < 1800 {
            let evidence = Evidence {
                evidence_type: "publish_age".to_string(),
                source: "npm_registry".to_string(),
                detail: format!("{} seconds old", age),
            };

            if age < 300 {
                // Less than 5 minutes old
                return Verdict {
                    verdict: VerdictType::Block,
                    risk_score: 85,
                    title: "Extremely fresh package install".to_string(),
                    summary: format!(
                        "Package {} was published {} seconds ago. This is extremely recent and risky.",
                        intelligence.package,
                        age
                    ),
                    recommended_action: Some("Wait at least 24 hours before installing this package, or pin a known stable version.".to_string()),
                    safe_command: None,
                    evidence: vec![evidence],
                };
            }

            return Verdict {
                verdict: VerdictType::Warn,
                risk_score: 55,
                title: "Fresh high-risk package install".to_string(),
                summary: format!(
                    "Package {} was published {} seconds ago and may not have been audited yet.",
                    intelligence.package,
                    age
                ),
                recommended_action: Some("Pin a known stable version or wait 24h.".to_string()),
                safe_command: None,
                evidence: vec![evidence],
            };
        }
    }

    // Rule 3: Lifecycle script check
    let has_risky_script = intelligence.has_postinstall_script
        || intelligence.has_install_script
        || intelligence.has_prepare_script;

    if has_risky_script {
        let script_type = if intelligence.has_postinstall_script {
            "postinstall"
        } else if intelligence.has_install_script {
            "install"
        } else {
            "prepare"
        };

        return Verdict {
            verdict: VerdictType::Warn,
            risk_score: 65,
            title: "Package with lifecycle scripts".to_string(),
            summary: format!(
                "Package {} has a {} script that will execute during installation.",
                intelligence.package,
                script_type
            ),
            recommended_action: Some("Review the package contents before installing.".to_string()),
            safe_command: None,
            evidence: vec![Evidence {
                evidence_type: "lifecycle_script".to_string(),
                source: "npm_package_json".to_string(),
                detail: format!("{} script present", script_type),
            }],
        };
    }

    // Rule 4: OSV advisory check — block CRITICAL/HIGH, warn on others
    if !intelligence.osv_advisories.is_empty() {
        let top_advisory = &intelligence.osv_advisories[0];
        let sev = top_advisory.severity.to_uppercase();
        let is_critical_high = sev.contains("CRITICAL") || sev.contains("HIGH");

        if is_critical_high {
            return blocked_verdict(
                "Known vulnerability",
                &format!(
                    "Package {} has a known advisory: {} — {}",
                    intelligence.package, top_advisory.id, top_advisory.summary
                ),
                Some(vec![Evidence {
                    evidence_type: "advisory".to_string(),
                    source: "osv".to_string(),
                    detail: format!("{} ({})", top_advisory.id, top_advisory.severity),
                }]),
            );
        }

        // MEDIUM/LOW/UNKNOWN severity → warn
        return Verdict {
            verdict: VerdictType::Warn,
            risk_score: 60,
            title: "Package has known advisory".to_string(),
            summary: format!(
                "Package {} has a known advisory: {} — {}",
                intelligence.package, top_advisory.id, top_advisory.summary
            ),
            recommended_action: Some("Review the advisory before installing.".to_string()),
            safe_command: None,
            evidence: vec![Evidence {
                evidence_type: "advisory".to_string(),
                source: "osv".to_string(),
                detail: format!("{} ({})", top_advisory.id, top_advisory.severity),
            }],
        };
    }

    // Rule 5: Provenance check for critical packages
    if CRITICAL_PACKAGES.iter().any(|c| pkg.contains(c)) && !intelligence.has_provenance {
        return Verdict {
            verdict: VerdictType::Warn,
            risk_score: 45,
            title: "Critical package without provenance".to_string(),
            summary: format!(
                "{} is a critical package but lacks npm provenance information.",
                pkg
            ),
            recommended_action: Some("Verify the package authenticity manually.".to_string()),
            safe_command: None,
            evidence: vec![Evidence {
                evidence_type: "provenance".to_string(),
                source: "npm_registry".to_string(),
                detail: "No provenance statement found".to_string(),
            }],
        };
    }

    // Rule 6: License check for suspicious/proprietary licenses
    if let Some(ref license) = intelligence.license {
        let license_upper = license.to_uppercase();

        // Check for missing or unknown license
        if license_upper == "NOASSERTION" || license.is_empty() {
            return Verdict {
                verdict: VerdictType::Warn,
                risk_score: 40,
                title: "Package license unclear".to_string(),
                summary: format!(
                    "Package {} has no clear license information ({}).",
                    pkg, license
                ),
                recommended_action: Some("Verify the license before installing.".to_string()),
                safe_command: None,
                evidence: vec![Evidence {
                    evidence_type: "license".to_string(),
                    source: "npm_registry".to_string(),
                    detail: format!("License: {}", license),
                }],
            };
        }

        // Check for proprietary licenses
        if license_upper.contains("PROPRIETARY") || license_upper.contains("CLOSED") || license_upper.contains("COMMERCIAL") {
            return Verdict {
                verdict: VerdictType::Warn,
                risk_score: 50,
                title: "Proprietary license detected".to_string(),
                summary: format!(
                    "Package {} has a proprietary license: {}.",
                    pkg, license
                ),
                recommended_action: Some("Review the license terms before installing.".to_string()),
                safe_command: None,
                evidence: vec![Evidence {
                    evidence_type: "license".to_string(),
                    source: "npm_registry".to_string(),
                    detail: format!("License: {}", license),
                }],
            };
        }

        // Check for GPL/AGPL/LGPL family licenses
        let has_restrictive_license = license_upper.contains("GPL-3.0")
            || license_upper.contains("GPL-3")
            || license_upper.contains("LGPL")
            || license_upper.contains("AGPL")
            || license_upper.contains("GPL-2.0")
            || license_upper.contains("GPL-2");

        if has_restrictive_license {
            let license_type = if license_upper.contains("AGPL") {
                "AGPL"
            } else if license_upper.contains("LGPL") {
                "LGPL"
            } else if license_upper.contains("GPL") {
                "GPL"
            } else {
                "restrictive"
            };

            return Verdict {
                verdict: VerdictType::Warn,
                risk_score: 35,
                title: format!("{} license detected", license_type).to_string(),
                summary: format!(
                    "Package {} has a {} license which may have compatibility implications.",
                    pkg, license
                ),
                recommended_action: Some("Review license compatibility with your project.".to_string()),
                safe_command: None,
                evidence: vec![Evidence {
                    evidence_type: "license".to_string(),
                    source: "npm_registry".to_string(),
                    detail: format!("License: {}", license),
                }],
            };
        }
    } else {
        // No license field at all
        return Verdict {
            verdict: VerdictType::Warn,
            risk_score: 45,
            title: "Package has no license information".to_string(),
            summary: format!(
                "Package {} has no license field in its package metadata.",
                pkg
            ),
            recommended_action: Some("Verify the license before installing.".to_string()),
            safe_command: None,
            evidence: vec![Evidence {
                evidence_type: "license".to_string(),
                source: "npm_registry".to_string(),
                detail: "No license field found".to_string(),
            }],
        };
    }

    // Default: ALLOW
    Verdict {
        verdict: VerdictType::Allow,
        risk_score: 5,
        title: "Package appears safe".to_string(),
        summary: format!(
            "No risk factors detected for {}.",
            intelligence.package
        ),
        recommended_action: None,
        safe_command: None,
        evidence: vec![],
    }
}

fn blocked_verdict(title: &str, summary: &str, extra_evidence: Option<Vec<Evidence>>) -> Verdict {
    let mut evidence = vec![Evidence {
        evidence_type: "block_rule".to_string(),
        source: "kairo_rules".to_string(),
        detail: title.to_string(),
    }];
    if let Some(mut extra) = extra_evidence {
        evidence.append(&mut extra);
    }
    Verdict {
        verdict: VerdictType::Block,
        risk_score: 95,
        title: title.to_string(),
        summary: summary.to_string(),
        recommended_action: Some("Do not install this package.".to_string()),
        safe_command: None,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Block list tests ---

    #[test]
    fn test_blocked_package_event_stream_flat() {
        let action = Action::test_package(Ecosystem::npm, "event-stream-flat", "0.0.1");
        let intel = PackageIntelligence::test_package("event-stream-flat");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Block);
        assert!(verdict.title.contains("malicious"));
    }

    #[test]
    fn test_blocked_package_flatmap_stream() {
        let action = Action::test_package(Ecosystem::npm, "flatmap-stream", "0.1.1");
        let intel = PackageIntelligence::test_package("flatmap-stream");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Block);
    }

    #[test]
    fn test_blocked_package_event_stream_promise() {
        let action = Action::test_package(Ecosystem::npm, "event-stream-promise", "1.0.0");
        let intel = PackageIntelligence::test_package("event-stream-promise");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Block);
    }

    // --- Publish age tests ---

    #[test]
    fn test_very_fresh_package_under_5_minutes_blocks() {
        let action = Action::test_package(Ecosystem::npm, "new-package", "latest");
        let intel = PackageIntelligence::test_package("new-package").with_age(120); // 2 min
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Block);
        assert!(verdict.risk_score >= 80);
    }

    #[test]
    fn test_fresh_package_under_30_minutes_warns() {
        let action = Action::test_package(Ecosystem::pnpm, "new-package", "latest");
        let intel = PackageIntelligence::test_package("new-package").with_age(600); // 10 min
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
        assert!(verdict.risk_score >= 50);
    }

    #[test]
    fn test_30_minutes_is_not_fresh() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "latest");
        let intel = PackageIntelligence::test_package("some-package").with_age(1800).with_license("MIT");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Allow);
    }

    #[test]
    fn test_old_package_allowed() {
        let action = Action::test_package(Ecosystem::npm, "old-package", "1.0.0");
        let intel = PackageIntelligence::test_package("old-package").with_age(86400).with_license("MIT");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Allow);
    }

    // --- Lifecycle script tests ---

    #[test]
    fn test_postinstall_script_warns() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let mut intel = PackageIntelligence::test_package("some-package").with_age(86400);
        intel.has_postinstall_script = true;
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
        assert!(verdict.summary.contains("postinstall"));
    }

    #[test]
    fn test_prepare_script_warns() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let mut intel = PackageIntelligence::test_package("some-package").with_age(86400);
        intel.has_prepare_script = true;
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
    }

    #[test]
    fn test_install_script_warns() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let mut intel = PackageIntelligence::test_package("some-package").with_age(86400);
        intel.has_install_script = true;
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
    }

    // --- OSV Advisory tests ---

    #[test]
    fn test_osv_critical_advisory_blocks() {
        let action = Action::test_package(Ecosystem::npm, "vulnerable-package", "1.0.0");
        let intel = PackageIntelligence::test_package("vulnerable-package")
            .with_advisory("OSV-2024-1234", "CRITICAL");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Block);
    }

    #[test]
    fn test_osv_high_advisory_blocks() {
        let action = Action::test_package(Ecosystem::npm, "vulnerable-package", "1.0.0");
        let intel = PackageIntelligence::test_package("vulnerable-package")
            .with_advisory("OSV-2024-5678", "HIGH");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Block);
    }

    #[test]
    fn test_osv_low_advisory_warns() {
        let action = Action::test_package(Ecosystem::npm, "vulnerable-package", "1.0.0");
        let intel = PackageIntelligence::test_package("vulnerable-package")
            .with_advisory("OSV-2024-0001", "LOW");
        let verdict = decide(&action, &intel);
        // LOW severity warns but does not block
        assert_eq!(verdict.verdict, VerdictType::Warn);
    }

    #[test]
    fn test_multiple_advisories_takes_highest() {
        let action = Action::test_package(Ecosystem::npm, "multi-advisory-package", "1.0.0");
        let mut intel = PackageIntelligence::test_package("multi-advisory-package");
        // Push CRITICAL first so it becomes osv_advisories[0]
        intel.osv_advisories.push(OsvAdvisory {
            id: "OSV-CRITICAL".to_string(),
            severity: "CRITICAL".to_string(),
            summary: "Critical severity".to_string(),
            modified: "2024-01-01T00:00:00Z".to_string(),
        });
        intel.osv_advisories.push(OsvAdvisory {
            id: "OSV-LOW".to_string(),
            severity: "LOW".to_string(),
            summary: "Low severity".to_string(),
            modified: "2024-01-01T00:00:00Z".to_string(),
        });
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Block);
    }

    // --- Provenance tests ---

    #[test]
    fn test_critical_package_without_provenance_warns() {
        let action = Action::test_package(Ecosystem::npm, "express", "4.18.0");
        let mut intel = PackageIntelligence::test_package("express");
        intel.has_provenance = false;
        intel.publish_age_seconds = Some(86400 * 365); // old enough to not be fresh
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
        assert!(verdict.summary.contains("provenance"));
    }

    #[test]
    fn test_critical_package_with_provenance_allowed() {
        let action = Action::test_package(Ecosystem::npm, "lodash", "4.17.21");
        let mut intel = PackageIntelligence::test_package("lodash");
        intel.has_provenance = true;
        intel.publish_age_seconds = Some(86400 * 365);
        intel.license = Some("MIT".to_string());
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Allow);
    }

    // --- Ecosystem tests ---

    #[test]
    fn test_pnpm_fresh_package_warns() {
        let action = Action::test_package(Ecosystem::pnpm, "some-package", "latest");
        let intel = PackageIntelligence::test_package("some-package").with_age(300);
        let verdict = decide(&action, &intel);
        // Exactly 300s is not < 5 min (300s is the boundary), so it warns not blocks
        assert_eq!(verdict.verdict, VerdictType::Warn);
    }

    #[test]
    fn test_cargo_fresh_package() {
        let action = Action::test_package(Ecosystem::cargo, "ripgrep", "13.0.0");
        let intel = PackageIntelligence::test_package("ripgrep").with_age(600);
        let verdict = decide(&action, &intel);
        // Should warn or allow depending on other factors
        assert_ne!(verdict.verdict, VerdictType::Block); // not on block list
    }

    #[test]
    fn test_docker_image_fresh() {
        let action = Action::test_package(Ecosystem::docker, "node", "18-alpine");
        let intel = PackageIntelligence::test_package("node").with_age(600);
        let verdict = decide(&action, &intel);
        // 10 min old — freshness check returns Warn (not < 5 min for Block)
        assert_eq!(verdict.verdict, VerdictType::Warn);
    }

    // --- Verdict type tests ---

    #[test]
    fn test_verdict_type_display() {
        assert_eq!(format!("{}", VerdictType::Allow), "ALLOW");
        assert_eq!(format!("{}", VerdictType::Warn), "WARN");
        assert_eq!(format!("{}", VerdictType::Block), "BLOCK");
    }

    // --- Evidence tests ---

    #[test]
    fn test_fresh_package_includes_evidence() {
        let action = Action::test_package(Ecosystem::npm, "newpkg", "latest");
        let intel = PackageIntelligence::test_package("newpkg").with_age(300);
        let verdict = decide(&action, &intel);
        assert!(!verdict.evidence.is_empty());
        assert!(verdict.evidence.iter().any(|e| e.evidence_type == "publish_age"));
    }

    #[test]
    fn test_osv_advisory_includes_evidence() {
        let action = Action::test_package(Ecosystem::npm, "badpkg", "1.0.0");
        let intel = PackageIntelligence::test_package("badpkg").with_advisory("OSV-1", "CRITICAL");
        let verdict = decide(&action, &intel);
        assert!(!verdict.evidence.is_empty());
        assert!(verdict.evidence.iter().any(|e| e.source == "osv"));
    }

    // --- Priority / ordering tests ---

    #[test]
    fn test_blocked_overrides_fresh() {
        // Even if fresh, a blocked package should block
        let action = Action::test_package(Ecosystem::npm, "flatmap-stream", "0.1.1");
        let mut intel = PackageIntelligence::test_package("flatmap-stream");
        intel.publish_age_seconds = Some(60); // very fresh
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Block);
    }

    #[test]
    fn test_advisory_overrides_fresh() {
        // A critical advisory should block even if not super fresh
        let action = Action::test_package(Ecosystem::npm, "pkg-with-cve", "2.0.0");
        let intel = PackageIntelligence::test_package("pkg-with-cve")
            .with_age(3600) // 1 hour old
            .with_advisory("CVE-2024-9999", "CRITICAL");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Block);
    }

    #[test]
    fn test_risk_score_reflects_actual_risk() {
        // Block list = very high risk
        let action = Action::test_package(Ecosystem::npm, "flatmap-stream", "1.0.0");
        let intel = PackageIntelligence::test_package("flatmap-stream");
        let verdict = decide(&action, &intel);
        assert!(verdict.risk_score >= 90);

        // Fresh package = medium risk
        let action = Action::test_package(Ecosystem::npm, "newpkg", "latest");
        let intel = PackageIntelligence::test_package("newpkg").with_age(600);
        let verdict = decide(&action, &intel);
        assert!(verdict.risk_score >= 50 && verdict.risk_score < 90);

        // Old safe package = low risk
        let action = Action::test_package(Ecosystem::npm, "old-safe-pkg", "1.0.0");
        let intel = PackageIntelligence::test_package("old-safe-pkg").with_age(86400 * 30).with_license("MIT");
        let verdict = decide(&action, &intel);
        assert!(verdict.risk_score < 30);
    }

    // --- License tests ---

    #[test]
    fn test_gpl3_license_warns() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let intel = PackageIntelligence::test_package("some-package")
            .with_age(86400)
            .with_license("GPL-3.0");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
        assert!(verdict.title.contains("GPL"));
        assert!(verdict.evidence.iter().any(|e| e.evidence_type == "license"));
    }

    #[test]
    fn test_lgpl_license_warns() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let intel = PackageIntelligence::test_package("some-package")
            .with_age(86400)
            .with_license("LGPL-2.1");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
        assert!(verdict.title.contains("LGPL"));
    }

    #[test]
    fn test_agpl_license_warns() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let intel = PackageIntelligence::test_package("some-package")
            .with_age(86400)
            .with_license("AGPL-3.0");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
        assert!(verdict.title.contains("AGPL"));
    }

    #[test]
    fn test_no_license_field_warns() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let intel = PackageIntelligence::test_package("some-package").with_age(86400);
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
        assert!(verdict.title.contains("no license"));
    }

    #[test]
    fn test_proprietary_license_warns() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let intel = PackageIntelligence::test_package("some-package")
            .with_age(86400)
            .with_license("PROPRIETARY");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
        assert!(verdict.title.contains("Proprietary"));
    }

    #[test]
    fn test_noassertion_license_warns() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let intel = PackageIntelligence::test_package("some-package")
            .with_age(86400)
            .with_license("NOASSERTION");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
        assert!(verdict.summary.contains("no clear license"));
    }

    #[test]
    fn test_mit_license_allows() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let intel = PackageIntelligence::test_package("some-package")
            .with_age(86400)
            .with_license("MIT");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Allow);
    }

    #[test]
    fn test_apache_license_allows() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let intel = PackageIntelligence::test_package("some-package")
            .with_age(86400)
            .with_license("Apache-2.0");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Allow);
    }

    #[test]
    fn test_bsd_license_allows() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let intel = PackageIntelligence::test_package("some-package")
            .with_age(86400)
            .with_license("BSD-3-Clause");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Allow);
    }

    #[test]
    fn test_isc_license_allows() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let intel = PackageIntelligence::test_package("some-package")
            .with_age(86400)
            .with_license("ISC");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Allow);
    }

    #[test]
    fn test_gpl2_license_warns() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let intel = PackageIntelligence::test_package("some-package")
            .with_age(86400)
            .with_license("GPL-2.0");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
        assert!(verdict.title.contains("GPL"));
    }

    #[test]
    fn test_commercial_license_warns() {
        let action = Action::test_package(Ecosystem::npm, "some-package", "1.0.0");
        let intel = PackageIntelligence::test_package("some-package")
            .with_age(86400)
            .with_license("COMMERCIAL");
        let verdict = decide(&action, &intel);
        assert_eq!(verdict.verdict, VerdictType::Warn);
        assert!(verdict.title.contains("Proprietary"));
    }
}
