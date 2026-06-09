use agentguard_ipc::IpcClient;
use agentguard_core::GuardResult;

pub async fn status(standard: Option<String>) -> GuardResult<()> {
    let client = IpcClient::new();
    let std = standard.unwrap_or_else(|| "eu-ai-act".to_string());
    let result = client.get_compliance_status(std).await?;

    println!("\n  === Compliance Status: {} ===\n", result.standard);
    println!("  Overall   : {}", status_icon(&result.overall_status));
    println!("  Articles  : {}", result.articles_count);
    println!("  Controls  : {} implemented, {} partial, {} missing",
        result.controls_implemented, result.controls_partial, result.controls_missing);

    if !result.gaps.is_empty() {
        println!("\n  --- GAPS ---");
        for gap in &result.gaps {
            println!("  [{}] {}: {}", gap.severity, gap.control_id, gap.description);
            println!("    Fix: {}", gap.remediation);
        }
    }
    println!();
    Ok(())
}

pub async fn evaluate(standard: Option<String>) -> GuardResult<()> {
    let engine = agentguard_compliance::ComplianceEngine::new();
    let std = standard.unwrap_or_else(|| "eu-ai-act".to_string());
    let report = engine.evaluate(&std);

    println!("\n  === {} v{} ===\n", report.standard, report.standard_version);
    for article in &report.articles {
        let icon = if article.controls_missing > 0 { "❌" }
            else if article.controls_partial > 0 { "⚠️" }
            else { "✅" };
        println!("  {} {} — {}", icon, article.article, article.title);
        println!("     Controls: {}/{} implemented ({} partial, {} missing)",
            article.controls_implemented, article.controls_total,
            article.controls_partial, article.controls_missing);
        for gap in &article.gaps {
            println!("       • {}", gap);
        }
    }
    println!();
    Ok(())
}

pub async fn generate(standard: Option<String>, format: Option<String>, output: Option<String>) -> GuardResult<()> {
    let client = IpcClient::new();
    let std = standard.unwrap_or_else(|| "eu-ai-act".to_string());
    let fmt = format.unwrap_or_else(|| "json".to_string());
    let result = client.get_compliance_report(std, fmt).await?;

    let out_path = output.unwrap_or_else(|| format!("phylax_compliance_{}.json", result.standard.replace(' ', "_").to_lowercase()));
    std::fs::write(&out_path, &result.report_json)
        .map_err(|e| agentguard_core::GuardError::IpcError(format!("Failed to write report: {e}")))?;
    println!("  + Report generated: {}", out_path);
    println!("    Standard: {}", result.standard);
    println!("    Status: {}", result.overall_status);
    Ok(())
}

pub async fn check_gaps(standard: Option<String>) -> GuardResult<()> {
    let client = IpcClient::new();
    let std = standard.unwrap_or_else(|| "eu-ai-act".to_string());
    let result = client.get_compliance_status(std).await?;

    if result.gaps.is_empty() {
        println!("  ✅ No compliance gaps found!");
    } else {
        println!("\n  Found {} compliance gaps:\n", result.gaps.len());
        for gap in &result.gaps {
            println!("  [{}] Art. {} — {}", gap.severity, gap.article, gap.description);
            println!("     Remediation: {}", gap.remediation);
            println!();
        }
    }
    Ok(())
}

pub fn list_standards() {
    println!("\n  Available compliance standards:\n");
    for s in agentguard_compliance::ComplianceEngine::list_standards() {
        println!("  {} — {}", s.id, s.name);
        println!("    {}", s.description);
        println!();
    }
}

fn status_icon(s: &str) -> String {
    match s {
        "implemented" => "✅ COMPLIANT".to_string(),
        "partial" => "⚠️  PARTIAL".to_string(),
        _ => format!("{} ({})", s, s),
    }
}
