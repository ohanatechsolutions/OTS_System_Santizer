using System.Text;

namespace OTSSystemSanitizer.Core;

/// <summary>Evidence-led explanation, not a signature-backed or behavioral malware verdict.</summary>
public static class ThreatInvestigator
{
    public static string Explain(ThreatFinding finding)
    {
        var evidence = finding.Evidence ?? "";
        string explanation;
        if (evidence.Contains("double extension", StringComparison.OrdinalIgnoreCase))
            explanation = "The filename disguises an executable behind a document/image-like extension. " +
                "Windows uses the final extension. This can be abused, but installers and test fixtures can also do it.";
        else if (evidence.Contains("temporary directory", StringComparison.OrdinalIgnoreCase))
            explanation = "The executable or script is in a writable temporary directory. Malware can run there, " +
                "but normal installers, updates and tools do too.";
        else if (finding.Source.Contains("Defender", StringComparison.OrdinalIgnoreCase))
            explanation = "This is a Microsoft Defender historical detection record. The issue may already be resolved. " +
                "Review Windows Security / Protection history.";
        else
            explanation = "A local heuristic or persistence metadata check highlighted this entry. " +
                "The recorded details are why it was selected, but do not prove malware.";

        var sb = new StringBuilder();
        sb.AppendLine("FINDING: " + finding.Title);
        sb.AppendLine("Priority: " + finding.Level + " (not a confirmed infection)");
        sb.AppendLine("Source: " + finding.Source);
        sb.AppendLine("Location: " + finding.Path);
        sb.AppendLine("Observed: " + finding.ObservedAt.ToLocalTime().ToString("G"));
        sb.AppendLine();
        sb.AppendLine("WHY IT WAS FLAGGED");
        sb.AppendLine(explanation);
        sb.AppendLine();
        sb.AppendLine("RECORDED EVIDENCE");
        sb.AppendLine(evidence);
        sb.AppendLine();
        sb.AppendLine("WHAT IS NOT PROVEN");
        sb.AppendLine("No full behavioral sandbox, reputation verdict, comprehensive signature verification " +
                      "or memory forensics confirmed that this file is malicious.");
        sb.AppendLine();
        sb.AppendLine("DECISION GUIDE");
        sb.AppendLine("Review the original source and hash; check Windows Security. Restore trusted files. " +
                      "Destroy only if evidence supports irreversible removal.");
        return sb.ToString();
    }

    public static string QuarantineReport(QuarantinedFile item)
    {
        var sb = new StringBuilder();
        sb.AppendLine("QUARANTINE INVESTIGATION");
        sb.AppendLine("Original path: " + item.OriginalPath);
        sb.AppendLine("Quarantined: " + item.QuarantinedAt.ToLocalTime().ToString("G"));
        sb.AppendLine("SHA-256: " + item.Sha256);
        sb.AppendLine("Protection: AES-256-GCM with the Windows user's DPAPI-wrapped key.");
        sb.AppendLine("Limitation: quarantine is not kernel enforced and cannot stop running malware.");
        sb.AppendLine();
        sb.AppendLine(item.Investigation ?? "Legacy quarantine item: detector evidence was not saved. " +
            "Investigate its original path and hash independently; do not presume malware.");
        sb.AppendLine();
        sb.AppendLine("NEXT: Restore legitimate files or explicitly Destroy this reviewed encrypted vault copy.");
        sb.AppendLine("Destruction cannot guarantee forensic secure erasure.");
        return sb.ToString();
    }
}
