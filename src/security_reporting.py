
"""Security reporting and audit logging utilities for the cipher toolkit.

The module is intentionally independent of the CLI/GUI so it can be reused
by both interfaces without changing the cryptanalysis algorithms.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
import html
import json


# Always save relative report paths beside this module (normally src/reports),
# not relative to the directory from which Python/VS Code was launched.
MODULE_DIR = Path(__file__).resolve().parent
REPORT_DIR = MODULE_DIR / "reports"


def _resolve_output_path(output_path: str | Path) -> Path:
    """Resolve report paths consistently.

    Absolute paths are preserved. Relative paths are resolved relative to
    this module's directory, so reports/example.html is saved inside the
    project's src/reports directory even when launched from another folder.
    """
    path = Path(output_path).expanduser()

    if not path.is_absolute():
        path = MODULE_DIR / path

    path.parent.mkdir(parents=True, exist_ok=True)
    return path.resolve()


@dataclass
class AuditEvent:
    """One non-sensitive event in an analysis session."""

    timestamp: str
    event: str
    details: str = ""
    status: str = "INFO"


class AuditLogger:
    """Collect analysis events and optionally save them as JSON."""

    def __init__(self) -> None:
        self.events: List[AuditEvent] = []

    def log(
        self,
        event: str,
        details: str = "",
        status: str = "INFO",
    ) -> None:
        self.events.append(
            AuditEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event=event,
                details=details,
                status=status.upper(),
            )
        )

    def to_dict(self) -> List[Dict[str, str]]:
        return [asdict(event) for event in self.events]

    def save_json(self, output_path: str | Path) -> Path:
        path = _resolve_output_path(output_path)
        path.write_text(
            json.dumps(self.to_dict(), indent=4),
            encoding="utf-8",
        )
        return path


class SecurityReport:
    """Create JSON, text, and HTML reports from an analysis result."""

    def __init__(
        self,
        *,
        operation: str,
        cipher_type: str,
        ciphertext_length: int,
        letter_count: int,
        result: Optional[Dict[str, Any]] = None,
        findings: Optional[Iterable[str]] = None,
        limitations: Optional[Iterable[str]] = None,
        audit_events: Optional[Iterable[Dict[str, Any]]] = None,
        configuration: Optional[Dict[str, Any]] = None,
        security_assessment: str = "Not assessed",
        strength_rating: str = "Not assessed",
        keyspace: str = "Not assessed",
        brute_force_resistance: str = "Not assessed",
        analysis_confidence: str = "Not assessed",
        assessment_basis: str = "Not assessed",
    ) -> None:
        self.operation = operation
        self.cipher_type = cipher_type
        self.ciphertext_length = ciphertext_length
        self.letter_count = letter_count
        self.result = dict(result or {})
        self.findings = list(findings or [])
        self.limitations = list(limitations or [])
        self.audit_events = list(audit_events or [])
        self.configuration = dict(configuration or {})
        self.security_assessment = security_assessment
        self.strength_rating = strength_rating

        cipher_upper = cipher_type.upper()

        if keyspace == "Not assessed":
            keyspace = (
                "26 possible shifts"
                if cipher_upper == "CAESAR"
                else (
                    "26^k possible keys (k = key length)"
                    if cipher_upper == "VIGENERE"
                    else "Depends on algorithm"
                )
            )

        if brute_force_resistance == "Not assessed":
            brute_force_resistance = (
                "Very Low"
                if cipher_upper == "CAESAR"
                else (
                    "Low to Moderate; depends on key length and key reuse"
                    if cipher_upper == "VIGENERE"
                    else "Not assessed"
                )
            )

        if analysis_confidence == "Not assessed":
            analysis_confidence = (
                "Low"
                if self.letter_count < 50
                else ("Moderate" if self.letter_count < 150 else "Higher")
            )

        if assessment_basis == "Not assessed":
            assessment_basis = (
                f"{self.letter_count} alphabetic characters; "
                "algorithm-level weakness and sample length considered"
            )

        self.keyspace = keyspace
        self.brute_force_resistance = brute_force_resistance
        self.analysis_confidence = analysis_confidence
        self.assessment_basis = assessment_basis
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_metadata": {
                "generated_at": self.generated_at,
                "operation": self.operation,
                "cipher_type": self.cipher_type,
            },
            "input_summary": {
                "ciphertext_length": self.ciphertext_length,
                "alphabetic_character_count": self.letter_count,
            },
            "analysis_configuration": self.configuration,
            "analysis_result": self.result,
            "security_assessment": self.security_assessment,
            "ciphertext_strength": self.strength_rating,
            "security_metrics": {
                "keyspace": self.keyspace,
                "brute_force_resistance": self.brute_force_resistance,
                "analysis_confidence": self.analysis_confidence,
                "assessment_basis": self.assessment_basis,
            },
            "security_findings": self.findings,
            "limitations": self.limitations,
            "audit_events": self.audit_events,
        }

    def save_json(self, output_path: str | Path) -> Path:
        path = _resolve_output_path(output_path)
        path.write_text(
            json.dumps(self.to_dict(), indent=4, ensure_ascii=False),
            encoding="utf-8",
        )
        return path

    def to_text(self) -> str:
        data = self.to_dict()

        lines = [
            "CLASSICAL CIPHER SECURITY ANALYSIS REPORT",
            "=" * 48,
            f"Generated At: {data['report_metadata']['generated_at']}",
            f"Operation: {data['report_metadata']['operation']}",
            f"Cipher Type: {data['report_metadata']['cipher_type']}",
            "",
            "INPUT SUMMARY",
            "-" * 20,
            f"Ciphertext Length: {data['input_summary']['ciphertext_length']}",
            (
                "Alphabetic Characters: "
                f"{data['input_summary']['alphabetic_character_count']}"
            ),
            "",
            "ANALYSIS CONFIGURATION",
            "-" * 28,
        ]

        for key, value in self.configuration.items():
            lines.append(f"{key}: {value}")

        lines.extend(["", "ANALYSIS RESULT", "-" * 20])

        for key, value in self.result.items():
            lines.append(f"{key}: {value}")

        lines.extend(
            [
                "",
                "SECURITY ASSESSMENT",
                "-" * 20,
                self.security_assessment,
                f"Ciphertext Strength: {self.strength_rating}",
                f"Keyspace: {self.keyspace}",
                f"Brute-Force Resistance: {self.brute_force_resistance}",
                f"Analysis Confidence: {self.analysis_confidence}",
                f"Assessment Basis: {self.assessment_basis}",
            ]
        )

        lines.extend(["", "SECURITY FINDINGS", "-" * 20])
        lines.extend(f"- {item}" for item in self.findings)

        lines.extend(["", "LIMITATIONS", "-" * 20])
        lines.extend(f"- {item}" for item in self.limitations)

        lines.extend(["", "AUDIT EVENTS", "-" * 20])

        for event in self.audit_events:
            lines.append(
                f"[{event.get('timestamp', 'N/A')}] "
                f"{event.get('status', 'INFO')} - "
                f"{event.get('event', 'Unknown event')}: "
                f"{event.get('details', '')}"
            )

        return "\n".join(lines) + "\n"

    def save_text(self, output_path: str | Path) -> Path:
        path = _resolve_output_path(output_path)
        path.write_text(self.to_text(), encoding="utf-8")
        return path

    def to_html(self) -> str:
        data = self.to_dict()

        def esc(value: Any) -> str:
            return html.escape(str(value))

        result_rows = "".join(
            f"<tr><th>{esc(key)}</th><td>{esc(value)}</td></tr>"
            for key, value in self.result.items()
        )

        finding_rows = "".join(
            f"<li>{esc(item)}</li>" for item in self.findings
        ) or "<li>No findings recorded.</li>"

        limitation_rows = "".join(
            f"<li>{esc(item)}</li>" for item in self.limitations
        ) or "<li>No limitations recorded.</li>"

        audit_rows = "".join(
            "<tr>"
            f"<td>{esc(event.get('timestamp', 'N/A'))}</td>"
            f"<td>{esc(event.get('event', ''))}</td>"
            f"<td>{esc(event.get('details', ''))}</td>"
            f"<td>{esc(event.get('status', 'INFO'))}</td>"
            "</tr>"
            for event in self.audit_events
        ) or "<tr><td colspan='4'>No audit events recorded.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Analysis Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 36px; color: #1f2937; line-height: 1.5; }}
h1 {{ color: #173f5f; text-align: center; }}
h2 {{ color: #173f5f; border-bottom: 2px solid #173f5f; padding-bottom: 5px; margin-top: 28px; }}
table {{ width: 100%; border-collapse: collapse; margin: 14px 0 24px; }}
th, td {{ border: 1px solid #b8c2cc; padding: 9px; text-align: left; vertical-align: top; }}
th {{ background: #eaf1f7; }}
li {{ margin: 6px 0; }}
.note {{ background: #fff6d8; border-left: 5px solid #d6a100; padding: 12px; }}
</style>
</head>
<body>
<h1>Classical Cipher Security Analysis Report</h1>

<table>
<tr><th>Generated At</th><td>{esc(data['report_metadata']['generated_at'])}</td></tr>
<tr><th>Operation</th><td>{esc(data['report_metadata']['operation'])}</td></tr>
<tr><th>Cipher Type</th><td>{esc(data['report_metadata']['cipher_type'])}</td></tr>
<tr><th>Ciphertext Length</th><td>{esc(data['input_summary']['ciphertext_length'])}</td></tr>
<tr><th>Alphabetic Character Count</th><td>{esc(data['input_summary']['alphabetic_character_count'])}</td></tr>
</table>

<h2>Analysis Configuration</h2>
<table>
{"".join(
    f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>"
    for k, v in data["analysis_configuration"].items()
) or "<tr><td>No configuration recorded.</td></tr>"}
</table>

<h2>Analysis Result</h2>
<table>
{result_rows or '<tr><td>No result data recorded.</td></tr>'}
</table>

<h2>Security Assessment</h2>
<div class="note">
<b>Assessment:</b> {esc(data["security_assessment"])}<br>
<b>Ciphertext Strength:</b> {esc(data["ciphertext_strength"])}<br>
<b>Keyspace:</b> {esc(data["security_metrics"]["keyspace"])}<br>
<b>Brute-Force Resistance:</b> {esc(data["security_metrics"]["brute_force_resistance"])}<br>
<b>Analysis Confidence:</b> {esc(data["security_metrics"]["analysis_confidence"])}<br>
<b>Assessment Basis:</b> {esc(data["security_metrics"]["assessment_basis"])}
</div>

<h2>Security Findings</h2>
<ul>{finding_rows}</ul>

<h2>Limitations</h2>
<div class="note"><ul>{limitation_rows}</ul></div>

<h2>Audit Events</h2>
<table>
<tr><th>Timestamp</th><th>Event</th><th>Details</th><th>Status</th></tr>
{audit_rows}
</table>

</body>
</html>
"""

    def save_html(self, output_path: str | Path) -> Path:
        path = _resolve_output_path(output_path)
        path.write_text(self.to_html(), encoding="utf-8")
        return path