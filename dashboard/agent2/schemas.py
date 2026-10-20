from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

SUPPORTED_VULNERABILITIES = {"sqli", "lfi", "file_upload"}
FINAL_STATUSES = {"confirmed", "unresolved", "analysis_limit_reached", "failed"}
CONFIDENCE_VALUES = {"high", "medium", "low"}


class SchemaError(ValueError):
    pass


@dataclass
class Finding:
    finding_id: str
    vulnerability_type: str
    endpoint: str
    method: str
    parameter: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        required = ["finding_id", "vulnerability_type", "endpoint", "method"]
        missing = [key for key in required if not data.get(key)]
        if missing:
            raise SchemaError(f"Finding missing required fields: {', '.join(missing)}")

        vuln = str(data["vulnerability_type"]).strip().lower()
        aliases = {
            "sql injection": "sqli",
            "sql_injection": "sqli",
            "local file inclusion": "lfi",
            "file upload": "file_upload",
            "file-upload": "file_upload",
            "unrestricted file upload": "file_upload",
        }
        vuln = aliases.get(vuln, vuln)
        if vuln not in SUPPORTED_VULNERABILITIES:
            raise SchemaError(
                f"Unsupported vulnerability_type={vuln!r}; expected one of "
                f"{sorted(SUPPORTED_VULNERABILITIES)}"
            )

        return cls(
            finding_id=str(data["finding_id"]),
            vulnerability_type=vuln,
            endpoint=str(data["endpoint"]),
            method=str(data["method"]).upper(),
            parameter=dict(data.get("parameter") or {}),
            evidence=dict(data.get("evidence") or {}),
            metadata=dict(data.get("metadata") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FindingBatch:
    batch_id: str
    source_revision: str
    findings: list[Finding]
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FindingBatch":
        if not data.get("batch_id"):
            raise SchemaError("batch_id is required")
        if not data.get("source_revision"):
            raise SchemaError("source_revision is required")

        raw_findings = data.get("findings")
        if not isinstance(raw_findings, list) or not raw_findings:
            raise SchemaError("findings must be a non-empty array")

        findings = [Finding.from_dict(item) for item in raw_findings]
        ids = [f.finding_id for f in findings]
        if len(ids) != len(set(ids)):
            raise SchemaError("finding_id values must be unique inside a batch")

        return cls(
            batch_id=str(data["batch_id"]),
            source_revision=str(data["source_revision"]),
            findings=findings,
            metadata=dict(data.get("metadata") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "source_revision": self.source_revision,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }


def validate_finish_result(result: dict[str, Any], finding: Finding) -> dict[str, Any]:
    """Validate and normalize the model's final per-finding result."""
    if not isinstance(result, dict):
        raise SchemaError("finish.result must be an object")

    result = dict(result)
    result["finding_id"] = finding.finding_id
    result["vulnerability_type"] = finding.vulnerability_type

    status = str(result.get("analysis_status", "")).strip().lower()
    if status not in FINAL_STATUSES:
        raise SchemaError(f"Invalid analysis_status: {status!r}")
    result["analysis_status"] = status

    confidence = str(result.get("confidence", "low")).strip().lower()
    if confidence not in CONFIDENCE_VALUES:
        confidence = "low"
    result["confidence"] = confidence

    if status == "confirmed":
        locations = result.get("code_locations")
        root_cause = result.get("root_cause")
        remediation = result.get("remediation")
        if not isinstance(locations, list) or not locations:
            raise SchemaError("confirmed result requires non-empty code_locations")
        if not isinstance(root_cause, dict) or not root_cause.get("summary"):
            raise SchemaError("confirmed result requires root_cause.summary")
        if not isinstance(remediation, dict) or not remediation.get("recommended_strategy"):
            raise SchemaError("confirmed result requires remediation.recommended_strategy")
    else:
        if not result.get("reason"):
            result["reason"] = "Phân tích chưa xác nhận được nguyên nhân gốc rễ."

    return result
