"""Adapt Agent 1 logs without losing the observed upload/rendering flow."""
from copy import deepcopy
import re
from typing import Any
from urllib.parse import urlsplit

from .security import redact_data, redact_secrets


def extract_method_and_endpoint(observations: list[dict[str, Any]]) -> tuple[str, str]:
    for obs in observations:
        parts = str(obs.get("request_line", "")).strip().split()
        if len(parts) >= 2:
            # Payloads remain in evidence; localization uses the route itself.
            return parts[0].upper(), urlsplit(parts[1]).path or "/"
    return "UNKNOWN", "/"


def _target_key(target: dict[str, Any]) -> tuple[str, str]:
    return target.get("location") or "unknown", target.get("parameter") or "unknown"


def _observation_evidence(obs: dict[str, Any]) -> dict[str, Any]:
    keys = ("step", "request_line", "response_status", "target", "verdict",
            "confidence", "summary", "indicators", "uncertainties",
            "file_upload_signal", "response_key_text")
    result = {key: deepcopy(obs[key]) for key in keys if key in obs}
    request = obs.get("request_content")
    if isinstance(request, str):
        request = re.sub(r"(?im)^(?:cookie|authorization|proxy-authorization):[^\r\n]*",
                         "[credential header omitted]", request)
        result["request_content"] = redact_secrets(request)
    result = redact_data(result)
    truncated = []

    def bounded(value: Any, path: str) -> Any:
        if isinstance(value, str) and len(value) > 8000:
            truncated.append(path)
            return value[:8000] + "\n[omitted: evidence truncated]"
        if isinstance(value, dict):
            return {key: bounded(item, f"{path}.{key}") for key, item in value.items()}
        if isinstance(value, list):
            if len(value) > 24:
                truncated.append(path)
            return [bounded(item, f"{path}[{i}]") for i, item in enumerate(value[:24])]
        return value

    result = bounded(result, "observation")
    if truncated:
        result["truncated_fields"] = truncated
    return result


def _select_observations(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Keep baseline, strongest observations and latest steps in original order.
    if len(observations) <= 24:
        return observations
    indices = [0]
    indices += [i for i, obs in enumerate(observations) if obs.get("verdict") == "vulnerable"]
    indices += list(range(len(observations) - 1, -1, -1))
    selected = list(dict.fromkeys(indices))[:24]
    return [observations[i] for i in sorted(selected)]


def convert_agent1_to_batch(agent1_data: dict[str, Any], source_revision: str = "local-snapshot-001") -> dict[str, Any]:
    """Support exported logs and raw sessions without modifying the caller's data."""
    session = agent1_data.get("session") or agent1_data
    observations = agent1_data.get("observations", session.get("observations", []))
    session_id = session.get("session_id", "unknown-session")
    profile = str(session.get("profile", "unknown")).strip().lower()
    vulnerability_type = {
        "file upload": "file_upload", "file-upload": "file_upload",
        "unrestricted file upload": "file_upload",
    }.get(profile, profile)
    targets = []
    seen = set()
    for target in (session.get("targets") or []) + [obs.get("target") or {} for obs in observations]:
        key = _target_key(target)
        if key not in seen and key != ("unknown", "unknown"):
            targets.append(deepcopy(target))
            seen.add(key)
    if not targets:
        targets = [{"parameter": "unknown", "location": "unknown"}]

    candidates = []
    upload_observations = [obs for obs in observations
                           if extract_method_and_endpoint([obs])[0] in {"POST", "PUT", "PATCH"}
                           and ((obs.get("file_upload_signal") or {}).get("filename")
                                or "multipart/form-data" in str(obs.get("request_content", "")).lower())]
    if vulnerability_type == "file_upload" and upload_observations:
        # One upload handler owns the whole upload -> retrieve/execute sequence.
        # A later cmd/path target is supporting evidence, not a second upload bug.
        routes = list(dict.fromkeys(extract_method_and_endpoint([obs]) for obs in upload_observations))
        for method, endpoint in routes:
            local = [obs for obs in upload_observations
                     if extract_method_and_endpoint([obs]) == (method, endpoint)]
            target = next((obs["target"] for obs in local if obs.get("target")),
                          {"parameter": "unknown", "location": "unknown"})
            candidates.append((target, method, endpoint, local))
    else:
        for target in targets:
            matching = [obs for obs in observations if _target_key(obs.get("target") or {}) == _target_key(target)]
            # The same parameter on two routes must not be assigned to the first route.
            routes = list(dict.fromkeys(extract_method_and_endpoint([obs]) for obs in matching))
            if not routes:
                routes = [extract_method_and_endpoint(observations)]
            for method, endpoint in routes:
                local = [obs for obs in matching if extract_method_and_endpoint([obs]) == (method, endpoint)]
                candidates.append((target, method, endpoint, local))

    findings = []
    for target, method, endpoint, local in candidates:
        selected = _select_observations(local)
        related = _select_observations([obs for obs in observations if obs not in local])
        evidence = {
            "summary": session.get("session_summary", ""),
            "final_verdict": session.get("final_verdict", "inconclusive"),
            "final_evidence_summary": session.get("final_evidence_summary", ""),
            "total_steps": session.get("total_steps", len(observations)),
            "observed_targets": list({
                _target_key(obs.get("target") or {}): deepcopy(obs.get("target") or {})
                for obs in local
            }.values()),
            "observations": [_observation_evidence(obs) for obs in selected],
            "related_observations": [_observation_evidence(obs) for obs in related],
            "omitted_observation_count": len(observations) - len(selected) - len(related),
        }
        findings.append({
            "finding_id": f"F-{session_id}-{len(findings) + 1:03d}",
            "vulnerability_type": vulnerability_type,
            "endpoint": endpoint, "method": method,
            "parameter": {"name": target.get("parameter", "unknown"),
                          "location": target.get("location", "unknown")},
            "evidence": evidence,
        })
    return {
        "batch_id": f"B-{session_id}", "source_revision": source_revision,
        "metadata": {"origin": agent1_data.get("producer", "Agent 1 Adapter")},
        "findings": findings,
    }
