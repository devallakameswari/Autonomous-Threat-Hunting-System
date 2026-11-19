"""
LLMs/llm_manager.py
High-level interface used by the detection engine to get a human-readable
explanation of a threat finding. Tries the local Ollama LLM first; if it's
unavailable or disabled, falls back to a deterministic template-based
summary so the system never blocks on the LLM being offline.
"""

from config import Config
from LLMs.ollama_client import OllamaClient
from LLMs.prompt_templates import THREAT_SUMMARY_PROMPT, ATTACK_CHAIN_SUMMARY_PROMPT
from Threat_Intelligence.mitre_mapper import map_threat


class LLMManager:
    def __init__(self):
        self.enabled = Config.LLM_ENABLED
        self.client = OllamaClient()

    def _fallback_threat_summary(self, finding: dict) -> str:
        mitre = map_threat(finding.get("threat_type", ""))
        return (
            f"{finding.get('title', 'Security finding')}. "
            f"This was classified as {finding.get('severity', 'MEDIUM')} severity with "
            f"{round(finding.get('confidence', 0) * 100)}% confidence via "
            f"{finding.get('detection_source', 'the detection engine')}. "
            f"{finding.get('description', '')} "
            f"This maps to MITRE ATT&CK {', '.join(mitre['techniques'])} ({mitre['name']}). "
            f"Recommended action: investigate the source IP, review associated account "
            f"activity, and consider a temporary block if activity continues."
        )

    def summarize_threat(self, finding: dict) -> str:
        if not self.enabled or not self.client.is_available():
            return self._fallback_threat_summary(finding)

        mitre = map_threat(finding.get("threat_type", ""))
        prompt = THREAT_SUMMARY_PROMPT.format(
            threat_type=finding.get("threat_type", "unknown"),
            severity=finding.get("severity", "MEDIUM"),
            confidence=finding.get("confidence", 0),
            source_ip=finding.get("source_ip", "unknown"),
            user=finding.get("user", "N/A"),
            detection_source=finding.get("detection_source", "unknown"),
            description=finding.get("description", ""),
            mitre=", ".join(mitre["techniques"]),
        )
        try:
            return self.client.generate(prompt)
        except RuntimeError:
            return self._fallback_threat_summary(finding)

    def summarize_attack_chain(self, chain: dict) -> str:
        fallback = (
            f"Source {chain['source_ip']} progressed through the following stages: "
            f"{' -> '.join(chain['stages'])}, reaching a peak severity of "
            f"{chain['max_severity']} across {chain['finding_count']} correlated findings. "
            f"This pattern suggests a deliberate, multi-stage attack rather than isolated noise. "
            f"Recommend prioritizing this source IP for immediate investigation and containment."
        )

        if not self.enabled or not self.client.is_available():
            return fallback

        prompt = ATTACK_CHAIN_SUMMARY_PROMPT.format(
            source_ip=chain["source_ip"],
            stages=" -> ".join(chain["stages"]),
            max_severity=chain["max_severity"],
            finding_count=chain["finding_count"],
        )
        try:
            return self.client.generate(prompt)
        except RuntimeError:
            return fallback
