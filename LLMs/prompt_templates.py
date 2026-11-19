"""
LLMs/prompt_templates.py
Prompt templates used to ask the local LLM (via Ollama) to explain
threat findings in plain language for SOC analysts and management.
"""

THREAT_SUMMARY_PROMPT = """You are a senior SOC (Security Operations Center) analyst.
Explain the following detected security threat in 3-4 concise sentences for a
non-expert reader. Cover: what happened, why it's suspicious, and one concrete
recommended remediation action. Do not invent facts not present below.

Threat Type: {threat_type}
Severity: {severity}
Confidence: {confidence}
Source IP: {source_ip}
Affected User: {user}
Detection Source: {detection_source}
Description: {description}
MITRE ATT&CK: {mitre}

Respond with plain text only, no markdown headers.
"""

ATTACK_CHAIN_SUMMARY_PROMPT = """You are a senior SOC analyst writing an executive summary.
The following is a correlated attack chain from a single source IP, showing the
stages of the attack in order. Summarize the likely attacker intent and overall
risk in 3-5 sentences, suitable for inclusion in an incident report.

Source IP: {source_ip}
Stages observed (in order): {stages}
Peak Severity: {max_severity}
Number of related findings: {finding_count}

Respond with plain text only, no markdown headers.
"""

REMEDIATION_PROMPT = """You are a security engineer. Given this threat finding, list
3 short, specific, actionable remediation steps as a numbered list (no more than
one sentence each).

Threat Type: {threat_type}
Description: {description}
"""
