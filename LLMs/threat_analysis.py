def build_threat_prompt(threat):

    return f"""
You are a cybersecurity threat analyst.

Analyze the following security event.

Threat Type:
{threat.get('threat_type')}

Source IP:
{threat.get('source_ip')}

Username:
{threat.get('username')}

Severity:
{threat.get('severity')}

Confidence:
{threat.get('confidence')}%

Timestamp:
{threat.get('timestamp')}

Evidence:
{threat.get('raw_event')}

Provide:

1. What happened?
2. Why is this suspicious?
3. Attack type
4. Severity justification
5. Recommended defensive action

Give a concise security analyst explanation.
"""


def analyze_threat_with_llm(threat, llm_client):

    prompt = build_threat_prompt(threat)

    try:

        response = llm_client.generate(prompt)

        threat["llm_explanation"] = response
        threat["llm_confirmed"] = True

    except Exception as e:

        threat["llm_explanation"] = (
            "LLM analysis unavailable."
        )

        threat["llm_confirmed"] = False
        threat["llm_error"] = str(e)

    return threat