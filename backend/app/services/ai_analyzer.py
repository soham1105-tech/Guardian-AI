import json
from groq import Groq
from app.config import settings

client = Groq(api_key=settings.GROQ_API_KEY) if settings.GROQ_API_KEY else None

SYSTEM_PROMPT = """You are a cybersecurity email analyst. You will receive structured
security evidence extracted from an email (NOT the raw email itself). Based ONLY on
this evidence, provide a threat assessment.

Do not invent indicators that are not present in the evidence.
Respond ONLY with valid JSON, no markdown, no preamble, in this exact structure:

{
  "classification": "string - e.g. Likely Credential Phishing / Likely Safe / Suspicious - Needs Review",
  "confidence": integer 0-100,
  "explanation": "2-3 sentence plain English explanation citing the specific evidence",
  "recommended_action": "string - e.g. Block sender and report to IT / Safe to open / Quarantine for manual review"
}
"""


def get_ai_verdict(evidence: dict) -> dict:
    """
    Sends structured evidence (not raw email) to the LLM and gets back
    a plain-English verdict. Falls back gracefully if API key missing
    or request fails.
    """
    if not client:
        return _fallback_verdict(evidence, reason="AI service not configured (missing API key)")

    try:
        response = client.chat.completions.create(
            model=settings.AI_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(evidence, indent=2)},
            ],
            temperature=0.2,
            max_tokens=500,
        )

        raw_content = response.choices[0].message.content.strip()

        # Strip markdown fences if model adds them despite instructions
        raw_content = raw_content.replace("```json", "").replace("```", "").strip()

        parsed = json.loads(raw_content)

        return {
            "classification": parsed.get("classification", "Unknown"),
            "confidence": int(parsed.get("confidence", 0)),
            "explanation": parsed.get("explanation", ""),
            "recommended_action": parsed.get("recommended_action", "Manual review recommended"),
        }

    except json.JSONDecodeError:
        return _fallback_verdict(evidence, reason="AI response could not be parsed")
    except Exception as e:
        return _fallback_verdict(evidence, reason=f"AI service error: {str(e)}")


def _fallback_verdict(evidence: dict, reason: str) -> dict:
    """
    Deterministic fallback so the pipeline never breaks if AI is unavailable.
    Uses the risk_engine's score/category directly.
    """
    score = evidence.get("risk_score", 0)
    category = evidence.get("risk_category", "SAFE")

    return {
        "classification": f"Rule-based verdict: {category}",
        "confidence": 50,
        "explanation": f"AI analysis unavailable ({reason}). Verdict based on deterministic risk engine only.",
        "recommended_action": "Manual review recommended" if score >= 30 else "Low risk based on automated checks",
    }