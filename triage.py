import re
from typing import Dict, List, Any


class PhishingScorer:
   

    URGENCY_KEYWORDS = [
        "urgent", "immediate", "as soon as possible", "expires", "deadline",
        "within 24 hours", "today", "now", "quickly", "don't delay"
    ]
    COERCION_KEYWORDS = [
        "strictly confidential", "confidential", "do not share", "internal only",
        "bypass standard procedure", "skip protocol", "authorized", "mandatory"
    ]
    FEAR_GREED_KEYWORDS = [
        "account locked", "suspended", "unauthorized transaction", "fraud alert",
        "security breach", "refund", "prize", "winning", "lottery", "inheritance",
        "payment required", "overdue", "penalty"
    ]

    def __init__(self, parsed_telemetry: Dict[str, Any]) -> None:
        
        self.telemetry = parsed_telemetry
        self.risk_score: int = 0
        self.psychological_triggers: Dict[str, List[str]] = {
            'urgency': [],
            'coercion': [],
            'fear_greed': []
        }

    def psychological_vector_weighting(self) -> None:
        
        text = self.telemetry.get('body_preview', '').lower()
        
        headers_text = ' '.join(self.telemetry.get('headers', {}).values()).lower()
        full_text = text + " " + headers_text

        for keyword in self.URGENCY_KEYWORDS:
            if keyword in full_text:
                self.psychological_triggers['urgency'].append(keyword)

        for keyword in self.COERCION_KEYWORDS:
            if keyword in full_text:
                self.psychological_triggers['coercion'].append(keyword)

        for keyword in self.FEAR_GREED_KEYWORDS:
            if keyword in full_text:
                self.psychological_triggers['fear_greed'].append(keyword)

    def evaluate_risk_score(self) -> int:
        
        score = 0

        url_analysis = self.telemetry.get('urls', [])
        for url_info in url_analysis:
            if url_info['typosquat']:
                score += 15  
            if url_info['combosquat']:
                score += 10
            if url_info['has_homoglyph']:
                score += 20 
        if score > 40:
            score = 40

        header_int = self.telemetry.get('header_integrity', {})
        if header_int.get('mismatch'):
            score += 20
        elif header_int.get('status') == 'missing':
            score += 10

        if self.telemetry.get('body_has_homoglyph'):
            score += 15

        self.psychological_vector_weighting()
        trigger_count = (len(self.psychological_triggers['urgency']) +
                         len(self.psychological_triggers['coercion']) +
                         len(self.psychological_triggers['fear_greed']))
        score += min(trigger_count * 3, 25)

        self.risk_score = min(100, max(0, score))
        return self.risk_score

    def decision_tree(self) -> Dict[str, Any]:
        
        score = self.risk_score
        if score < 30:
            return {
                'severity': 'LOW',
                'action': 'SAFE',
                'corporate_action': 'CLOSE: No action required. Ticket resolved.',
                'escalate': False,
                'color': '#10B981'
            }
        elif 30 <= score <= 65:
            return {
                'severity': 'MEDIUM',
                'action': 'SUSPICIOUS',
                'corporate_action': 'WARN: Strip attachments, notify user, and quarantine email.',
                'escalate': False,
                'color': '#F59E0B'
            }
        else:
            return {
                'severity': 'HIGH',
                'action': 'MALICIOUS',
                'corporate_action': 'ESCALATE TO SOC: Block sender domain, log SIEM, trigger incident response.',
                'escalate': True,
                'color': '#EF4444'
            }

    def produce_triage_report(self) -> Dict[str, Any]:
       
        self.evaluate_risk_score()  # ensures score and triggers computed
        decision = self.decision_tree()
        return {
            'risk_score': self.risk_score,
            'psychological_triggers': self.psychological_triggers,
            'decision': decision,
            'raw_telemetry': self.telemetry
        }