import re
import unicodedata
from typing import List, Dict, Optional, Tuple
from difflib import SequenceMatcher


class EmailParser:

    TRUSTED_BRANDS = [
        "microsoft", "google", "paypal", "amazon", "apple", "meta", "facebook",
        "linkedin", "dropbox", "adobe", "chase", "bankofamerica", "wellsfargo",
        "github", "gitlab", "slack", "zoom", "cisco", "fortinet", "crowdstrike"
    ]

    COMBOSQUAT_KEYWORDS = [
        "secure", "login", "verify", "account", "update", "confirm", "signin",
        "authenticate", "validate", "support", "billing", "payment", "alert"
    ]

    HOMOGLYPHS = {
        'а': 'a', 'е': 'e', 'ё': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
        'у': 'y', 'х': 'x', 'ԁ': 'd', 'ѕ': 's', 'і': 'i', 'ј': 'j',
        'ｃ': 'c', 'ｂ': 'b', 'ｉ': 'i', 'ａ': 'a'
    }

    def __init__(self, raw_email: str) -> None:
       
        self.raw_email = raw_email
        self.headers: Dict[str, str] = {}
        self.body: str = ""
        self._parse_headers_and_body()

    def _parse_headers_and_body(self) -> None:
        parts = self.raw_email.split("\n\n", 1)
        if len(parts) < 2:
            self.body = self.raw_email
            return

        header_section = parts[0]
        self.body = parts[1]

        current_key = None
        for line in header_section.splitlines():
            if line.strip() == "":
                continue
            if line[0].isspace() and current_key: 
                self.headers[current_key] += " " + line.strip()
            else:
                if ": " in line:
                    key, val = line.split(": ", 1)
                    self.headers[key.strip()] = val.strip()
                    current_key = key.strip()
                else:
                    continue

    def extract_urls(self) -> List[str]:
        """Extract all URLs from email body and headers."""
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w$.+!*\'(),;?:@=&#%/~\\_]*)?'
        urls = re.findall(url_pattern, self.raw_email, re.IGNORECASE)
        return list(set(urls))

    @staticmethod
    def right_to_left_url_analyzer(url: str) -> str:
       
        clean = re.sub(r'^https?://', '', url.lower().split('/')[0])
        parts = clean.split('.')
       
        if '\u202e' in clean:
            clean = clean.replace('\u202e', '')
        tlds = {'co.uk', 'com.au', 'org.uk', 'ac.jp'}
        if len(parts) >= 3 and '.'.join(parts[-2:]) in tlds:
            return '.'.join(parts[-2:])
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return clean

    def detect_typosquatting(self, domain: str) -> List[str]:
       
        domain_clean = domain.lower().split('.')[0]  # main SLD
        matches = []
        for brand in self.TRUSTED_BRANDS:
            ratio = SequenceMatcher(None, domain_clean, brand).ratio()
            if ratio > 0.85 and domain_clean != brand:
                matches.append(brand)
        return matches

    def detect_combosquatting(self, domain: str) -> bool:
       
        domain_lower = domain.lower()
        return any(keyword in domain_lower for keyword in self.COMBOSQUAT_KEYWORDS)

    def detect_homoglyph(self, text: str) -> bool:
       
        for char in text:
            if char in self.HOMOGLYPHS:
                return True
            try:
                if unicodedata.name(char).startswith('CYRILLIC'):
                    return True
            except ValueError:
                continue
        return False

    def check_header_integrity(self) -> Dict[str, str]:
       
        result = {
            'status': 'valid',
            'from_display': '',
            'from_addr': '',
            'routing_domain': '',
            'mismatch': False
        }
        from_header = self.headers.get('From', '')
        if not from_header:
            result['status'] = 'missing'
            return result

        match = re.match(r'(.+?)\s*<(.+?)>', from_header)
        if match:
            display_name = match.group(1).strip()
            email_addr = match.group(2).strip()
            result['from_display'] = display_name
            result['from_addr'] = email_addr
        else:
            email_addr = from_header.strip()
            result['from_addr'] = email_addr

        if '@' in result['from_addr']:
            result['routing_domain'] = result['from_addr'].split('@')[-1].lower()

        routing_domains = []
        for header in ['Return-Path', 'Reply-To', 'Received']:
            if header in self.headers:
                val = self.headers[header].lower()
                if header in ['Return-Path', 'Reply-To']:
                    match_dom = re.search(r'@([a-z0-9.-]+)', val)
                    if match_dom:
                        routing_domains.append(match_dom.group(1))
                if header == 'Received':
                    match_by = re.search(r'by\s+([a-z0-9.-]+)', val)
                    if match_by:
                        routing_domains.append(match_by.group(1))
        if routing_domains and result['routing_domain']:
            if result['routing_domain'] not in routing_domains:
                result['mismatch'] = True
                result['status'] = 'mismatch'
        elif result['routing_domain'] and not routing_domains:
            result['status'] = 'unknown'
        return result

    def run_all(self) -> Dict:
        
        urls = self.extract_urls()
        analyzed_urls = []
        for url in urls:
            root_domain = self.right_to_left_url_analyzer(url)
            analyzed_urls.append({
                'original': url,
                'root_domain': root_domain,
                'typosquat': self.detect_typosquatting(root_domain),
                'combosquat': self.detect_combosquatting(root_domain),
                'has_homoglyph': self.detect_homoglyph(url)
            })

        header_integrity = self.check_header_integrity()
        body_homoglyph = self.detect_homoglyph(self.body)

        return {
            'headers': self.headers,
            'body_preview': self.body[:500],
            'urls': analyzed_urls,
            'header_integrity': header_integrity,
            'body_has_homoglyph': body_homoglyph,
            'raw_email_length': len(self.raw_email)
        }