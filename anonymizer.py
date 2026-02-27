# Copyright 2025 DJAM Foundation / IA Commune Algeria
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""core/anonymizer.py — PII detection and redaction."""
import re


class Anonymizer:
    PATTERNS = {
        "email":       (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[EMAIL]"),
        "phone":       (r"\b(?:\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b", "[PHONE]"),
        "ssn":         (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
        "credit_card": (r"\b(?:\d{4}[\s\-]?){4}\b", "[CARD]"),
        "ip_address":  (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]"),
    }

    def __init__(self, fields: list = None):
        self.fields = fields or list(self.PATTERNS.keys())

    def anonymize(self, text: str) -> tuple:
        replacements = []
        for field in self.fields:
            if field not in self.PATTERNS:
                continue
            pattern, placeholder = self.PATTERNS[field]
            for m in re.findall(pattern, text):
                replacements.append({"field": field, "original": m,
                                     "replaced_with": placeholder})
            text = re.sub(pattern, placeholder, text)
        return text, replacements

    def anonymize_dict(self, data: dict, keys: list) -> dict:
        result = dict(data)
        for k in keys:
            if k in result and isinstance(result[k], str):
                result[k], _ = self.anonymize(result[k])
        return result
