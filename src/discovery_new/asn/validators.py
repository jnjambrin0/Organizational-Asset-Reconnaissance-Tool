"""
ASN Validators

Specialized validators for ASN discovery and validation.
"""

import re
import logging
from typing import Optional, Set, List

from ..common.validators import BaseValidator

logger = logging.getLogger(__name__)


class ASNValidator(BaseValidator):
    """Enhanced ASN validator with comprehensive checks."""

    def __init__(self):
        # ASN number validation patterns
        self.asn_patterns = [
            re.compile(r"^AS(\d+)$", re.IGNORECASE),  # AS12345 format
            re.compile(r"^(\d+)$"),  # Plain number format
        ]

        # Valid ASN ranges
        self.min_asn = 1
        self.max_asn_16bit = 65535
        self.max_asn_32bit = 4294967295

        # Reserved ASN ranges (RFC)
        self.reserved_ranges = [
            (0, 0),  # Reserved
            (23456, 23456),  # AS_TRANS
            (64496, 64511),  # Reserved for use in documentation
            (64512, 65534),  # Reserved for Private Use
            (65535, 65535),  # Reserved
        ]

    def validate(self, asn_identifier: str) -> bool:
        """Validate an ASN identifier."""
        if not asn_identifier:
            return False

        # Try to extract ASN number
        asn_number = self._extract_asn_number(asn_identifier)
        if asn_number is None:
            return False

        # Check if in valid range
        if not (self.min_asn <= asn_number <= self.max_asn_32bit):
            return False

        # Check if not in reserved ranges
        if self._is_reserved_asn(asn_number):
            logger.debug(f"ASN {asn_number} is in reserved range")
            return False

        return True

    def normalize_asn(self, asn_identifier: str) -> Optional[int]:
        """Normalize ASN identifier to integer format."""
        if self.validate(asn_identifier):
            return self._extract_asn_number(asn_identifier)
        return None

    def format_asn(self, asn_number: int) -> str:
        """Format ASN number as AS12345."""
        return f"AS{asn_number}"

    def is_16bit_asn(self, asn_number: int) -> bool:
        """Check if ASN is 16-bit (legacy format)."""
        return 1 <= asn_number <= self.max_asn_16bit

    def is_32bit_asn(self, asn_number: int) -> bool:
        """Check if ASN is 32-bit (new format)."""
        return self.max_asn_16bit < asn_number <= self.max_asn_32bit

    def _extract_asn_number(self, asn_identifier: str) -> Optional[int]:
        """Extract ASN number from various formats."""
        asn_str = asn_identifier.strip()

        for pattern in self.asn_patterns:
            match = pattern.match(asn_str)
            if match:
                try:
                    # Get the number (either from group 1 or the whole match)
                    number_str = match.group(1) if match.groups() else match.group(0)
                    return int(number_str)
                except (ValueError, IndexError):
                    continue

        return None

    def _is_reserved_asn(self, asn_number: int) -> bool:
        """Check if ASN is in reserved range."""
        for start, end in self.reserved_ranges:
            if start <= asn_number <= end:
                return True
        return False


class ASNDescriptionValidator(BaseValidator):
    """Validator for ASN descriptions and organization names."""

    def __init__(self):
        # Common noise patterns in ASN descriptions
        self.noise_patterns = [
            re.compile(r"^UNALLOCATED", re.IGNORECASE),
            re.compile(r"^RESERVED", re.IGNORECASE),
            re.compile(r"^PRIVATE", re.IGNORECASE),
            re.compile(r"^DOCUMENTATION", re.IGNORECASE),
            re.compile(r"^RFC\d+", re.IGNORECASE),
            re.compile(r"^TEST", re.IGNORECASE),
        ]

        # High-quality description indicators
        self.quality_indicators = [
            re.compile(
                r"\b(NETWORKS?|TELECOMMUNICATIONS?|TELECOM|INTERNET|ISP)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(CORPORATION|CORP|COMPANY|ENTERPRISES?|LIMITED|LTD|INC)\b",
                re.IGNORECASE,
            ),
            re.compile(r"\b(UNIVERSITY|COLLEGE|EDUCATION|RESEARCH)\b", re.IGNORECASE),
            re.compile(r"\b(GOVERNMENT|GOV|FEDERAL|STATE|MUNICIPAL)\b", re.IGNORECASE),
            re.compile(r"\b(CLOUD|HOSTING|DATACENTER|DATA\s*CENTER)\b", re.IGNORECASE),
        ]

        # Suspicious patterns (likely non-organizational)
        self.suspicious_patterns = [
            re.compile(r"^\d+$"),  # Pure numeric
            re.compile(r"^[A-Z]{1,3}\d+$"),  # Short acronym + number
            re.compile(r"^[A-F0-9-]+$"),  # Hexadecimal-like
        ]

    def validate(self, description: str) -> bool:
        """Validate an ASN description."""
        if not description or len(description.strip()) < 3:
            return False

        desc = description.strip()

        # Check for noise patterns
        for pattern in self.noise_patterns:
            if pattern.search(desc):
                return False

        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern.match(desc):
                return False

        return True

    def calculate_quality_score(self, description: str) -> float:
        """Calculate quality score for ASN description (0.0 to 1.0)."""
        if not self.validate(description):
            return 0.0

        desc = description.strip()
        score = 0.5  # Base score

        # Boost for quality indicators
        for pattern in self.quality_indicators:
            if pattern.search(desc):
                score += 0.2
                break  # Only one boost per category

        # Length considerations
        if 10 <= len(desc) <= 80:  # Good length range
            score += 0.1
        elif len(desc) > 100:  # Too long, might be noise
            score -= 0.1

        # Word count considerations
        word_count = len(desc.split())
        if 2 <= word_count <= 10:  # Good word count
            score += 0.1
        elif word_count > 15:  # Too many words
            score -= 0.1

        # Check for mixed case (indicates proper formatting)
        if desc.islower() or desc.isupper():
            score -= 0.1  # All same case is suspicious
        else:
            score += 0.1  # Mixed case is good

        return max(0.0, min(1.0, score))

    def extract_organization_name(self, description: str) -> Optional[str]:
        """Extract likely organization name from ASN description."""
        if not self.validate(description):
            return None

        desc = description.strip()

        # Remove common prefixes/suffixes
        cleaned = self._clean_description(desc)

        # Extract the main organization name
        # Simple heuristic: take the first meaningful part
        words = cleaned.split()
        if words:
            # Look for company-like patterns
            for i, word in enumerate(words):
                if word.upper() in [
                    "CORPORATION",
                    "CORP",
                    "COMPANY",
                    "LIMITED",
                    "LTD",
                    "INC",
                ]:
                    # Take everything before this word as the org name
                    return " ".join(words[: i + 1])

            # If no company indicator, take first few words
            if len(words) >= 2:
                return " ".join(words[:2])
            else:
                return words[0]

        return None

    def _clean_description(self, description: str) -> str:
        """Clean ASN description by removing noise."""
        cleaned = description

        # Remove common prefixes
        prefixes_to_remove = ["AS", "ASN", "AUTONOMOUS SYSTEM", "THE ", "A ", "AN "]

        for prefix in prefixes_to_remove:
            if cleaned.upper().startswith(prefix):
                cleaned = cleaned[len(prefix) :].strip()

        # Remove trailing numbers/codes
        cleaned = re.sub(r"\s+[A-Z0-9-]+$", "", cleaned)

        return cleaned.strip()


class ASNRelevanceValidator:
    """Validator for ASN relevance to target organization."""

    def __init__(self, target_terms: Optional[Set[str]] = None):
        self.target_terms = {term.lower() for term in (target_terms or set())}
        self.description_validator = ASNDescriptionValidator()

    def calculate_relevance_score(
        self,
        asn_number: int,
        asn_name: Optional[str],
        asn_description: Optional[str],
        country: Optional[str] = None,
    ) -> float:
        """Calculate relevance score for ASN to target organization."""

        score = 0.3  # Base score

        # Check ASN description quality
        if asn_description:
            quality_score = self.description_validator.calculate_quality_score(
                asn_description
            )
            score += quality_score * 0.3

            # Check for target term matches in description
            desc_lower = asn_description.lower()
            for term in self.target_terms:
                if term in desc_lower:
                    score += 0.4
                    break

        # Check ASN name quality
        if asn_name:
            name_lower = asn_name.lower()
            for term in self.target_terms:
                if term in name_lower:
                    score += 0.3
                    break

        # ASN number considerations
        asn_validator = ASNValidator()
        if asn_validator.is_16bit_asn(asn_number):
            score += 0.1  # 16-bit ASNs are often more established

        return max(0.0, min(1.0, score))

    def is_likely_target_asn(
        self,
        asn_number: int,
        asn_name: Optional[str],
        asn_description: Optional[str],
        min_relevance: float = 0.5,
    ) -> bool:
        """Check if ASN is likely related to target organization."""
        relevance_score = self.calculate_relevance_score(
            asn_number, asn_name, asn_description
        )
        return relevance_score >= min_relevance


def validate_asn_discovery_context(
    search_terms: Set[str], min_terms: int = 1
) -> List[str]:
    """
    Validate ASN discovery context parameters.

    Returns:
        List of validation errors (empty if valid)
    """
    errors = []

    if len(search_terms) < min_terms:
        errors.append(f"At least {min_terms} search term(s) required for ASN discovery")

    for term in search_terms:
        if not term or len(term.strip()) < 2:
            errors.append(f"Search term too short: '{term}'")

    return errors
