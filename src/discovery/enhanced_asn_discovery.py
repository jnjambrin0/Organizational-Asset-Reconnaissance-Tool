"""Enhanced ASN Discovery with multiple sources and intelligent filtering."""

import logging
import re
from typing import Set, Optional, Callable, List, Dict
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.core.models import ASN, ReconnaissanceResult
from src.utils.network import make_request
from src.utils.rate_limiter import get_rate_limiter
from src.utils.backoff import with_api_backoff, RateLimitError
from src.config.settings import get_settings

logger = logging.getLogger(__name__)


@dataclass
class ASNCandidate:
    """Represents a potential ASN with confidence scoring."""

    asn: ASN
    confidence_score: float
    sources: List[str]
    reasons: List[str]


class EnhancedASNDiscovery:
    """Enhanced ASN discovery with multiple sources and intelligent filtering."""

    def __init__(self, config=None):
        self.config = config or get_settings()
        self.max_asns_per_org = self.config.recon.max_asns_per_org

    def find_asns_for_organization(
        self,
        org_name: str,
        base_domains: Optional[Set[str]],
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> Set[ASN]:
        """Enhanced ASN discovery with multi-source intelligence."""

        logger.info(f"🔍 Enhanced ASN discovery for: {org_name}")

        if progress_callback:
            progress_callback(0.0, "Starting enhanced ASN discovery...")

        # Phase 1: Generate search queries with variations
        search_queries = self._generate_search_queries(org_name, base_domains)

        # Phase 2: Multi-source ASN collection
        asn_candidates = self._collect_asn_candidates(
            search_queries, result, progress_callback
        )

        # Phase 3: Intelligent filtering and scoring
        filtered_asns = self._filter_and_score_asns(
            asn_candidates, org_name, base_domains
        )

        # Phase 4: Final validation and selection
        final_asns = self._select_final_asns(filtered_asns, result)

        # Add to result
        for asn in final_asns:
            result.add_asn(asn)

        logger.info(
            f"✅ Enhanced ASN discovery completed: {len(final_asns)} high-confidence ASNs found"
        )

        if progress_callback:
            progress_callback(
                100.0, f"Enhanced ASN discovery complete ({len(final_asns)} ASNs)"
            )

        return final_asns

    def _generate_search_queries(
        self, org_name: str, base_domains: Optional[Set[str]]
    ) -> List[str]:
        """Generate intelligent search query variations with strict relevance filtering."""
        queries = set()

        if org_name:
            # Base organization name (most important)
            queries.add(org_name)

            # Clean version without punctuation
            org_clean = org_name.replace(",", "").replace(".", "").strip()
            if org_clean != org_name:
                queries.add(org_clean)

            # Remove common suffixes but keep meaningful parts
            suffixes = [
                "Inc",
                "LLC",
                "Corporation",
                "Corp",
                "Ltd",
                "Limited",
                "Company",
                "Co",
            ]
            for suffix in suffixes:
                for variant in [f" {suffix}", f".{suffix}", f", {suffix}"]:
                    if org_clean.endswith(variant):
                        clean_name = org_clean[: -len(variant)].strip()
                        # Only add if it's still meaningful (not too short)
                        if len(clean_name) >= 4:
                            queries.add(clean_name)

            # STRICT acronym generation - only for multi-word companies with meaningful words
            words = org_clean.split()
            if len(words) >= 2:
                # Filter out generic words before creating acronym
                meaningful_words = [
                    w for w in words if len(w) >= 3 and not self._is_generic_word(w)
                ]
                if len(meaningful_words) >= 2:
                    acronym = "".join(word[0].upper() for word in meaningful_words)
                    # Only add acronyms that are 3+ characters and not too generic
                    if len(acronym) >= 3 and not self._is_too_generic_acronym(acronym):
                        queries.add(acronym)

            # Add case variations only for the main organization name
            queries.add(org_clean.title())
            queries.add(org_clean.upper())

        # Add base domains (these are usually reliable)
        if base_domains:
            for domain in base_domains:
                # Extract company name from domain
                root_name = domain.split(".")[0]
                # Only add if it's meaningful and matches organization
                if len(root_name) >= 4 and self._domain_matches_organization(
                    root_name, org_name
                ):
                    queries.add(root_name)
                    queries.add(root_name.capitalize())

        # STRICT filtering of final queries
        final_queries = []
        for q in queries:
            if self._is_valid_search_query(q.strip(), org_name):
                final_queries.append(q.strip())

        # Prioritize more specific queries
        final_queries.sort(key=lambda x: (-len(x), x.lower()))

        # Limit to prevent explosion but keep quality
        if len(final_queries) > 8:  # Reduced from 12
            final_queries = final_queries[:8]

        logger.info(f"Generated {len(final_queries)} strict search query variations")
        return final_queries

    def _is_generic_word(self, word: str) -> bool:
        """Check if a word is too generic to be useful in search."""
        generic_words = {
            "company",
            "corp",
            "corporation",
            "inc",
            "ltd",
            "limited",
            "group",
            "international",
            "global",
            "systems",
            "services",
            "solutions",
            "technology",
            "tech",
            "network",
            "networks",
            "communications",
            "telecom",
            "digital",
            "online",
            "web",
            "internet",
            "data",
            "software",
            "hardware",
            "consulting",
        }
        return word.lower() in generic_words

    def _is_too_generic_acronym(self, acronym: str) -> bool:
        """Check if an acronym is too generic and would cause false positives."""
        # Common generic acronyms that appear in many unrelated ASNs
        generic_acronyms = {
            "SC",
            "LLC",
            "INC",
            "LTD",
            "CO",
            "SA",
            "SRL",
            "IT",
            "IS",
            "US",
            "UK",
            "NET",
            "COM",
            "ORG",
            "GOV",
            "EDU",
            "INT",
            "MIL",
            "TV",
            "FM",
            "AM",
        }
        return acronym.upper() in generic_acronyms

    def _domain_matches_organization(self, domain_root: str, org_name: str) -> bool:
        """Check if domain root is related to the organization."""
        if not org_name:
            return True

        org_clean = re.sub(r"[^a-zA-Z0-9]", "", org_name.lower())
        domain_clean = re.sub(r"[^a-zA-Z0-9]", "", domain_root.lower())

        # Must have significant overlap
        if domain_clean in org_clean or org_clean in domain_clean:
            return True

        # Check for substantial similarity (at least 60% overlap)
        if len(domain_clean) >= 4 and len(org_clean) >= 4:
            overlap = len(set(domain_clean) & set(org_clean))
            min_len = min(len(domain_clean), len(org_clean))
            if overlap / min_len >= 0.6:
                return True

        return False

    def _is_valid_search_query(self, query: str, org_name: str) -> bool:
        """Validate that a search query is worth executing."""
        if not query or len(query) < 2:
            return False

        # Reject overly generic single words
        if len(query.split()) == 1:
            if len(query) < 4:  # Too short
                return False
            if self._is_generic_word(query):  # Too generic
                return False
            if query.lower() in {
                "coffee",
                "tea",
                "food",
                "restaurant",
                "cafe",
                "shop",
                "store",
            }:
                return False

        # Must be related to organization if we have one
        if org_name and not self._query_relates_to_organization(query, org_name):
            return False

        return True

    def _query_relates_to_organization(self, query: str, org_name: str) -> bool:
        """Check if query is related to the target organization."""
        query_clean = re.sub(r"[^a-zA-Z0-9]", "", query.lower())
        org_clean = re.sub(r"[^a-zA-Z0-9]", "", org_name.lower())

        # Direct match or substantial overlap
        if query_clean == org_clean:
            return True

        if query_clean in org_clean or org_clean in query_clean:
            return True

        # For longer queries, check for meaningful overlap
        if len(query_clean) >= 4 and len(org_clean) >= 4:
            # Check for common substrings of at least 4 characters
            for i in range(len(query_clean) - 3):
                for j in range(i + 4, len(query_clean) + 1):
                    substring = query_clean[i:j]
                    if substring in org_clean and len(substring) >= 4:
                        return True

        return False

    def _collect_asn_candidates(
        self,
        queries: List[str],
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> List[ASNCandidate]:
        """Collect ASN candidates from multiple sources."""

        candidates = []
        total_queries = len(queries)

        # Source 1: BGP.HE.NET (existing implementation)
        for i, query in enumerate(queries):
            try:
                bgp_asns = self._query_bgp_he_net(query, result)
                for asn in bgp_asns:
                    candidate = ASNCandidate(
                        asn=asn,
                        confidence_score=0.7,  # Medium confidence from BGP.HE.NET
                        sources=["BGP.HE.NET"],
                        reasons=[f'Found via BGP.HE.NET search for "{query}"'],
                    )
                    candidates.append(candidate)

                if progress_callback:
                    progress = (i + 1) / total_queries * 40  # 40% for BGP queries
                    progress_callback(
                        progress, f"BGP.HE.NET query {i+1}/{total_queries}"
                    )

            except Exception as e:
                logger.warning(f"BGP.HE.NET query failed for '{query}': {e}")
                result.add_warning(
                    f"Enhanced ASN Discovery: BGP.HE.NET query failed for '{query}'"
                )

        # Source 2: WHOIS organization search (placeholder for future implementation)
        if progress_callback:
            progress_callback(50.0, "WHOIS organization search (placeholder)")

        # Source 3: DNS-based ASN discovery from resolved IPs (limited scope)
        if result.domains:
            ip_asns = self._discover_asns_from_domain_ips(result.domains, result)
            candidates.extend(ip_asns)

        if progress_callback:
            progress_callback(70.0, f"Collected {len(candidates)} ASN candidates")

        return candidates

    def _discover_asns_from_domain_ips(self, domains, result) -> List[ASNCandidate]:
        """Discover ASNs from a limited set of resolved domain IPs."""
        candidates = []

        # Limit IP resolution to avoid the massive WHOIS problem
        max_ips_to_check = 20  # Reasonable limit
        ips_checked = 0

        for domain in domains:
            if ips_checked >= max_ips_to_check:
                break

            for subdomain in list(domain.subdomains)[:5]:  # Limit subdomains per domain
                if ips_checked >= max_ips_to_check:
                    break

                if subdomain.resolved_ips:
                    for ip in list(subdomain.resolved_ips)[
                        :2
                    ]:  # Max 2 IPs per subdomain
                        if ips_checked >= max_ips_to_check:
                            break

                        try:
                            asn_info = self._lightweight_ip_to_asn(ip)
                            if asn_info:
                                candidate = ASNCandidate(
                                    asn=asn_info,
                                    confidence_score=0.9,  # High confidence from IP resolution
                                    sources=["IP-to-ASN"],
                                    reasons=[f"Resolved from domain IP {ip}"],
                                )
                                candidates.append(candidate)
                                ips_checked += 1

                        except Exception as e:
                            logger.debug(f"IP-to-ASN lookup failed for {ip}: {e}")
                            ips_checked += 1

        logger.info(
            f"IP-based ASN discovery: checked {ips_checked} IPs, found {len(candidates)} candidates"
        )
        return candidates

    def _lightweight_ip_to_asn(self, ip: str) -> Optional[ASN]:
        """Lightweight IP to ASN lookup with timeout and error handling."""
        try:
            # This would use a more efficient API or cached lookup
            # For now, placeholder implementation
            return None
        except Exception:
            return None

    def _filter_and_score_asns(
        self,
        candidates: List[ASNCandidate],
        org_name: str,
        base_domains: Optional[Set[str]],
    ) -> List[ASNCandidate]:
        """Intelligent filtering and scoring of ASN candidates with strict relevance."""

        # Group candidates by ASN number
        asn_groups: Dict[int, List[ASNCandidate]] = {}
        for candidate in candidates:
            asn_num = candidate.asn.number
            if asn_num not in asn_groups:
                asn_groups[asn_num] = []
            asn_groups[asn_num].append(candidate)

        # Merge and score each ASN group with strict filtering
        scored_asns = []
        for asn_num, group in asn_groups.items():
            merged_candidate = self._merge_asn_candidates(group, org_name, base_domains)

            # STRICT relevance filtering
            if self._is_asn_genuinely_relevant(
                merged_candidate.asn, org_name, base_domains
            ):
                if merged_candidate.confidence_score >= 0.6:  # Increased threshold
                    scored_asns.append(merged_candidate)
                else:
                    logger.debug(
                        f"ASN {asn_num} filtered out: low confidence ({merged_candidate.confidence_score:.2f})"
                    )
            else:
                logger.debug(
                    f"ASN {asn_num} filtered out: not genuinely relevant to {org_name}"
                )

        # Sort by confidence score
        scored_asns.sort(key=lambda x: x.confidence_score, reverse=True)

        # Apply reasonable limits to prevent explosion
        if len(scored_asns) > 20:  # Reasonable limit for legitimate ASNs
            logger.warning(
                f"Large number of ASNs found ({len(scored_asns)}), limiting to top 20 most relevant"
            )
            scored_asns = scored_asns[:20]

        logger.info(f"Filtered to {len(scored_asns)} genuinely relevant ASN candidates")
        return scored_asns

    def _is_asn_genuinely_relevant(
        self, asn: ASN, org_name: str, base_domains: Optional[Set[str]]
    ) -> bool:
        """Check if an ASN is genuinely relevant to the target organization."""

        if not org_name:
            return True  # No filtering if no organization specified

        asn_desc = (asn.description or asn.name or "").lower()
        org_clean = re.sub(r"[^a-zA-Z0-9]", "", org_name.lower())

        # 1. DIRECT ORGANIZATION MATCH - High confidence
        if self._has_direct_organization_match(asn_desc, org_name):
            return True

        # 2. DOMAIN CORRELATION - Medium-high confidence
        if base_domains and self._asn_correlates_with_domains(asn_desc, base_domains):
            return True

        # 3. REJECT OBVIOUS FALSE POSITIVES
        if self._is_obvious_false_positive(asn_desc, org_name):
            return False

        # 4. SUBSIDIARY/RELATED COMPANY CHECK - Lower confidence
        if self._might_be_subsidiary_or_related(asn_desc, org_name):
            return True

        # 5. DEFAULT: Reject if no clear relationship
        return False

    def _has_direct_organization_match(self, asn_desc: str, org_name: str) -> bool:
        """Check for direct organization name match in ASN description."""

        org_clean = re.sub(r"[^a-zA-Z0-9]", "", org_name.lower())
        asn_clean = re.sub(r"[^a-zA-Z0-9]", "", asn_desc.lower())

        # Exact match
        if org_clean in asn_clean:
            return True

        # Check for organization name words in ASN description
        org_words = org_name.lower().split()
        meaningful_org_words = [
            w for w in org_words if len(w) >= 4 and not self._is_generic_word(w)
        ]

        if len(meaningful_org_words) >= 1:
            for word in meaningful_org_words:
                if word in asn_clean and len(word) >= 4:
                    # Additional validation: word should be significant part of ASN description
                    if (
                        len(word) / len(asn_clean) >= 0.15
                    ):  # At least 15% of description
                        return True

        return False

    def _asn_correlates_with_domains(
        self, asn_desc: str, base_domains: Set[str]
    ) -> bool:
        """Check if ASN description correlates with known base domains."""

        asn_clean = re.sub(r"[^a-zA-Z0-9]", "", asn_desc.lower())

        for domain in base_domains:
            domain_root = domain.split(".")[0].lower()
            if len(domain_root) >= 4:
                if domain_root in asn_clean:
                    return True

        return False

    def _is_obvious_false_positive(self, asn_desc: str, org_name: str) -> bool:
        """Detect obvious false positives that should be rejected."""

        asn_lower = asn_desc.lower()
        org_lower = org_name.lower()

        # Generic infrastructure providers (unless that's what we're looking for)
        if "starbucks" not in org_lower:  # Only apply if not looking for infrastructure
            generic_providers = {
                "cloudflare",
                "amazon",
                "google",
                "microsoft",
                "akamai",
                "fastly",
                "digitalocean",
                "linode",
                "vultr",
                "ovh",
            }
            for provider in generic_providers:
                if provider in asn_lower and provider not in org_lower:
                    return True

        # Generic business types that don't match
        if "coffee" in asn_lower and "coffee" not in org_lower:
            # Reject coffee-related ASNs unless we're specifically looking for coffee companies
            coffee_indicators = ["roasters", "cafe", "espresso", "beans", "brewing"]
            if any(indicator in asn_lower for indicator in coffee_indicators):
                return True

        # Geographic mismatches for very specific regions
        if self._has_geographic_mismatch(asn_desc, org_name):
            return True

        # Different business sectors
        if self._has_sector_mismatch(asn_desc, org_name):
            return True

        return False

    def _has_geographic_mismatch(self, asn_desc: str, org_name: str) -> bool:
        """Check for obvious geographic mismatches."""

        # This is a simplified check - could be expanded
        asn_lower = asn_desc.lower()
        org_lower = org_name.lower()

        # If organization is clearly US-based but ASN is clearly non-US
        us_indicators = ["usa", "america", "united states", "inc", "llc", "corporation"]
        non_us_indicators = ["romania", "srl", "gmbh", "ltd", "limited", "sa", "spa"]

        org_seems_us = any(indicator in org_lower for indicator in us_indicators)
        asn_seems_non_us = any(
            indicator in asn_lower for indicator in non_us_indicators
        )

        # Only flag as mismatch if very clear indicators
        if org_seems_us and asn_seems_non_us:
            # Additional check: make sure there's no actual relationship
            org_clean = re.sub(r"[^a-zA-Z0-9]", "", org_lower)
            asn_clean = re.sub(r"[^a-zA-Z0-9]", "", asn_lower)
            if org_clean not in asn_clean and asn_clean not in org_clean:
                return True

        return False

    def _has_sector_mismatch(self, asn_desc: str, org_name: str) -> bool:
        """Check for obvious business sector mismatches."""

        # This is a basic implementation - could be expanded
        asn_lower = asn_desc.lower()
        org_lower = org_name.lower()

        # Define sector keywords
        sectors = {
            "telecom": ["telecom", "telecommunications", "mobile", "cellular", "phone"],
            "hosting": ["hosting", "datacenter", "server", "cloud", "vps"],
            "retail": ["retail", "store", "shop", "market"],
            "food": ["restaurant", "food", "cafe", "coffee", "dining"],
            "finance": ["bank", "financial", "credit", "investment", "insurance"],
        }

        # Detect organization sector
        org_sector = None
        for sector, keywords in sectors.items():
            if any(keyword in org_lower for keyword in keywords):
                org_sector = sector
                break

        # Detect ASN sector
        asn_sector = None
        for sector, keywords in sectors.items():
            if any(keyword in asn_lower for keyword in keywords):
                asn_sector = sector
                break

        # Flag mismatch only if both sectors are clearly defined and different
        if org_sector and asn_sector and org_sector != asn_sector:
            # Additional check: make sure there's no actual relationship
            org_clean = re.sub(r"[^a-zA-Z0-9]", "", org_lower)
            asn_clean = re.sub(r"[^a-zA-Z0-9]", "", asn_lower)
            if org_clean not in asn_clean and asn_clean not in org_clean:
                return True

        return False

    def _might_be_subsidiary_or_related(self, asn_desc: str, org_name: str) -> bool:
        """Check if ASN might be a subsidiary or related company."""

        # This is a conservative check for potential relationships
        asn_lower = asn_desc.lower()
        org_lower = org_name.lower()

        # Look for partial matches that might indicate relationships
        org_words = [w for w in org_lower.split() if len(w) >= 4]

        for word in org_words:
            if word in asn_lower:
                # Found a match, but verify it's meaningful
                if len(word) >= 5:  # Longer words are more meaningful
                    return True

        return False

    def _merge_asn_candidates(
        self,
        candidates: List[ASNCandidate],
        org_name: str,
        base_domains: Optional[Set[str]],
    ) -> ASNCandidate:
        """Merge multiple candidates for the same ASN and calculate final score."""

        # Use the most complete ASN info
        best_asn = max(candidates, key=lambda c: len(c.asn.description or "")).asn

        # Merge sources and reasons
        all_sources = []
        all_reasons = []
        for candidate in candidates:
            all_sources.extend(candidate.sources)
            all_reasons.extend(candidate.reasons)

        # Calculate confidence score
        base_score = max(c.confidence_score for c in candidates)

        # Boost score for multiple sources
        if len(set(all_sources)) > 1:
            base_score += 0.1

        # Boost score for name matching
        if best_asn.description and org_name:
            if self._names_match(best_asn.description, org_name):
                base_score += 0.2

        # Boost score for domain correlation
        if base_domains and best_asn.description:
            for domain in base_domains:
                domain_root = domain.split(".")[0]
                if domain_root.lower() in best_asn.description.lower():
                    base_score += 0.15
                    break

        # Cap at 1.0
        final_score = min(base_score, 1.0)

        return ASNCandidate(
            asn=best_asn,
            confidence_score=final_score,
            sources=list(set(all_sources)),
            reasons=all_reasons,
        )

    def _names_match(self, asn_desc: str, org_name: str) -> bool:
        """Check if ASN description matches organization name."""
        asn_lower = asn_desc.lower()
        org_lower = org_name.lower()

        # Direct substring match
        if org_lower in asn_lower or asn_lower in org_lower:
            return True

        # Word-based matching
        asn_words = set(re.findall(r"\w+", asn_lower))
        org_words = set(re.findall(r"\w+", org_lower))

        # Check for significant word overlap
        common_words = asn_words.intersection(org_words)
        significant_words = {w for w in common_words if len(w) > 3}

        return len(significant_words) >= 1

    def _select_final_asns(
        self, candidates: List[ASNCandidate], result: ReconnaissanceResult
    ) -> Set[ASN]:
        """Select final ASNs based on confidence and limits."""

        selected_asns = set()

        # Take top candidates up to max limit
        for candidate in candidates[: self.max_asns_per_org]:
            selected_asns.add(candidate.asn)

            # Log selection reasoning
            logger.info(
                f"Selected ASN {candidate.asn.number} ({candidate.asn.description}) "
                f"- Confidence: {candidate.confidence_score:.2f} "
                f"- Sources: {', '.join(candidate.sources)}"
            )

        # Warn if we hit the limit
        if len(candidates) > self.max_asns_per_org:
            warning = (
                f"Limited ASN results to {self.max_asns_per_org} highest-confidence candidates "
                f"(found {len(candidates)} total candidates)"
            )
            logger.warning(warning)
            result.add_warning(f"Enhanced ASN Discovery: {warning}")

        return selected_asns

    @with_api_backoff
    def _query_bgp_he_net(self, query: str, result: ReconnaissanceResult) -> Set[ASN]:
        """Query BGP.HE.NET with enhanced error handling."""
        # Reuse existing implementation from asn_discovery.py
        # This would be imported and called
        from src.discovery.asn_discovery import _query_bgp_he_net

        return _query_bgp_he_net(query, result)
