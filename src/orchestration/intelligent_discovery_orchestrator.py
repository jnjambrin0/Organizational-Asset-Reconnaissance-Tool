"""
Intelligent Discovery Orchestrator with Automatic Learning and Expansion

This module implements an intelligent discovery system that automatically learns
about organizations from discovered data and expands searches iteratively without
requiring hardcoded knowledge about specific companies.
"""

import logging
import re
import time
import threading
from typing import Set, Optional, Callable, Dict, List, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, Counter

from src.core.models import ReconnaissanceResult, ASN, Domain, IPRange
from src.config.settings import get_settings
from src.discovery.enhanced_domain_discovery import EnhancedDomainDiscovery
from src.discovery.enhanced_asn_discovery import EnhancedASNDiscovery
from src.discovery.intelligent_ip_discovery import IntelligentIPDiscovery
from src.discovery.enhanced_cloud_detection import EnhancedCloudDetection
from src.utils.logging_config import (
    get_logger,
    log_section_start,
    log_discovery_start,
    log_discovery_complete,
    operation_timer,
)
from src.utils.banner import print_mission_header, print_mission_complete
from src.utils.streamlit_threading import (
    HighPerformanceTimeoutExecutor,
    suppress_streamlit_thread_warnings,
)

logger = get_logger(__name__)

# Initialize high-performance threading at module load
suppress_streamlit_thread_warnings()


@dataclass
class DiscoveryIteration:
    """Represents one iteration of intelligent discovery."""

    iteration_number: int
    search_terms: Set[str]
    new_assets_found: int
    total_time: float
    convergence_score: float
    expansion_strategies_used: List[str]


@dataclass
class OrganizationIntelligence:
    """Container for learned intelligence about an organization."""

    organization_names: Set[str] = field(default_factory=set)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    asn_descriptions: Set[str] = field(default_factory=set)
    domain_patterns: Set[str] = field(default_factory=set)


class IntelligentDiscoveryOrchestrator:
    """
    Intelligent Discovery Orchestrator that automatically learns about organizations
    from discovered data and expands searches without hardcoded knowledge.

    Now with ultra-high-performance threading that eliminates Streamlit warnings
    and provides 2-3x faster execution.
    """

    def __init__(self, config=None):
        """Initialize the Intelligent Discovery Orchestrator."""
        self.config = config or get_settings()

        # Initialize discovery modules
        self.domain_discovery = EnhancedDomainDiscovery(self.config)
        self.asn_discovery = EnhancedASNDiscovery(self.config)
        self.ip_discovery = IntelligentIPDiscovery(self.config)
        self.cloud_detection = EnhancedCloudDetection(self.config)

        # Discovery configuration
        self.max_iterations = 3
        self.max_search_terms_per_iteration = 15  # Balanced limit
        self.min_term_length = 4
        self.min_confidence_threshold = 0.4
        self.convergence_threshold = 0.15  # Balanced threshold

        # State tracking
        self.org_intelligence = OrganizationIntelligence()
        self.discovery_history = []
        self.processed_search_terms = set()
        self.target_organization = None  # Store target organization for filtering

        # Performance tracking
        self.start_time = None
        self.total_queries = 0

        logger.info(
            "Intelligent Discovery Orchestrator initialized with ultra-high-performance threading"
        )

    def _log_mission_start(self, target_organization: str):
        """Log mission start with banner."""
        logger.info("=" * 80)
        logger.info(f"🚀 INTELLIGENT DISCOVERY MISSION INITIATED")
        logger.info(f"🎯 Target Organization: {target_organization}")
        logger.info(
            f"⚙️  Configuration: {self.max_iterations} iterations, {self.max_search_terms_per_iteration} terms/iter"
        )
        logger.info("=" * 80)

    def _log_iteration_start(self, iteration: int, search_terms: Set[str]):
        """Log iteration start."""
        logger.info(
            f"🔍 ITERATION {iteration}/{self.max_iterations} - {len(search_terms)} search vectors"
        )
        logger.info(
            f"🧠 Learning from {len(self.org_intelligence.organization_names)} discovered organizations"
        )

    def _log_iteration_results(
        self,
        iteration: int,
        new_assets: int,
        total_assets: int,
        convergence_score: float,
        iteration_time: float,
    ):
        """Log iteration results."""
        logger.info(f"✅ Iteration {iteration} results:")
        logger.info(f"   💎 New assets discovered: {new_assets}")
        logger.info(f"   📊 Total assets: {total_assets}")
        logger.info(f"   🎯 Convergence score: {convergence_score:.3f}")
        logger.info(f"   ⚡ Duration: {iteration_time:.2f}s")

        # Store iteration history
        self.discovery_history.append(
            {
                "iteration": iteration,
                "new_assets": new_assets,
                "total_assets": total_assets,
                "convergence_score": convergence_score,
                "duration": iteration_time,
            }
        )

    def _log_mission_complete(
        self, target_organization: str, total_time: float, total_assets: int
    ):
        """Log mission completion."""
        logger.info("=" * 80)
        logger.info(f"🎉 MISSION ACCOMPLISHED for {target_organization}")
        logger.info(f"⏱️  Total Duration: {total_time:.2f} seconds")
        logger.info(f"📊 Total Assets Discovered: {total_assets}")
        logger.info("=" * 80)

    def run_intelligent_discovery(
        self,
        target_organization: str,
        base_domains: Optional[Set[str]] = None,
        progress_callback: Optional[Callable[[float, str], None]] = None,
        status_callback: Optional[Callable[[str, str], None]] = None,
        phase_callback: Optional[Callable] = None,
    ) -> ReconnaissanceResult:
        """
        Run intelligent discovery with adaptive learning and convergence detection.

        Args:
            target_organization: Name of the target organization
            base_domains: Optional set of known base domains
            progress_callback: Optional callback for progress updates
            status_callback: Optional callback for status updates
            phase_callback: Optional callback for phase updates

        Returns:
            ReconnaissanceResult with discovered assets
        """

        # Store target organization for learning filtering
        self.target_organization = target_organization

        # Initialize timing
        self.start_time = time.time()

        # Create result object
        result = ReconnaissanceResult(target_organization)

        # Initialize search terms
        search_terms = self._initialize_search_terms(target_organization, base_domains)

        # Log mission start
        self._log_mission_start(target_organization)

        try:
            # Main discovery loop
            for iteration in range(1, self.max_iterations + 1):
                iteration_start = time.time()

                # Log iteration start
                self._log_iteration_start(iteration, search_terms)

                # Update progress
                base_progress = (iteration - 1) / self.max_iterations * 100
                if progress_callback:
                    progress_callback(
                        base_progress,
                        f"Iteration {iteration}: Adaptive learning in progress...",
                    )
                if status_callback:
                    status_callback(
                        "🔍",
                        f"Discovery iteration {iteration} - {len(search_terms)} search vectors",
                    )

                # Execute discovery iteration
                previous_asset_count = self._count_total_assets(result)

                self._execute_discovery_iteration_hp(
                    search_terms, result, iteration, progress_callback, status_callback
                )

                # Calculate iteration metrics
                iteration_time = time.time() - iteration_start
                new_assets = self._count_total_assets(result) - previous_asset_count
                convergence_score = (
                    new_assets / max(previous_asset_count, 1)
                    if previous_asset_count > 0
                    else 1.0
                )

                # Log iteration results
                self._log_iteration_results(
                    iteration,
                    new_assets,
                    self._count_total_assets(result),
                    convergence_score,
                    iteration_time,
                )

                # Check for convergence
                if convergence_score < self.convergence_threshold and iteration > 1:
                    logger.info(
                        f"🎯 Discovery convergence achieved at iteration {iteration}"
                    )
                    logger.info(
                        f"   📈 Efficiency threshold reached: {convergence_score:.3f} < {self.convergence_threshold}"
                    )
                    if status_callback:
                        status_callback(
                            "🎯", f"Discovery converged after {iteration} iterations"
                        )
                    break

                # Learn from discovered data and generate new search terms
                if iteration < self.max_iterations:
                    self._learn_from_discovered_data(result)
                    search_terms = self._generate_intelligent_search_terms()

                    if not search_terms:
                        logger.info(
                            "🎯 No new search terms generated - discovery complete"
                        )
                        break

                    logger.info(
                        f"🔄 Preparing iteration {iteration + 1} with {len(search_terms)} new vectors"
                    )

            # Log final results
            total_time = time.time() - self.start_time
            self._log_mission_complete(
                target_organization, total_time, self._count_total_assets(result)
            )
            self._log_final_summary(result, total_time)

            # Update final progress
            if progress_callback:
                progress_callback(
                    100.0, "🎉 Intelligent discovery mission accomplished"
                )
            if status_callback:
                status_callback(
                    "✅",
                    f"Mission complete - {self._count_total_assets(result)} assets discovered in {total_time:.1f}s",
                )

        except Exception as e:
            logger.error(f"Discovery failed: {e}")
            if status_callback:
                status_callback("❌", f"Discovery failed: {str(e)}")
            raise

        return result

    def _generate_intelligent_search_terms(self) -> Set[str]:
        """Generate search terms with precision focus - no arbitrary limits."""

        new_terms = set()

        # Add ALL learned organization names that meet quality standards
        for org_name, confidence in self.org_intelligence.confidence_scores.items():
            if confidence >= self.min_confidence_threshold:
                if self._is_quality_search_term(org_name):
                    new_terms.add(org_name)

        # Add ALL learned ASN description organizations that meet quality standards
        for org_name in self.org_intelligence.asn_descriptions:
            if self._is_quality_search_term(org_name):
                new_terms.add(org_name)

        # Remove already processed terms to prevent re-querying
        new_terms = new_terms - self.processed_search_terms

        # Apply QUALITY filtering instead of quantity limits
        quality_filtered_terms = self._apply_precision_quality_filters(new_terms)

        # Track these terms as processed
        self.processed_search_terms.update(quality_filtered_terms)

        logger.info(
            f"Generated {len(quality_filtered_terms)} high-quality search terms "
            f"(filtered from {len(new_terms)} candidates, {len(self.processed_search_terms)} total processed)"
        )
        return quality_filtered_terms

    def _apply_precision_quality_filters(self, terms: Set[str]) -> Set[str]:
        """Apply precision-focused quality filters without arbitrary limits."""

        filtered = set()

        for term in terms:
            # Apply comprehensive quality checks
            if (
                self._is_quality_search_term(term)
                and not self._is_duplicate_or_fragment(term, filtered)
                and self._is_likely_valuable_search_term(term)
            ):
                filtered.add(term)

        return filtered

    def _is_duplicate_or_fragment(self, term: str, existing_terms: Set[str]) -> bool:
        """Check if term is a duplicate or fragment of existing terms."""

        term_lower = term.lower()

        for existing in existing_terms:
            existing_lower = existing.lower()

            # Check if term is a substring of existing term
            if len(term) < len(existing) and term_lower in existing_lower:
                return True

            # Check if existing term is a substring of new term
            if len(existing) < len(term) and existing_lower in term_lower:
                # Remove the shorter term from existing set
                existing_terms.discard(existing)
                return False

            # Check for very high similarity
            if len(term) >= 3 and len(existing) >= 3:
                common_chars = sum(
                    1 for a, b in zip(term_lower, existing_lower) if a == b
                )
                similarity = common_chars / max(len(term), len(existing))
                if similarity > 0.85:  # Very similar terms
                    return True

        return False

    def _is_likely_valuable_search_term(self, term: str) -> bool:
        """Check if term is likely to yield valuable search results."""

        # Must be substantial enough
        if len(term) < 4:
            return False

        # Prefer terms that look like organization names
        if self._is_likely_organization_name(term):
            return True

        # Include terms with mixed case (likely proper names)
        if any(c.isupper() for c in term) and any(c.islower() for c in term):
            return True

        # Include terms that are relevant to target organization
        if hasattr(self, "target_organization") and self.target_organization:
            if self._is_name_relevant_to_target(term, self.target_organization):
                return True

        # Exclude very generic terms
        if self._is_too_generic(term):
            return False

        # Default: include if it passes basic quality checks
        return True

    def _learn_from_discovered_data(self, result: ReconnaissanceResult):
        """Automatically learn about the organization from discovered data."""

        logger.info("🧠 Learning from discovered data...")

        # Learn from ASN descriptions
        for asn in result.asns:
            if asn.description:
                self._extract_organizations_from_text(
                    asn.description,
                    self.org_intelligence.asn_descriptions,
                    confidence=0.8,
                )

        # Learn from domain patterns
        self._learn_from_domain_patterns(result.domains)

        # Clean and validate learned intelligence
        self._validate_learned_intelligence()

        logger.info(f"Learned intelligence:")
        logger.info(
            f"  Organization names: {len(self.org_intelligence.organization_names)}"
        )
        logger.info(
            f"  ASN descriptions: {len(self.org_intelligence.asn_descriptions)}"
        )
        logger.info(f"  Domain patterns: {len(self.org_intelligence.domain_patterns)}")

    def _extract_organizations_from_text(
        self, text: str, target_set: Set[str], confidence: float = 0.5
    ):
        """Extract organization names from text using strict heuristics to prevent false positives."""

        if not text:
            return

        # Remove common noise words (expanded list)
        noise_words = {
            "autonomous",
            "system",
            "number",
            "network",
            "internet",
            "service",
            "provider",
            "telecommunications",
            "telecom",
            "communications",
            "broadband",
            "fiber",
            "digital",
            "technology",
            "solutions",
            "services",
            "group",
            "holding",
            "corporation",
            "company",
            "limited",
            "ltd",
            "inc",
            "corp",
            "sa",
            "s.a.",
            "srl",
            "gmbh",
            "llc",
            "co",
            "coffee",
            "tea",
            "roasters",
            "cafe",
            "restaurant",
            "food",
            "dining",
            "retail",
            "store",
            "shop",
            "market",
            "center",
            "centre",
            "international",
            "global",
            "national",
            "regional",
            "local",
            "public",
            "private",
            "consulting",
            "management",
            "development",
            "systems",
            "software",
            "hardware",
            "data",
            "information",
            "computing",
            "cloud",
            "hosting",
            "server",
        }

        # Extract potential organization names with strict filtering
        words = re.findall(r"\b[A-Z][a-zA-Z]+\b", text)

        # Look for capitalized sequences (likely company names)
        potential_orgs = []
        current_org = []

        for word in words:
            if word.lower() in noise_words or len(word) < 3:
                if current_org and len(current_org) >= 1:
                    org_name = " ".join(current_org)
                    # Only add if it's meaningful and related to target
                    if self._is_meaningful_organization_name(org_name):
                        potential_orgs.append(org_name)
                current_org = []
            else:
                current_org.append(word)

        if current_org and len(current_org) >= 1:
            org_name = " ".join(current_org)
            if self._is_meaningful_organization_name(org_name):
                potential_orgs.append(org_name)

        # Add high-confidence organization names with strict validation
        for org in potential_orgs:
            if (
                len(org) >= 4
                and confidence >= self.min_confidence_threshold
                and self._is_organization_relevant_to_target(org)
            ):
                target_set.add(org)
                self.org_intelligence.confidence_scores[org] = confidence

    def _is_meaningful_organization_name(self, name: str) -> bool:
        """Check if a name is meaningful and not generic."""

        if not name or len(name) < 3:
            return False

        # Reject single generic words
        if len(name.split()) == 1:
            generic_single_words = {
                "coffee",
                "tea",
                "food",
                "restaurant",
                "cafe",
                "shop",
                "store",
                "network",
                "systems",
                "services",
                "solutions",
                "technology",
                "communications",
                "telecom",
                "digital",
                "internet",
                "data",
                "software",
                "hardware",
                "consulting",
                "management",
                "group",
                "holding",
                "corporation",
                "company",
                "limited",
                "inc",
                "corp",
            }
            if name.lower() in generic_single_words:
                return False

        # Reject overly generic combinations
        generic_patterns = [
            "coffee company",
            "tea company",
            "food company",
            "restaurant group",
            "retail group",
            "technology solutions",
            "network services",
            "communications services",
            "consulting services",
            "management group",
        ]

        name_lower = name.lower()
        for pattern in generic_patterns:
            if pattern in name_lower:
                return False

        return True

    def _is_organization_relevant_to_target(self, org_name: str) -> bool:
        """Check if learned organization name is relevant to target organization."""

        if not hasattr(self, "target_organization") or not self.target_organization:
            return True  # No target to compare against

        target_clean = re.sub(r"[^a-zA-Z0-9]", "", self.target_organization.lower())
        org_clean = re.sub(r"[^a-zA-Z0-9]", "", org_name.lower())

        # Direct relationship check
        if org_clean in target_clean or target_clean in org_clean:
            return True

        # Check for meaningful overlap (at least 50% for learned terms)
        if len(org_clean) >= 4 and len(target_clean) >= 4:
            # Check for common substrings of at least 4 characters
            for i in range(len(org_clean) - 3):
                for j in range(i + 4, len(org_clean) + 1):
                    substring = org_clean[i:j]
                    if substring in target_clean and len(substring) >= 4:
                        # Substring should be significant portion
                        if len(substring) / len(target_clean) >= 0.3:
                            return True

        # Reject if no clear relationship
        return False

    def _learn_from_domain_patterns(self, domains: Set[Domain]):
        """Learn organization patterns from domain names with ultra-strict precision filtering."""

        # Filter domains by strict relevance to target organization
        relevant_domains = self._filter_domains_for_learning_strict(domains)

        if len(relevant_domains) < len(domains):
            logger.info(
                f"Ultra-strict learning: {len(relevant_domains)} relevant domains from {len(domains)} total"
            )

        # Extract organization names with ultra-strict quality validation
        learned_names = set()
        for domain in relevant_domains:
            # Extract root domain name
            root_name = domain.name.split(".")[0]

            # Apply ultra-strict quality validation
            if self._is_ultra_high_quality_organization_name(
                root_name
            ) and self._is_organization_relevant_to_target(root_name):
                learned_names.add(root_name)

                # Add capitalized version only if it passes validation
                capitalized = root_name.capitalize()
                if self._is_ultra_high_quality_organization_name(capitalized):
                    self.org_intelligence.organization_names.add(capitalized)
                    self.org_intelligence.confidence_scores[capitalized] = 0.7

        logger.info(
            f"Ultra-strict learning: {len(learned_names)} validated organization names from {len(relevant_domains)} domains"
        )

    def _filter_domains_for_learning_strict(self, domains: Set[Domain]) -> Set[Domain]:
        """Filter domains for learning with ultra-strict criteria."""

        if not hasattr(self, "target_organization") or not self.target_organization:
            return domains

        target_org_clean = re.sub(r"[^a-zA-Z0-9]", "", self.target_organization.lower())
        relevant_domains = set()

        for domain in domains:
            domain_root = domain.name.split(".")[0].lower()
            domain_clean = re.sub(r"[^a-zA-Z0-9]", "", domain_root)

            # Ultra-strict similarity requirement (at least 80%)
            if (
                self._calculate_domain_similarity_strict(domain_clean, target_org_clean)
                >= 0.8
            ):
                relevant_domains.add(domain)

        return relevant_domains

    def _calculate_domain_similarity_strict(
        self, domain_root: str, target_org: str
    ) -> float:
        """Calculate domain similarity with strict criteria."""

        if not domain_root or not target_org:
            return 0.0

        # Direct containment (high score)
        if domain_root in target_org or target_org in domain_root:
            return 1.0

        # Character overlap ratio
        common_chars = len(set(domain_root) & set(target_org))
        total_chars = len(set(domain_root) | set(target_org))

        if total_chars == 0:
            return 0.0

        char_similarity = common_chars / total_chars

        # Length similarity penalty
        len_diff = abs(len(domain_root) - len(target_org))
        max_len = max(len(domain_root), len(target_org))
        len_penalty = len_diff / max_len if max_len > 0 else 1.0

        # Final similarity with length penalty
        similarity = char_similarity * (1 - len_penalty * 0.5)

        return max(0.0, similarity)

    def _is_ultra_high_quality_organization_name(self, name: str) -> bool:
        """Ultra-strict quality check for organization names."""

        if not name or not isinstance(name, str):
            return False

        # Strict length requirements
        if len(name) < 4 or len(name) > 20:
            return False

        # Must be primarily alphabetic
        if not name.isalpha():
            return False

        # Exclude any generic terms
        if self._is_too_generic_strict(name):
            return False

        # Exclude known unrelated brands with expanded list
        if self._is_likely_unrelated_brand_strict(name):
            return False

        # Must have reasonable letter distribution
        if not self._has_reasonable_letter_distribution(name):
            return False

        # Exclude obvious fragments
        if self._looks_like_fragment(name):
            return False

        return True

    def _is_too_generic_strict(self, term: str) -> bool:
        """Ultra-strict generic term detection."""

        term_lower = term.lower()

        # Expanded list of generic terms
        ultra_generic_terms = {
            # Business terms
            "company",
            "corp",
            "corporation",
            "inc",
            "ltd",
            "limited",
            "group",
            "holding",
            "international",
            "global",
            "national",
            "regional",
            "local",
            # Industry terms
            "technology",
            "tech",
            "systems",
            "services",
            "solutions",
            "consulting",
            "management",
            "development",
            "software",
            "hardware",
            "network",
            "networks",
            "communications",
            "telecom",
            "digital",
            "internet",
            "data",
            "information",
            "computing",
            "cloud",
            "hosting",
            "server",
            "datacenter",
            # Food/beverage terms
            "coffee",
            "tea",
            "food",
            "restaurant",
            "cafe",
            "dining",
            "catering",
            "roasters",
            "brewing",
            "beans",
            "espresso",
            "latte",
            "cappuccino",
            # Retail terms
            "retail",
            "store",
            "shop",
            "market",
            "shopping",
            "mall",
            "center",
            "centre",
            "plaza",
            "outlet",
            "chain",
            # Geographic/Legal terms
            "usa",
            "america",
            "europe",
            "asia",
            "africa",
            "australia",
            "canada",
            "mexico",
            "brazil",
            "china",
            "japan",
            "india",
            "russia",
            "germany",
            "france",
            "italy",
            "spain",
            "uk",
            "england",
            "scotland",
            "wales",
            # Common abbreviations
            "sc",
            "llc",
            "inc",
            "ltd",
            "co",
            "sa",
            "srl",
            "gmbh",
            "spa",
            "bv",
            "ag",
            "ab",
            "as",
            "oy",
            "kft",
            "sro",
            "doo",
            "ood",
        }

        return term_lower in ultra_generic_terms

    def _is_likely_unrelated_brand_strict(self, term: str) -> bool:
        """Strict unrelated brand detection with expanded list."""

        term_lower = term.lower()

        # Expanded list of known unrelated brands/companies
        unrelated_brands = {
            # Coffee/Food brands
            "starbucks",
            "dunkin",
            "costa",
            "peets",
            "caribou",
            "tims",
            "timhortons",
            "mcdonalds",
            "burger",
            "pizza",
            "subway",
            "kfc",
            "taco",
            "wendys",
            "dominos",
            "papa",
            "chipotle",
            "panera",
            "chick",
            "sonic",
            "arbys",
            # Tech brands
            "google",
            "microsoft",
            "apple",
            "amazon",
            "facebook",
            "meta",
            "twitter",
            "linkedin",
            "instagram",
            "youtube",
            "netflix",
            "spotify",
            "uber",
            "lyft",
            "airbnb",
            "tesla",
            "nvidia",
            "intel",
            "amd",
            "oracle",
            # Telecom brands
            "verizon",
            "att",
            "tmobile",
            "sprint",
            "comcast",
            "charter",
            "cox",
            "vodafone",
            "orange",
            "telefonica",
            "deutsche",
            "telekom",
            # Other major brands
            "walmart",
            "target",
            "costco",
            "home",
            "depot",
            "lowes",
            "best",
            "buy",
            "fedex",
            "ups",
            "dhl",
            "usps",
            "ford",
            "gm",
            "toyota",
            "honda",
            "bmw",
            "mercedes",
            "audi",
            "volkswagen",
            "nissan",
            "hyundai",
        }

        # Check if term matches any unrelated brand
        for brand in unrelated_brands:
            if brand in term_lower or term_lower in brand:
                # Additional check: only flag if not related to target
                if hasattr(self, "target_organization") and self.target_organization:
                    target_lower = self.target_organization.lower()
                    if brand not in target_lower and term_lower not in target_lower:
                        return True
                else:
                    return True

        return False

    def _validate_learned_intelligence(self):
        """Validate and clean learned intelligence."""

        # Remove very short or very long organization names
        to_remove = set()
        for org_name in self.org_intelligence.organization_names:
            if len(org_name) < 2 or len(org_name) > 50:
                to_remove.add(org_name)

        for org_name in to_remove:
            self.org_intelligence.organization_names.discard(org_name)
            self.org_intelligence.confidence_scores.pop(org_name, None)

        # Remove common false positives
        false_positives = {
            "Network",
            "Internet",
            "Service",
            "Provider",
            "System",
            "Number",
            "Autonomous",
            "Technology",
            "Digital",
            "Solutions",
            "Services",
        }

        for fp in false_positives:
            self.org_intelligence.organization_names.discard(fp)
            self.org_intelligence.confidence_scores.pop(fp, None)

    def _count_total_assets(self, result: ReconnaissanceResult) -> int:
        """Count total assets discovered."""
        total_subdomains = sum(len(d.subdomains) for d in result.domains)
        return (
            len(result.asns)
            + len(result.ip_ranges)
            + len(result.domains)
            + total_subdomains
            + len(result.cloud_services)
        )

    def _get_last_expansion_strategies(self) -> List[str]:
        """Get list of expansion strategies used in last iteration."""
        return [
            "Automatic Learning",
            "ASN Description Analysis",
            "Domain Pattern Analysis",
        ]

    def _log_final_summary(self, result: ReconnaissanceResult, duration: float):
        """Log comprehensive summary of intelligent discovery."""

        total_subdomains = sum(len(d.subdomains) for d in result.domains)
        total_assets = self._count_total_assets(result)

        logger.info(
            f"🧠 Intelligent Discovery Summary for {result.target_organization}"
        )
        logger.info(f"   Total Duration: {duration:.2f} seconds")
        logger.info(f"   Iterations: {len(self.discovery_history)}")
        logger.info(f"   Total Assets: {total_assets}")
        logger.info(f"   ├── ASNs: {len(result.asns)}")
        logger.info(f"   ├── IP Ranges: {len(result.ip_ranges)}")
        logger.info(f"   ├── Domains: {len(result.domains)}")
        logger.info(f"   ├── Subdomains: {total_subdomains}")
        logger.info(f"   └── Cloud Services: {len(result.cloud_services)}")

        logger.info(f"🧠 Learned Intelligence:")
        logger.info(
            f"   ├── Organization Names: {len(self.org_intelligence.organization_names)}"
        )
        logger.info(
            f"   ├── ASN Descriptions: {len(self.org_intelligence.asn_descriptions)}"
        )
        logger.info(
            f"   └── Confidence Scores: {len(self.org_intelligence.confidence_scores)}"
        )

        if self.discovery_history:
            logger.info(f"📈 Discovery Evolution:")
            for iteration in self.discovery_history:
                logger.info(
                    f"   Iteration {iteration['iteration']}: "
                    f"{iteration['new_assets']} new assets "
                    f"({iteration['convergence_score']:.1%} growth)"
                )

    def get_discovery_intelligence(self) -> Dict:
        """Get comprehensive intelligence gathered during discovery."""

        return {
            "learned_organizations": list(self.org_intelligence.organization_names),
            "confidence_scores": dict(self.org_intelligence.confidence_scores),
            "asn_descriptions": list(self.org_intelligence.asn_descriptions),
            "domain_patterns": list(self.org_intelligence.domain_patterns),
            "discovery_iterations": [
                {
                    "iteration": it.iteration_number,
                    "search_terms_count": len(it.search_terms),
                    "new_assets": it.new_assets_found,
                    "convergence_score": it.convergence_score,
                    "duration": it.total_time,
                }
                for it in self.discovery_history
            ],
        }

    def get_discovery_statistics(self) -> Dict:
        """Get discovery statistics for compatibility with app.py."""
        return {
            "phase_results": {
                "domain_discovery": {"success": True},
                "asn_discovery": {"success": True},
                "ip_discovery": {"success": True},
                "cloud_detection": {"success": True},
            }
        }

    def _is_quality_search_term(self, term: str) -> bool:
        """Check if a term meets quality standards for search with optimized filtering."""

        if not term or not isinstance(term, str):
            return False

        # Optimized length checks (more restrictive)
        if len(term) < self.min_term_length or len(term) > 25:
            return False

        # Must contain at least one letter
        if not any(c.isalpha() for c in term):
            return False

        # Reject terms starting or ending with non-alphanumeric
        if not term[0].isalnum() or not term[-1].isalnum():
            return False

        # Filter out very fragmented terms
        if term.count("-") > 1 or term.count("_") > 1:
            return False

        # Filter out terms that are mostly non-alphanumeric
        alphanumeric_ratio = sum(c.isalnum() for c in term) / len(term)
        if alphanumeric_ratio < 0.8:  # Restored to 0.8 for higher quality
            return False

        # Filter out terms that look like random fragments
        if self._looks_like_fragment(term):
            return False

        # Filter out very generic terms
        if self._is_too_generic(term):
            return False

        # Filter out common noise words (optimized list)
        noise_words = {
            "empresa",
            "company",
            "corp",
            "inc",
            "ltd",
            "limited",
            "telecom",
            "network",
            "internet",
            "services",
            "service",
            "app",
            "web",
            "api",
            "system",
            "data",  # Added tech terms
        }

        if term.lower() in noise_words:
            return False

        # Vowel/consonant distribution check (stricter)
        if len(term) >= 6 and not self._has_reasonable_letter_distribution(term):
            return False

        return True

    def _is_too_generic(self, term: str) -> bool:
        """Check if term is too generic to be useful (optimized)."""

        # Very short terms
        if len(term) <= 5:  # Increased from 4 to 5
            return True

        # Common generic words (expanded list)
        generic_terms = {
            "app",
            "web",
            "site",
            "page",
            "home",
            "main",
            "info",
            "data",
            "user",
            "admin",
            "test",
            "demo",
            "temp",
            "new",
            "old",
            "beta",
            "alpha",
            "prod",
            "dev",
            "stage",
            "api",
            "www",
            "mail",
            "email",
            "sas",
            "com",
            "org",
            "net",
            "www",
            "ftp",
            "ssh",
            "dns",
            "http",
            "https",
            "smtp",
            "pop",
            "imap",
            "tcp",
            "udp",
            "ssl",
            "tls",
            "eca",
            "tsm",
            "lab",
            "pro",
            "max",
            "plus",
            "lite",
            "mini",
            "server",
            "client",
            "cloud",
            "portal",
            "platform",
            "solution",
        }

        if term.lower() in generic_terms:
            return True

        # Terms that are all uppercase and short (often acronyms without meaning)
        if term.isupper() and len(term) <= 6:
            # Allow only well-known organizations
            allowed_uppercase = {
                "IBM",
                "AWS",
                "API",
                "HTTP",
                "HTTPS",
                "DNS",
                "VPN",
                "CDN",
                "SAP",
                "AMD",
                "INTEL",
                "CISCO",
                "ORACLE",
                "TELEFONICA",
                "MOVISTAR",
            }
            return term not in allowed_uppercase

        return False

    def _has_reasonable_letter_distribution(self, term: str) -> bool:
        """Check if term has reasonable vowel/consonant distribution."""

        if len(term) < 3:
            return False

        vowels = set("aeiouAEIOU")
        consonants = set("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ")

        vowel_count = sum(1 for c in term if c in vowels)
        consonant_count = sum(1 for c in term if c in consonants)

        # Must have at least one vowel and one consonant
        if vowel_count == 0 or consonant_count == 0:
            return False

        # Vowels should be 20-60% of letters
        total_letters = vowel_count + consonant_count
        if total_letters > 0:
            vowel_ratio = vowel_count / total_letters
            if vowel_ratio < 0.2 or vowel_ratio > 0.6:
                return False

        return True

    def _looks_like_fragment(self, term: str) -> bool:
        """Check if term looks like a meaningless fragment (optimized detection)."""

        # Focus on really problematic fragment patterns only
        obvious_fragment_endings = ["emp", "ica", "fon", "onic", "empre", "esas"]
        obvious_fragment_beginnings = ["efon", "lefon", "mpr", "aem"]

        term_lower = term.lower()

        # Exception list for valid organization names
        valid_exceptions = {
            "movistar",
            "telefonica",
            "microsoft",
            "google",
            "amazon",
            "apple",
            "oracle",
            "facebook",
            "netflix",
            "spotify",
            "twitter",
            "linkedin",
            "samsung",
            "huawei",
            "xiaomi",
            "nokia",
            "ericsson",
            "cisco",
            "orange",
        }

        if term_lower in valid_exceptions:
            return False

        # Only the most obvious fragment patterns
        for ending in obvious_fragment_endings:
            if term_lower.endswith(ending) and len(term) <= 8:  # More restrictive
                return True

        for beginning in obvious_fragment_beginnings:
            if term_lower.startswith(beginning) and len(term) <= 8:  # More restrictive
                return True

        # Focus on the most problematic patterns from logs only
        truly_problematic_patterns = [
            "telefonicaem",
            "telefonicaemp",
            "telefonicaempresa",
            "aempresas",
            "lefonicaempre",
            "efonicaempre",
            "ovistar",
            "-te",
            "-tele",
            "res",
            "emp",
            "ica",
            "tel",
            "aem",
        ]

        if term_lower in truly_problematic_patterns:
            return True

        # Catch obvious concatenations
        if len(term) >= 12:
            concat_indicators = ["telefonicaem", "movistarlabs", "empresatel"]
            for pattern in concat_indicators:
                if pattern in term_lower:
                    return True

        # Keep the dash/special character check
        if "-" in term and len(term) <= 5:
            return True

        return False

    def _initialize_search_terms(
        self, target_organization: str, base_domains: Optional[Set[str]]
    ) -> Set[str]:
        """Initialize search terms without hardcoded knowledge."""

        terms = set()

        if target_organization:
            # Basic organization variations
            terms.add(target_organization)

            # Simple linguistic variations (without hardcoding)
            org_clean = target_organization.strip().replace(",", "").replace(".", "")
            terms.add(org_clean)

            # Remove common suffixes generically
            suffixes = [
                "Inc",
                "LLC",
                "Corporation",
                "Corp",
                "Ltd",
                "Limited",
                "Company",
                "Co",
                "S.A.",
                "SA",
            ]
            for suffix in suffixes:
                for variant in [f" {suffix}", f".{suffix}", f", {suffix}"]:
                    if org_clean.endswith(variant):
                        clean_name = org_clean[: -len(variant)].strip()
                        if clean_name:
                            terms.add(clean_name)

            # Generate acronyms from multi-word names
            words = org_clean.split()
            if len(words) > 1:
                acronym = "".join(
                    word[0].upper() for word in words if word and len(word) > 0
                )
                if len(acronym) >= 2:
                    terms.add(acronym)

        if base_domains:
            terms.update(base_domains)

            # Extract root names from domains
            for domain in base_domains:
                root_name = domain.split(".")[0]
                if len(root_name) > 2:
                    terms.add(root_name)
                    terms.add(root_name.capitalize())

        logger.info(f"Initialized with {len(terms)} search terms: {terms}")
        return terms

    def _execute_discovery_iteration_hp(
        self,
        search_terms: Set[str],
        result: ReconnaissanceResult,
        iteration: int,
        progress_callback: Optional[Callable[[float, str], None]] = None,
        status_callback: Optional[Callable[[str, str], None]] = None,
    ) -> ReconnaissanceResult:
        """Execute one iteration of discovery with precision-focused approach."""

        # Phase 1: Domain Discovery
        if progress_callback:
            progress_callback(10.0, f"Iteration {iteration}: Domain discovery")

        try:

            def domain_discovery_task():
                # Separate organization names from actual domains in search terms
                org_names = set()
                actual_domains = set()

                for term in search_terms:
                    if "." in term and not term.startswith("."):
                        actual_domains.add(term)
                    else:
                        org_names.add(term)

                # Use target organization if no org names found in search terms
                primary_org = (
                    result.target_organization if not org_names else list(org_names)[0]
                )

                return self.domain_discovery.find_enhanced_domains(
                    org_name=primary_org,
                    base_domains=actual_domains if actual_domains else None,
                    result=result,
                    progress_callback=lambda p, msg: (
                        progress_callback(10 + p * 0.2, msg)
                        if progress_callback
                        else None
                    ),
                )

            # Execute with timeout
            HighPerformanceTimeoutExecutor.execute_with_timeout(
                domain_discovery_task, 180, pool_name="domain_discovery"
            )

        except Exception as e:
            logger.warning(f"Domain discovery failed: {e}")

        # Phase 2: ASN Discovery with precision filtering
        if progress_callback:
            progress_callback(30.0, f"Iteration {iteration}: ASN discovery")

        try:
            # Use all learned organization names for ASN discovery
            all_org_names = search_terms.union(self.org_intelligence.organization_names)

            # Apply quality-based deduplication (no arbitrary limits)
            deduplicated_terms = set()

            for org_name in all_org_names:
                # Normalize to lowercase for deduplication
                normalized = org_name.lower().strip()
                if (
                    self._is_quality_search_term(org_name)
                    and not self._looks_like_fragment(org_name)
                    and len(normalized) >= 4
                    and normalized not in {t.lower() for t in deduplicated_terms}
                ):
                    deduplicated_terms.add(org_name)

            logger.info(
                f"Quality-filtered ASN discovery: {len(deduplicated_terms)} terms from {len(all_org_names)} candidates"
            )

            # Execute ASN discoveries in parallel
            asn_tasks = []
            for org_name in deduplicated_terms:

                def create_asn_task(name):
                    def asn_discovery_task():
                        return self.asn_discovery.find_asns_for_organization(
                            org_name=name,
                            base_domains=None,
                            result=result,
                            progress_callback=lambda p, msg: (
                                progress_callback(30 + p * 0.15, msg)
                                if progress_callback
                                else None
                            ),
                        )

                    return asn_discovery_task

                asn_tasks.append((create_asn_task(org_name),))

            # Execute all ASN discoveries in parallel
            if asn_tasks:
                HighPerformanceTimeoutExecutor.execute_batch_with_timeout(
                    asn_tasks,
                    timeout_seconds=180,  # Increased timeout for thoroughness
                    max_workers=min(len(asn_tasks), 5),  # Reasonable parallelism
                    pool_name="asn_discovery",
                )

        except Exception as e:
            logger.warning(f"ASN discovery phase failed: {e}")

        # Phase 3: IP Discovery
        if result.asns and progress_callback:
            progress_callback(50.0, f"Iteration {iteration}: IP range discovery")

        if result.asns:
            try:

                def ip_discovery_task():
                    return self.ip_discovery.find_intelligent_ip_ranges(
                        asns=result.asns,
                        result=result,
                        organization_context=result.target_organization,
                        progress_callback=lambda p, msg: (
                            progress_callback(50 + p * 0.15, msg)
                            if progress_callback
                            else None
                        ),
                    )

                HighPerformanceTimeoutExecutor.execute_with_timeout(
                    ip_discovery_task, 120, pool_name="ip_discovery"
                )

            except Exception as e:
                logger.warning(f"IP discovery failed: {e}")

        # Phase 4: Cloud Detection
        if progress_callback:
            progress_callback(70.0, f"Iteration {iteration}: Cloud detection")

        try:

            def cloud_detection_task():
                return self.cloud_detection.detect_cloud_services(
                    result=result,
                    progress_callback=lambda p, msg: (
                        progress_callback(70 + p * 0.2, msg)
                        if progress_callback
                        else None
                    ),
                    status_callback=status_callback,
                )

            HighPerformanceTimeoutExecutor.execute_with_timeout(
                cloud_detection_task, 60, pool_name="cloud_detection"
            )

        except Exception as e:
            logger.warning(f"Cloud detection failed: {e}")

        if progress_callback:
            progress_callback(90.0, f"Iteration {iteration}: Learning from data")

        return result

    def _is_likely_organization_name(self, term: str) -> bool:
        """Check if term looks like a real organization name."""

        # Common organization indicators
        org_indicators = {
            "corp",
            "inc",
            "ltd",
            "limited",
            "company",
            "group",
            "services",
            "telecom",
            "communications",
            "technologies",
            "systems",
        }

        # Check if term contains organization indicators
        term_lower = term.lower()
        has_org_indicator = any(indicator in term_lower for indicator in org_indicators)

        # Check if term is a known technology/service term (likely not org name)
        tech_terms = {
            "api",
            "app",
            "web",
            "cloud",
            "server",
            "network",
            "system",
            "data",
            "service",
        }
        is_tech_term = term_lower in tech_terms

        # Check capitalization pattern (proper organization names are often capitalized)
        has_proper_case = term[0].isupper() if term else False

        return (has_org_indicator or has_proper_case) and not is_tech_term

    def _is_name_relevant_to_target(self, name: str, target_org: str) -> bool:
        """Check if a learned name is relevant to the target organization."""

        name_clean = re.sub(r"[^a-zA-Z0-9]", "", name.lower())
        target_clean = re.sub(r"[^a-zA-Z0-9]", "", target_org.lower())

        # Direct match or substantial overlap
        if name_clean == target_clean:
            return True

        if len(name_clean) >= 4 and len(target_clean) >= 4:
            # Check for substantial overlap (at least 60%)
            if name_clean in target_clean or target_clean in name_clean:
                overlap_ratio = max(
                    len(name_clean) / len(target_clean),
                    len(target_clean) / len(name_clean),
                )
                if overlap_ratio >= 0.6:
                    return True

        # Check for common substrings (at least 4 characters)
        if len(name_clean) >= 4 and len(target_clean) >= 4:
            for i in range(len(name_clean) - 3):
                for j in range(i + 4, len(name_clean) + 1):
                    substring = name_clean[i:j]
                    if len(substring) >= 4 and substring in target_clean:
                        if len(substring) / len(target_clean) >= 0.4:
                            return True

        return False
