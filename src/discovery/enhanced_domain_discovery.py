"""Enhanced Domain Discovery with multiple sources and intelligent filtering."""

import logging
import re
import asyncio
from typing import Set, Optional, Callable, List, Dict, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

from src.core.models import Domain, Subdomain, ReconnaissanceResult
from src.config.settings import get_settings
from src.discovery.domain_discovery import _query_crtsh, _check_and_query_hackertarget

logger = logging.getLogger(__name__)


@dataclass
class DomainCandidate:
    """Represents a domain candidate with relevance scoring."""

    fqdn: str
    domain_type: str  # 'base', 'subdomain', 'wildcard'
    relevance_score: float
    sources: List[str]
    confidence: float
    reasons: List[str]


class EnhancedDomainDiscovery:
    """Enhanced domain discovery with multiple sources and intelligent filtering."""

    def __init__(self, config=None):
        self.config = config or get_settings()
        self.max_subdomains_per_domain = self.config.recon.max_subdomains_per_domain

        # Subdomain relevance patterns
        self.high_value_patterns = [
            r"^(www|mail|smtp|imap|pop3|ftp|sftp|ssh|vpn|api|admin|portal|dashboard)\.",
            r"^(dev|staging|test|prod|production|beta|alpha)\.",
            r"^(app|apps|service|services|web|mobile)\.",
            r"^(secure|auth|sso|oauth|login|signin)\.",
            r"^(cdn|static|assets|media|images|files)\.",
            r"^(db|database|sql|mysql|postgres|mongo)\.",
            r"^(backup|archive|storage|data)\.",
            r"^(monitor|status|health|metrics|logs)\.",
            r"^(git|repo|code|ci|cd|build|deploy)\.",
            r"^(support|help|docs|documentation|wiki)\.",
        ]

        self.low_value_patterns = [
            r"^ssl\d+\.",
            r"^test\d+\.",
            r"^temp\d+\.",
            r"^[a-f0-9]{8,}\.",
            r"^[0-9]{4,}\.",
            r"^cache[0-9]*\.",
            r"^cdn[0-9]*\.",
            r"^edge[0-9]*\.",
            r"^node[0-9]*\.",
            r"^server[0-9]*\.",
        ]

    def find_enhanced_domains(
        self,
        org_name: Optional[str],
        base_domains: Optional[Set[str]],
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ):
        """Enhanced domain discovery with intelligent filtering."""

        logger.info(f"🌍 Enhanced domain discovery for: {org_name}")

        if progress_callback:
            progress_callback(0.0, "Starting enhanced domain discovery...")

        try:
            # Phase 1: Multi-source domain collection
            domain_candidates = self._collect_domain_candidates(
                org_name, base_domains, result, progress_callback
            )

            # Phase 2: Intelligent filtering and scoring
            filtered_candidates = self._filter_and_score_domains(
                domain_candidates, org_name, base_domains
            )

            # Phase 3: Smart DNS resolution
            resolved_domains = self._smart_dns_resolution(
                filtered_candidates, result, progress_callback
            )

            # Phase 4: Final domain organization
            final_domains = self._organize_final_domains(resolved_domains)

            # Add to result
            for domain in final_domains:
                result.add_domain(domain)

            total_subdomains = sum(len(d.subdomains) for d in final_domains)
            logger.info(
                f"✅ Enhanced domain discovery complete: {len(final_domains)} domains, {total_subdomains} subdomains"
            )

            if progress_callback:
                progress_callback(
                    100.0,
                    f"Enhanced domain discovery complete ({len(final_domains)} domains)",
                )

        except Exception as e:
            logger.error(f"Enhanced domain discovery failed: {e}")
            raise

    def _collect_domain_candidates(
        self,
        org_name: Optional[str],
        base_domains: Optional[Set[str]],
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> List[DomainCandidate]:
        """Collect domain candidates from multiple sources."""

        candidates = []

        try:
            # Source 1: Certificate Transparency (crt.sh)
            ct_candidates = self._collect_from_certificate_transparency(
                org_name, base_domains, result
            )
            candidates.extend(ct_candidates)

            if progress_callback:
                progress_callback(
                    20.0, f"Certificate transparency: {len(ct_candidates)} candidates"
                )

            # Source 2: Passive DNS (HackerTarget)
            if base_domains:
                pdns_candidates = self._collect_from_passive_dns(base_domains, result)
                candidates.extend(pdns_candidates)

            if progress_callback:
                progress_callback(
                    40.0, f"Passive DNS: {len(candidates)} total candidates"
                )

            # Source 3: Search engine dorking (placeholder)
            # Future implementation: Google/Bing search queries

            # Source 4: DNS brute force (placeholder)
            # Future implementation: Common subdomain wordlists

            # Source 5: SSL certificate enumeration (placeholder)
            # Future implementation: Shodan/Censys SSL certificate data

            logger.info(
                f"Collected {len(candidates)} domain candidates from all sources"
            )
            return candidates

        except Exception as e:
            logger.error(f"Domain candidate collection failed: {e}")
            raise

    def _collect_from_certificate_transparency(
        self,
        org_name: Optional[str],
        base_domains: Optional[Set[str]],
        result: ReconnaissanceResult,
    ) -> List[DomainCandidate]:
        """Collect domains from Certificate Transparency logs."""

        candidates = []
        queries = set()

        # Generate CT queries
        if base_domains:
            for domain in base_domains:
                queries.add(f"%.{domain}")  # Subdomain search
                queries.add(domain)  # Direct domain search

        if org_name and not base_domains:
            queries.add(org_name)

        # Execute CT queries
        for query in queries:
            try:
                ct_domains = _query_crtsh(query, result)
                for fqdn in ct_domains:
                    candidate = self._create_domain_candidate(
                        fqdn,
                        sources=["Certificate Transparency"],
                        confidence=0.8,
                        reasons=[f'Found in CT logs via query "{query}"'],
                    )
                    candidates.append(candidate)
            except Exception as e:
                logger.warning(f"CT query failed for '{query}': {e}")

        return candidates

    def _collect_from_passive_dns(
        self, base_domains: Set[str], result: ReconnaissanceResult
    ) -> List[DomainCandidate]:
        """Collect domains from Passive DNS sources."""

        candidates = []

        for domain in base_domains:
            try:
                pdns_domains = _check_and_query_hackertarget(domain, result)
                for fqdn in pdns_domains:
                    candidate = self._create_domain_candidate(
                        fqdn,
                        sources=["Passive DNS"],
                        confidence=0.7,
                        reasons=[f'Found via Passive DNS for "{domain}"'],
                    )
                    candidates.append(candidate)
            except Exception as e:
                logger.warning(f"Passive DNS query failed for '{domain}': {e}")

        return candidates

    def _create_domain_candidate(
        self, fqdn: str, sources: List[str], confidence: float, reasons: List[str]
    ) -> DomainCandidate:
        """Create a domain candidate with initial classification."""

        # Determine domain type
        domain_type = self._classify_domain_type(fqdn)

        # Calculate initial relevance score
        relevance_score = self._calculate_initial_domain_relevance(fqdn, domain_type)

        return DomainCandidate(
            fqdn=fqdn.lower().strip(),
            domain_type=domain_type,
            relevance_score=relevance_score,
            sources=sources,
            confidence=confidence,
            reasons=reasons,
        )

    def _classify_domain_type(self, fqdn: str) -> str:
        """Classify domain as base, subdomain, or wildcard."""

        if "*" in fqdn:
            return "wildcard"

        parts = fqdn.split(".")
        if len(parts) <= 2:
            return "base"
        else:
            return "subdomain"

    def _calculate_initial_domain_relevance(self, fqdn: str, domain_type: str) -> float:
        """Calculate initial relevance score for a domain."""

        base_scores = {"base": 0.9, "subdomain": 0.7, "wildcard": 0.3}

        score = base_scores.get(domain_type, 0.5)

        if domain_type == "subdomain":
            # Check for high-value patterns
            for pattern in self.high_value_patterns:
                if re.match(pattern, fqdn, re.IGNORECASE):
                    score += 0.2
                    break

            # Check for low-value patterns
            for pattern in self.low_value_patterns:
                if re.match(pattern, fqdn, re.IGNORECASE):
                    score -= 0.3
                    break

        return max(0.0, min(1.0, score))

    def _filter_and_score_domains(
        self,
        candidates: List[DomainCandidate],
        org_name: Optional[str],
        base_domains: Optional[Set[str]],
    ) -> List[DomainCandidate]:
        """Filter and enhance scoring of domain candidates with precision-focused filtering."""

        # Group by FQDN and merge duplicates
        grouped = defaultdict(list)
        for candidate in candidates:
            grouped[candidate.fqdn].append(candidate)

        filtered = []

        for fqdn, group in grouped.items():
            # Merge candidates for the same FQDN
            merged_candidate = self._merge_domain_candidates(group)

            # Enhanced scoring with precision filtering
            enhanced_score = self._enhance_domain_relevance_precise(
                merged_candidate, org_name, base_domains
            )

            # Apply PRECISION-BASED filtering instead of arbitrary thresholds
            if self._is_domain_relevant_to_organization(
                merged_candidate, org_name, base_domains
            ):
                merged_candidate.relevance_score = enhanced_score
                filtered.append(merged_candidate)
            else:
                logger.debug(
                    f"Filtered domain {fqdn} - not relevant to organization (score: {enhanced_score:.2f})"
                )

        # Sort by relevance but DON'T apply arbitrary limits
        filtered.sort(key=lambda c: c.relevance_score, reverse=True)

        logger.info(
            f"Precision filtering: {len(filtered)} relevant domains from {len(candidates)} candidates"
        )
        return filtered

    def _merge_domain_candidates(
        self, candidates: List[DomainCandidate]
    ) -> DomainCandidate:
        """Merge multiple candidates for the same FQDN."""

        if len(candidates) == 1:
            return candidates[0]

        # Use the best candidate as base
        best = max(candidates, key=lambda c: c.confidence)

        # Merge sources and reasons
        all_sources = []
        all_reasons = []
        for candidate in candidates:
            all_sources.extend(candidate.sources)
            all_reasons.extend(candidate.reasons)

        # Enhanced confidence for multiple sources
        enhanced_confidence = min(
            best.confidence + (len(set(all_sources)) - 1) * 0.1, 1.0
        )

        return DomainCandidate(
            fqdn=best.fqdn,
            domain_type=best.domain_type,
            relevance_score=best.relevance_score,
            sources=list(set(all_sources)),
            confidence=enhanced_confidence,
            reasons=all_reasons,
        )

    def _enhance_domain_relevance_precise(
        self,
        candidate: DomainCandidate,
        org_name: Optional[str],
        base_domains: Optional[Set[str]],
    ) -> float:
        """Enhanced domain relevance scoring focused on precision, not arbitrary limits."""

        score = candidate.relevance_score

        # 1. ORGANIZATION NAME MATCHING - Core relevance factor
        if org_name:
            org_match_score = self._calculate_organization_match_score(
                candidate.fqdn, org_name
            )
            if org_match_score > 0:
                score += org_match_score * 0.4  # Strong boost for org matches
            elif candidate.domain_type == "base" and org_match_score == 0:
                # Base domains MUST match organization to some degree
                score = max(0.1, score - 0.5)

        # 2. BASE DOMAIN CORRELATION - Infrastructure relationship
        if base_domains:
            base_correlation = self._calculate_base_domain_correlation(
                candidate.fqdn, base_domains
            )
            score += base_correlation * 0.3

        # 3. MULTI-SOURCE CONFIDENCE - Discovery reliability
        if len(candidate.sources) > 1:
            score += 0.15  # Boost for multiple sources

        # 4. CERTIFICATE TRANSPARENCY CONFIDENCE - High reliability source
        if "Certificate Transparency" in candidate.sources:
            score += 0.1

        # 5. SUBDOMAIN VALUE ASSESSMENT - Functional importance
        if candidate.domain_type == "subdomain":
            subdomain_value = self._assess_subdomain_value(candidate.fqdn)
            score += subdomain_value * 0.2

        return min(score, 1.0)

    def _is_domain_relevant_to_organization(
        self,
        candidate: DomainCandidate,
        org_name: Optional[str],
        base_domains: Optional[Set[str]],
    ) -> bool:
        """Determine if domain is relevant to the organization using precision criteria."""

        # 1. BASE DOMAIN CORRELATION - Always include if matches known base domains
        if base_domains:
            for base_domain in base_domains:
                if (
                    candidate.fqdn.endswith(f".{base_domain}")
                    or candidate.fqdn == base_domain
                ):
                    return True

        # 2. ORGANIZATION NAME MATCHING - Include if matches organization
        if org_name:
            org_match_score = self._calculate_organization_match_score(
                candidate.fqdn, org_name
            )
            if org_match_score >= 0.3:  # Reasonable match threshold
                return True

        # 3. HIGH-CONFIDENCE DISCOVERY - Include if discovered with high confidence
        if candidate.confidence >= 0.8 and len(candidate.sources) >= 2:
            return True

        # 4. CERTIFICATE TRANSPARENCY + ORGANIZATION CONTEXT
        if "Certificate Transparency" in candidate.sources and org_name:
            # More lenient for CT discoveries if there's any organization context
            if self._has_organization_context(candidate.fqdn, org_name):
                return True

        # 5. EXCLUDE KNOWN FALSE POSITIVES - Specific exclusions
        if org_name and self._is_known_false_positive(candidate.fqdn, org_name):
            return False

        # 6. DEFAULT: Include if reasonable confidence and not obviously unrelated
        return candidate.confidence >= 0.6 and (
            not org_name or not self._is_obviously_unrelated(candidate.fqdn, org_name)
        )

    def _calculate_organization_match_score(self, fqdn: str, org_name: str) -> float:
        """Calculate how well a domain matches the organization name."""

        if not org_name:
            return 0.0

        # Extract root domain name
        domain_parts = fqdn.split(".")
        if len(domain_parts) >= 2:
            root_name = domain_parts[-2].lower()
        else:
            root_name = fqdn.lower()

        # Clean organization name
        org_clean = re.sub(r"[^a-zA-Z0-9]", "", org_name.lower())

        # 1. EXACT MATCH - Perfect score
        if root_name == org_clean:
            return 1.0

        # 2. SUBSTANTIAL OVERLAP - High score for significant matches
        if len(org_clean) >= 4 and org_clean in root_name:
            overlap_ratio = len(org_clean) / len(root_name)
            if overlap_ratio >= 0.6:  # 60% or more overlap
                return 0.8 + (overlap_ratio - 0.6) * 0.5  # 0.8-1.0 range

        if len(root_name) >= 4 and root_name in org_clean:
            overlap_ratio = len(root_name) / len(org_clean)
            if overlap_ratio >= 0.6:
                return 0.7 + (overlap_ratio - 0.6) * 0.5  # 0.7-0.95 range

        # 3. WORD-BASED MATCHING - Moderate score for word matches
        org_words = re.findall(r"\w+", org_name.lower())
        significant_words = [
            w
            for w in org_words
            if len(w) >= 4
            and w
            not in {
                "company",
                "corp",
                "corporation",
                "inc",
                "incorporated",
                "ltd",
                "limited",
                "group",
                "holdings",
                "international",
                "global",
                "worldwide",
                "enterprises",
            }
        ]

        best_word_score = 0.0
        for word in significant_words:
            if word in root_name:
                word_ratio = len(word) / len(root_name)
                if word_ratio >= 0.5:  # Word is substantial part of domain
                    best_word_score = max(best_word_score, 0.4 + word_ratio * 0.3)

        # 4. PARTIAL MATCHING - Lower score for partial matches
        if len(org_clean) >= 6:
            for i in range(len(org_clean) - 3):
                for j in range(i + 4, len(org_clean) + 1):
                    substring = org_clean[i:j]
                    if len(substring) >= 4 and substring in root_name:
                        partial_ratio = len(substring) / max(
                            len(root_name), len(org_clean)
                        )
                        if partial_ratio >= 0.3:
                            best_word_score = max(best_word_score, partial_ratio * 0.6)

        return best_word_score

    def _calculate_base_domain_correlation(
        self, fqdn: str, base_domains: Set[str]
    ) -> float:
        """Calculate correlation with known base domains."""

        for base_domain in base_domains:
            if fqdn.endswith(f".{base_domain}"):
                return 1.0  # Perfect correlation - it's a subdomain
            elif fqdn == base_domain:
                return 1.0  # Perfect correlation - it's the base domain

        # Check for similar domains (different TLD, etc.)
        domain_parts = fqdn.split(".")
        if len(domain_parts) >= 2:
            domain_root = domain_parts[-2]
            for base_domain in base_domains:
                base_parts = base_domain.split(".")
                if len(base_parts) >= 2 and domain_root == base_parts[-2]:
                    return 0.7  # High correlation - same root, different TLD

        return 0.0

    def _assess_subdomain_value(self, fqdn: str) -> float:
        """Assess the functional value of a subdomain."""

        subdomain_part = fqdn.split(".")[0].lower()

        # High-value subdomains
        high_value_patterns = {
            "www",
            "mail",
            "smtp",
            "imap",
            "pop3",
            "ftp",
            "sftp",
            "ssh",
            "vpn",
            "api",
            "admin",
            "portal",
            "dashboard",
            "app",
            "apps",
            "service",
            "services",
            "web",
            "mobile",
            "secure",
            "auth",
            "sso",
            "oauth",
            "login",
            "signin",
            "cdn",
            "static",
            "assets",
            "media",
            "images",
            "files",
            "support",
            "help",
            "docs",
            "documentation",
            "wiki",
            "blog",
            "news",
            "store",
            "shop",
            "pay",
            "payment",
            "billing",
            "account",
            "my",
            "user",
            "customer",
            "client",
        }

        if subdomain_part in high_value_patterns:
            return 1.0

        # Environment indicators
        env_patterns = {"dev", "staging", "test", "prod", "production", "beta", "alpha"}
        if subdomain_part in env_patterns:
            return 0.8

        # Infrastructure patterns
        infra_patterns = {
            "db",
            "database",
            "sql",
            "mysql",
            "postgres",
            "mongo",
            "redis",
        }
        if subdomain_part in infra_patterns:
            return 0.7

        # Monitoring/ops patterns
        ops_patterns = {"monitor", "status", "health", "metrics", "logs", "analytics"}
        if subdomain_part in ops_patterns:
            return 0.6

        # Low-value patterns (but not excluded)
        if re.match(r"^(ssl|cache|cdn|edge|node|server)\d*$", subdomain_part):
            return 0.3

        # Random/hash-like patterns
        if re.match(r"^[a-f0-9]{8,}$", subdomain_part) or re.match(
            r"^\d{4,}$", subdomain_part
        ):
            return 0.2

        # Default moderate value
        return 0.5

    def _has_organization_context(self, fqdn: str, org_name: str) -> bool:
        """Check if domain has any organizational context."""

        if not org_name:
            return False

        org_clean = re.sub(r"[^a-zA-Z0-9]", "", org_name.lower())
        fqdn_clean = re.sub(r"[^a-zA-Z0-9]", "", fqdn.lower())

        # Any overlap of 3+ characters
        if len(org_clean) >= 3:
            for i in range(len(org_clean) - 2):
                substring = org_clean[i : i + 3]
                if substring in fqdn_clean:
                    return True

        return False

    def _is_known_false_positive(self, fqdn: str, org_name: str) -> bool:
        """Check for known false positive patterns."""

        # Known unrelated domains that appear in CT logs
        false_positive_domains = {
            "now-tv.com",
            "nowtv.com",
            "teavana.com",
            "teavana.net",
            "evolution.com",
            "fresh.com",
            "seattle.com",
            "best.com",
        }

        if fqdn in false_positive_domains:
            return True

        # Check root domain against unrelated brands
        domain_parts = fqdn.split(".")
        if len(domain_parts) >= 2:
            root_domain = ".".join(domain_parts[-2:])
            if root_domain in false_positive_domains:
                return True

        return False

    def _is_obviously_unrelated(self, fqdn: str, org_name: str) -> bool:
        """Check if domain is obviously unrelated to the organization."""

        if not org_name:
            return False

        # Extract domain root
        domain_parts = fqdn.split(".")
        if len(domain_parts) >= 2:
            domain_root = domain_parts[-2].lower()
        else:
            domain_root = fqdn.lower()

        org_clean = re.sub(r"[^a-zA-Z0-9]", "", org_name.lower())

        # No overlap at all and very different
        if len(org_clean) >= 4 and len(domain_root) >= 4:
            # Calculate character overlap
            common_chars = sum(1 for c in domain_root if c in org_clean)
            overlap_ratio = common_chars / max(len(domain_root), len(org_clean))

            # If less than 20% character overlap, likely unrelated
            if overlap_ratio < 0.2:
                return True

        return False

    def _apply_domain_limits_strict(
        self,
        candidates: List[DomainCandidate],
        base_domains: Optional[Set[str]],
        org_name: Optional[str],
    ) -> List[DomainCandidate]:
        """Apply intelligent organization instead of arbitrary limits."""

        # NO ARBITRARY LIMITS - organize by relevance and relationship

        if not base_domains:
            # No base domains - return all relevant candidates sorted by relevance
            return candidates

        # Group by base domain relationship
        by_base_domain = defaultdict(list)
        independent_domains = []

        for candidate in candidates:
            assigned = False
            for base_domain in base_domains:
                if (
                    candidate.fqdn.endswith(f".{base_domain}")
                    or candidate.fqdn == base_domain
                ):
                    by_base_domain[base_domain].append(candidate)
                    assigned = True
                    break

            if not assigned:
                independent_domains.append(candidate)

        # Organize results: base domains first, then their subdomains, then independent domains
        organized = []

        # Add base domains and their subdomains
        for base_domain, domain_candidates in by_base_domain.items():
            # Sort by type (base first) and relevance
            base_candidates = [c for c in domain_candidates if c.fqdn == base_domain]
            subdomain_candidates = [
                c for c in domain_candidates if c.fqdn != base_domain
            ]

            # Sort subdomains by relevance
            subdomain_candidates.sort(key=lambda c: c.relevance_score, reverse=True)

            # Add base domain first, then subdomains
            organized.extend(base_candidates)
            organized.extend(subdomain_candidates)

        # Add independent domains (sorted by relevance)
        independent_domains.sort(key=lambda c: c.relevance_score, reverse=True)
        organized.extend(independent_domains)

        logger.info(
            f"Organized {len(organized)} domains: "
            f"{len(by_base_domain)} base domain groups, "
            f"{len(independent_domains)} independent domains"
        )

        return organized

    def _smart_dns_resolution(
        self,
        candidates: List[DomainCandidate],
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> List[Tuple[DomainCandidate, Optional[Subdomain]]]:
        """Smart DNS resolution with prioritization and batching."""

        if not candidates:
            return []

        # Prioritize candidates for resolution
        priority_candidates = self._prioritize_for_resolution(candidates)

        # Batch resolution to avoid DNS flooding
        resolved = []
        batch_size = 50  # Reasonable batch size
        total_batches = (len(priority_candidates) + batch_size - 1) // batch_size

        for batch_idx in range(total_batches):
            start_idx = batch_idx * batch_size
            end_idx = min(start_idx + batch_size, len(priority_candidates))
            batch = priority_candidates[start_idx:end_idx]

            # Resolve batch
            batch_resolved = self._resolve_domain_batch(batch, result)
            resolved.extend(batch_resolved)

            if progress_callback:
                progress = (
                    60 + (batch_idx + 1) / total_batches * 30
                )  # 60-90% for resolution
                progress_callback(
                    progress, f"DNS resolution batch {batch_idx + 1}/{total_batches}"
                )

        logger.info(f"DNS resolution complete: {len(resolved)} domains processed")
        return resolved

    def _prioritize_for_resolution(
        self, candidates: List[DomainCandidate]
    ) -> List[DomainCandidate]:
        """Prioritize candidates for DNS resolution."""

        # Sort by relevance score (already sorted)
        # Additional prioritization logic can be added here

        return candidates

    def _resolve_domain_batch(
        self, batch: List[DomainCandidate], result: ReconnaissanceResult
    ) -> List[Tuple[DomainCandidate, Optional[Subdomain]]]:
        """Resolve a batch of domains with timeout handling."""

        resolved = []

        # Use ThreadPoolExecutor for parallel resolution
        max_workers = min(10, len(batch))  # Limit concurrent DNS queries

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_candidate = {
                executor.submit(
                    self._resolve_single_domain, candidate, result
                ): candidate
                for candidate in batch
            }

            for future in as_completed(future_to_candidate, timeout=30):
                candidate = future_to_candidate[future]
                try:
                    subdomain_obj = future.result()
                    resolved.append((candidate, subdomain_obj))
                except Exception as e:
                    logger.debug(f"DNS resolution failed for {candidate.fqdn}: {e}")
                    # Still include candidate even if resolution failed
                    resolved.append((candidate, None))

        return resolved

    def _resolve_single_domain(
        self, candidate: DomainCandidate, result: ReconnaissanceResult
    ) -> Optional[Subdomain]:
        """Resolve a single domain with timeout."""

        try:
            # Use existing DNS resolution logic from domain_discovery
            from src.discovery.domain_discovery import _resolve_domain

            status, resolved_ips, checked_time = _resolve_domain(candidate.fqdn, result)

            return Subdomain(
                fqdn=candidate.fqdn,
                status=status or "unknown",
                resolved_ips=resolved_ips,
                data_source=f"Enhanced-DNS ({', '.join(candidate.sources)})",
                last_checked=checked_time,
            )

        except Exception as e:
            logger.debug(f"Failed to resolve {candidate.fqdn}: {e}")
            return None

    def _organize_final_domains(
        self, resolved: List[Tuple[DomainCandidate, Optional[Subdomain]]]
    ) -> Set[Domain]:
        """Organize resolved domains into final Domain objects."""

        domain_map = {}

        for candidate, subdomain_obj in resolved:
            # Determine base domain
            if candidate.domain_type == "base":
                base_domain_name = candidate.fqdn
            else:
                # Extract base domain from subdomain
                parts = candidate.fqdn.split(".")
                if len(parts) >= 2:
                    base_domain_name = ".".join(parts[-2:])
                else:
                    base_domain_name = candidate.fqdn

            # Create or get Domain object
            if base_domain_name not in domain_map:
                domain_map[base_domain_name] = Domain(
                    name=base_domain_name,
                    registrar=None,
                    creation_date=None,
                    data_source="Enhanced Domain Discovery",
                    subdomains=set(),
                )

            domain_obj = domain_map[base_domain_name]

            # Add subdomain if it's not the base domain
            if candidate.fqdn != base_domain_name and subdomain_obj:
                domain_obj.subdomains.add(subdomain_obj)

        return set(domain_map.values())
