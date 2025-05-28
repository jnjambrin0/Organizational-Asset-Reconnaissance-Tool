"""Intelligent IP Range Discovery with relevance filtering and smart consolidation."""

import logging
import ipaddress
from typing import Set, Optional, Callable, List, Dict, Tuple
from dataclasses import dataclass
from collections import defaultdict

from src.core.models import ASN, IPRange, ReconnaissanceResult
from src.config.settings import get_settings
from src.discovery.ip_discovery import _fetch_and_parse_asn_page, _query_irr_for_asn

logger = logging.getLogger(__name__)

@dataclass
class IPRangeCandidate:
    """Represents an IP range candidate with relevance scoring."""
    ip_range: IPRange
    relevance_score: float
    size_class: str  # 'small', 'medium', 'large', 'huge'
    source_confidence: float
    reasons: List[str]

class IntelligentIPDiscovery:
    """Intelligent IP range discovery with relevance filtering."""
    
    def __init__(self, config=None):
        self.config = config or get_settings()
        self.max_ip_ranges_per_asn = self.config.recon.max_ip_ranges_per_asn
        
        # Size classification thresholds
        self.size_thresholds = {
            'small': 256,      # /24 and smaller
            'medium': 4096,    # /20 and smaller  
            'large': 65536,    # /16 and smaller
            'huge': float('inf')  # Larger than /16
        }
    
    def find_intelligent_ip_ranges(
        self,
        asns: Set[ASN],
        result: ReconnaissanceResult,
        organization_context: Optional[str] = None,
        progress_callback: Optional[Callable[[float, str], None]] = None
    ) -> Set[IPRange]:
        """Intelligent IP range discovery with relevance filtering."""
        
        if not asns:
            logger.info("No ASNs provided for IP range discovery")
            if progress_callback:
                progress_callback(100.0, "Skipped (no ASNs)")
            return set()
        
        logger.info(f"🧠 Intelligent IP discovery for {len(asns)} ASNs")
        
        if progress_callback:
            progress_callback(0.0, "Starting intelligent IP discovery...")
        
        # Phase 1: Collect all IP range candidates
        candidates = self._collect_ip_candidates(asns, result, progress_callback)
        
        # Phase 2: Score and filter by relevance
        filtered_candidates = self._filter_by_relevance(candidates, organization_context)
        
        # Phase 3: Smart consolidation
        final_ranges = self._smart_consolidation(filtered_candidates, result)
        
        # Add to result
        result.ip_ranges.update(final_ranges)
        
        logger.info(f"✅ Intelligent IP discovery complete: {len(final_ranges)} relevant ranges selected")
        
        if progress_callback:
            progress_callback(100.0, f"Intelligent IP discovery complete ({len(final_ranges)} ranges)")
        
        return final_ranges
    
    def _collect_ip_candidates(
        self, 
        asns: Set[ASN], 
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None
    ) -> List[IPRangeCandidate]:
        """Collect IP range candidates from all sources."""
        
        candidates = []
        total_asns = len(asns)
        processed = 0
        
        for asn in asns:
            # Limit ranges per ASN to prevent explosion
            asn_candidates = []
            
            try:
                # BGP.HE.NET source
                bgp_ranges = _fetch_and_parse_asn_page(asn, result)
                for ip_range in bgp_ranges:
                    candidate = self._create_candidate(ip_range, asn, 'BGP.HE.NET', 0.8)
                    asn_candidates.append(candidate)
                
                # IRR source
                irr_ranges = _query_irr_for_asn(asn, result)
                for ip_range in irr_ranges:
                    candidate = self._create_candidate(ip_range, asn, 'IRR', 0.6)
                    asn_candidates.append(candidate)
                
                # Apply per-ASN limits
                limited_candidates = self._apply_per_asn_limits(asn_candidates, asn)
                candidates.extend(limited_candidates)
                
            except Exception as e:
                logger.warning(f"Error collecting IP ranges for ASN {asn.number}: {e}")
                result.add_warning(f"Intelligent IP Discovery: Error for ASN {asn.number} - {e}")
            
            processed += 1
            if progress_callback:
                progress = (processed / total_asns) * 60  # 60% for collection
                progress_callback(progress, f"Collected ranges for ASN {processed}/{total_asns}")
        
        logger.info(f"Collected {len(candidates)} IP range candidates from {len(asns)} ASNs")
        return candidates
    
    def _create_candidate(
        self, 
        ip_range: IPRange, 
        asn: ASN, 
        source: str, 
        source_confidence: float
    ) -> IPRangeCandidate:
        """Create an IP range candidate with initial scoring."""
        
        # Calculate network size
        try:
            network = ipaddress.ip_network(ip_range.cidr, strict=False)
            network_size = network.num_addresses
        except ValueError:
            network_size = 1
            logger.warning(f"Invalid CIDR format: {ip_range.cidr}")
        
        # Classify size
        size_class = self._classify_network_size(network_size)
        
        # Initial relevance score based on size (smaller networks often more relevant)
        relevance_score = self._calculate_initial_relevance(network_size, source)
        
        return IPRangeCandidate(
            ip_range=ip_range,
            relevance_score=relevance_score,
            size_class=size_class,
            source_confidence=source_confidence,
            reasons=[f'Found via {source} for ASN {asn.number}']
        )
    
    def _classify_network_size(self, size: int) -> str:
        """Classify network by size."""
        for class_name, threshold in self.size_thresholds.items():
            if size <= threshold:
                return class_name
        return 'huge'
    
    def _calculate_initial_relevance(self, network_size: int, source: str) -> float:
        """Calculate initial relevance score based on size and source."""
        
        # Base score by source
        source_scores = {
            'BGP.HE.NET': 0.8,
            'IRR': 0.6
        }
        base_score = source_scores.get(source, 0.5)
        
        # Adjust by size (smaller networks often more specific and relevant)
        if network_size <= 256:  # /24 or smaller
            size_modifier = 1.0
        elif network_size <= 4096:  # /20 or smaller
            size_modifier = 0.8
        elif network_size <= 65536:  # /16 or smaller
            size_modifier = 0.6
        else:  # Very large networks
            size_modifier = 0.3
        
        return base_score * size_modifier
    
    def _apply_per_asn_limits(
        self, 
        candidates: List[IPRangeCandidate], 
        asn: ASN
    ) -> List[IPRangeCandidate]:
        """Apply per-ASN limits to prevent explosion."""
        
        if len(candidates) <= self.max_ip_ranges_per_asn:
            return candidates
        
        # Sort by relevance and take top candidates
        sorted_candidates = sorted(candidates, key=lambda c: c.relevance_score, reverse=True)
        limited_candidates = sorted_candidates[:self.max_ip_ranges_per_asn]
        
        logger.info(f"Limited ASN {asn.number} to {self.max_ip_ranges_per_asn} ranges "
                   f"(found {len(candidates)} total)")
        
        return limited_candidates
    
    def _filter_by_relevance(
        self, 
        candidates: List[IPRangeCandidate], 
        organization_context: Optional[str]
    ) -> List[IPRangeCandidate]:
        """Filter candidates by relevance and adjust scores."""
        
        filtered = []
        
        for candidate in candidates:
            # Enhance relevance score with additional factors
            enhanced_score = self._enhance_relevance_score(candidate, organization_context)
            
            # Apply relevance threshold
            if enhanced_score >= 0.3:  # Minimum relevance threshold
                candidate.relevance_score = enhanced_score
                filtered.append(candidate)
        
        # Sort by relevance
        filtered.sort(key=lambda c: c.relevance_score, reverse=True)
        
        logger.info(f"Filtered to {len(filtered)} relevant IP range candidates")
        return filtered
    
    def _enhance_relevance_score(
        self, 
        candidate: IPRangeCandidate, 
        organization_context: Optional[str]
    ) -> float:
        """Enhance relevance score with contextual factors."""
        
        score = candidate.relevance_score
        
        # Boost score for smaller, more specific networks
        if candidate.size_class == 'small':
            score += 0.2
        elif candidate.size_class == 'medium':
            score += 0.1
        
        # Penalize huge networks (often too broad to be useful)
        if candidate.size_class == 'huge':
            score -= 0.3
        
        # Boost score for multiple source confirmation
        if candidate.source_confidence > 0.7:
            score += 0.1
        
        # Context-based scoring (if organization context available)
        if organization_context:
            score = self._apply_context_scoring(score, candidate, organization_context)
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _apply_context_scoring(
        self, 
        score: float, 
        candidate: IPRangeCandidate, 
        context: str
    ) -> float:
        """Apply organization context to scoring."""
        
        # This could be enhanced with:
        # - Geographic relevance
        # - Known infrastructure patterns
        # - Historical data
        
        # For now, basic implementation
        return score
    
    def _smart_consolidation(
        self, 
        candidates: List[IPRangeCandidate], 
        result: ReconnaissanceResult
    ) -> Set[IPRange]:
        """Smart consolidation to avoid over-consolidation."""
        
        if not candidates:
            return set()
        
        # Group by IP version
        ipv4_candidates = [c for c in candidates if c.ip_range.version == 4]
        ipv6_candidates = [c for c in candidates if c.ip_range.version == 6]
        
        final_ranges = set()
        
        # Process IPv4
        if ipv4_candidates:
            ipv4_ranges = self._consolidate_version_ranges(ipv4_candidates, 4)
            final_ranges.update(ipv4_ranges)
        
        # Process IPv6
        if ipv6_candidates:
            ipv6_ranges = self._consolidate_version_ranges(ipv6_candidates, 6)
            final_ranges.update(ipv6_ranges)
        
        logger.info(f"Smart consolidation: {len(candidates)} candidates → {len(final_ranges)} final ranges")
        return final_ranges
    
    def _consolidate_version_ranges(
        self, 
        candidates: List[IPRangeCandidate], 
        version: int
    ) -> Set[IPRange]:
        """Consolidate ranges for a specific IP version."""
        
        # Take top candidates by relevance (prevent over-consolidation)
        max_ranges_to_consolidate = 100  # Reasonable limit
        top_candidates = candidates[:max_ranges_to_consolidate]
        
        # Convert to networks
        networks = []
        candidate_map = {}
        
        for candidate in top_candidates:
            try:
                network = ipaddress.ip_network(candidate.ip_range.cidr, strict=False)
                networks.append(network)
                candidate_map[str(network)] = candidate
            except ValueError as e:
                logger.warning(f"Skipping invalid CIDR {candidate.ip_range.cidr}: {e}")
        
        # Smart consolidation (limited)
        if len(networks) <= 50:
            # Small number - can afford full consolidation
            consolidated = list(ipaddress.collapse_addresses(networks))
        else:
            # Large number - use sampling approach
            consolidated = self._sample_based_consolidation(networks)
        
        # Convert back to IPRange objects
        final_ranges = set()
        for network in consolidated:
            # Find best matching candidate for metadata
            best_candidate = self._find_best_candidate_for_network(network, candidate_map)
            
            ip_range = IPRange(
                cidr=str(network),
                version=version,
                asn=best_candidate.ip_range.asn if best_candidate else None,
                country=best_candidate.ip_range.country if best_candidate else None,
                data_source=f"Intelligent-Consolidated ({best_candidate.source_confidence:.1f})" if best_candidate else "Intelligent-Consolidated"
            )
            final_ranges.add(ip_range)
        
        return final_ranges
    
    def _sample_based_consolidation(self, networks: List) -> List:
        """Sample-based consolidation for large network lists."""
        
        # Group networks by prefix length
        by_prefix = defaultdict(list)
        for network in networks:
            by_prefix[network.prefixlen].append(network)
        
        consolidated = []
        
        # Consolidate within each prefix group
        for prefix_len, group_networks in by_prefix.items():
            if len(group_networks) <= 20:
                # Small group - full consolidation
                consolidated.extend(ipaddress.collapse_addresses(group_networks))
            else:
                # Large group - take most specific ranges
                sorted_networks = sorted(group_networks, key=lambda n: n.num_addresses)
                consolidated.extend(sorted_networks[:20])  # Top 20 most specific
        
        return consolidated
    
    def _find_best_candidate_for_network(
        self, 
        network, 
        candidate_map: Dict[str, IPRangeCandidate]
    ) -> Optional[IPRangeCandidate]:
        """Find the best candidate that matches or is contained in the network."""
        
        # Direct match
        if str(network) in candidate_map:
            return candidate_map[str(network)]
        
        # Find best overlapping candidate
        best_candidate = None
        best_overlap = 0
        
        for cidr_str, candidate in candidate_map.items():
            try:
                candidate_network = ipaddress.ip_network(cidr_str, strict=False)
                if network.supernet_of(candidate_network) or network.subnet_of(candidate_network):
                    overlap = min(network.num_addresses, candidate_network.num_addresses)
                    if overlap > best_overlap:
                        best_overlap = overlap
                        best_candidate = candidate
            except Exception:
                continue
        
        return best_candidate 