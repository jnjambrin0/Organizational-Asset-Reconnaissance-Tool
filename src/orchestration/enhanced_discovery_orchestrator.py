"""
Enhanced Discovery Orchestrator with advanced coordination and intelligent workflow management.

This module orchestrates the enhanced discovery process using improved modules with
rate limiting, configuration management, and comprehensive progress tracking.
"""

import logging
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Set, Callable, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum

from src.core.models import ReconnaissanceResult
from src.config.settings import get_settings
from src.utils.rate_limiter import get_rate_limiter
from src.utils.logging_config import create_progress_logger, get_logger

# Import enhanced discovery modules
from src.discovery.enhanced_domain_discovery import EnhancedDomainDiscovery
from src.discovery.enhanced_asn_discovery import EnhancedASNDiscovery
from src.discovery.intelligent_ip_discovery import IntelligentIPDiscovery
from src.discovery.enhanced_cloud_detection import EnhancedCloudDetection

logger = get_logger(__name__)


class DiscoveryPhase(Enum):
    """Enumeration of discovery phases."""

    DOMAIN_DISCOVERY = "domain_discovery"
    ASN_DISCOVERY = "asn_discovery"
    IP_RANGE_DISCOVERY = "ip_range_discovery"
    CLOUD_DETECTION = "cloud_detection"


@dataclass
class PhaseResult:
    """Result of a discovery phase execution."""

    phase: DiscoveryPhase
    success: bool
    duration: float
    assets_found: int
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DiscoveryConfig:
    """Configuration for discovery orchestration."""

    max_workers: int = 10
    timeout_per_phase: int = 300  # 5 minutes per phase
    enable_parallel_phases: bool = False
    skip_on_error: bool = False
    retry_failed_phases: bool = True
    max_phase_retries: int = 2

    # Phase-specific settings
    domain_discovery_config: Dict[str, Any] = field(default_factory=dict)
    asn_discovery_config: Dict[str, Any] = field(default_factory=dict)
    ip_discovery_config: Dict[str, Any] = field(default_factory=dict)
    cloud_detection_config: Dict[str, Any] = field(default_factory=dict)


class EnhancedDiscoveryOrchestrator:
    """Enhanced discovery orchestrator with intelligent workflow management."""

    def __init__(self, config=None, discovery_config=None):
        """Initialize the enhanced discovery orchestrator."""
        self.config = config or get_settings()
        self.discovery_config = discovery_config or DiscoveryConfig()
        self.rate_limiter = get_rate_limiter()

        # Initialize discovery modules
        self.domain_discovery = EnhancedDomainDiscovery(self.config)
        self.asn_discovery = EnhancedASNDiscovery(self.config)
        self.ip_discovery = IntelligentIPDiscovery(self.config)
        self.cloud_detection = EnhancedCloudDetection(self.config)

        # Phase execution results
        self.phase_results: Dict[DiscoveryPhase, PhaseResult] = {}

        logger.info("Enhanced Discovery Orchestrator initialized")

    def run_enhanced_discovery(
        self,
        target_organization: str,
        base_domains: Optional[Set[str]] = None,
        progress_callback: Optional[Callable[[float, str], None]] = None,
        status_callback: Optional[Callable[[str, str], None]] = None,
        phase_callback: Optional[Callable[[DiscoveryPhase, PhaseResult], None]] = None,
    ) -> ReconnaissanceResult:
        """
        Run the complete enhanced discovery process.

        Args:
            target_organization: Name of the target organization
            base_domains: Set of known domains to start with
            progress_callback: Optional callback for progress updates
            status_callback: Optional callback for status updates
            phase_callback: Optional callback for phase completion

        Returns:
            ReconnaissanceResult object containing all discovered assets
        """
        start_time = time.time()
        result = ReconnaissanceResult(target_organization=target_organization)

        logger.info(f"🚀 Starting enhanced reconnaissance for: {target_organization}")

        if status_callback:
            status_callback(
                "🚀", f"Starting enhanced reconnaissance for {target_organization}"
            )

        try:
            # Phase 1: Enhanced Domain Discovery
            phase1_result = self._execute_phase_with_retry(
                DiscoveryPhase.DOMAIN_DISCOVERY,
                lambda: self._run_domain_discovery_phase(
                    target_organization,
                    base_domains,
                    result,
                    lambda p, msg: (
                        progress_callback(p / 4, msg) if progress_callback else None
                    ),
                    status_callback,
                ),
            )

            if phase_callback:
                phase_callback(DiscoveryPhase.DOMAIN_DISCOVERY, phase1_result)

            # Phase 2: Enhanced ASN Discovery
            phase2_result = self._execute_phase_with_retry(
                DiscoveryPhase.ASN_DISCOVERY,
                lambda: self._run_asn_discovery_phase(
                    target_organization,
                    base_domains,
                    result,
                    lambda p, msg: (
                        progress_callback(25 + (p / 4), msg)
                        if progress_callback
                        else None
                    ),
                    status_callback,
                ),
            )

            if phase_callback:
                phase_callback(DiscoveryPhase.ASN_DISCOVERY, phase2_result)

            # Phase 3: Intelligent IP Range Discovery
            phase3_result = self._execute_phase_with_retry(
                DiscoveryPhase.IP_RANGE_DISCOVERY,
                lambda: self._run_ip_discovery_phase(
                    result,
                    lambda p, msg: (
                        progress_callback(50 + (p / 4), msg)
                        if progress_callback
                        else None
                    ),
                    status_callback,
                ),
            )

            if phase_callback:
                phase_callback(DiscoveryPhase.IP_RANGE_DISCOVERY, phase3_result)

            # Phase 4: Enhanced Cloud Detection
            phase4_result = self._execute_phase_with_retry(
                DiscoveryPhase.CLOUD_DETECTION,
                lambda: self._run_cloud_detection_phase(
                    result,
                    lambda p, msg: (
                        progress_callback(75 + (p / 4), msg)
                        if progress_callback
                        else None
                    ),
                    status_callback,
                ),
            )

            if phase_callback:
                phase_callback(DiscoveryPhase.CLOUD_DETECTION, phase4_result)

            # Finalization
            end_time = time.time()
            duration = end_time - start_time

            self._log_discovery_summary(result, duration)

            if progress_callback:
                progress_callback(100.0, "Enhanced reconnaissance complete")

            if status_callback:
                status_callback(
                    "✅", f"Enhanced reconnaissance complete in {duration:.2f}s"
                )

        except Exception as e:
            logger.exception(f"❌ Critical error during enhanced discovery: {e}")
            result.add_warning(f"Critical discovery error: {e}")
            if status_callback:
                status_callback("❌", f"Discovery failed: {e}")

        return result

    def _execute_phase_with_retry(
        self, phase: DiscoveryPhase, phase_function: Callable[[], Any]
    ) -> PhaseResult:
        """Execute a discovery phase with retry logic."""

        max_retries = (
            self.discovery_config.max_phase_retries
            if self.discovery_config.retry_failed_phases
            else 0
        )

        for attempt in range(max_retries + 1):
            start_time = time.time()
            phase_result = PhaseResult(
                phase=phase, success=False, duration=0.0, assets_found=0
            )

            try:
                logger.info(
                    f"🔄 Executing {phase.value} (attempt {attempt + 1}/{max_retries + 1})"
                )

                # Execute the phase function directly
                # (Retry logic is handled at this level, no need for additional backoff)
                phase_function()

                # If we get here, the phase succeeded
                phase_result.success = True
                phase_result.duration = time.time() - start_time

                logger.info(
                    f"✅ {phase.value} completed successfully in {phase_result.duration:.2f}s"
                )
                break

            except Exception as e:
                phase_result.duration = time.time() - start_time
                phase_result.errors.append(str(e))

                logger.warning(f"⚠️ {phase.value} failed on attempt {attempt + 1}: {e}")

                if attempt < max_retries:
                    wait_time = 2**attempt  # Exponential backoff
                    logger.info(f"Retrying {phase.value} in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logger.error(
                        f"❌ {phase.value} failed after {max_retries + 1} attempts"
                    )

                    if not self.discovery_config.skip_on_error:
                        raise

        self.phase_results[phase] = phase_result
        return phase_result

    def _run_domain_discovery_phase(
        self,
        target_organization: Optional[str],
        base_domains: Optional[Set[str]],
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
        status_callback: Optional[Callable[[str, str], None]] = None,
    ):
        """Execute the enhanced domain discovery phase."""

        logger.info(f"🌍 Phase 1: Enhanced Domain Discovery for {target_organization}")

        if status_callback:
            status_callback(
                "🔍", f"Enhanced domain discovery for {target_organization}"
            )

        # Create a progress logger for terminal
        progress = create_progress_logger(
            "enhanced_domain_discovery", total=100, prefix="Enhanced Domain Discovery"
        )
        progress.update(0, "Starting enhanced domain discovery...")

        try:
            self.domain_discovery.find_enhanced_domains(
                target_organization,
                base_domains,
                result,
                progress_callback=lambda p, msg: (
                    progress.update(p, msg),
                    progress_callback(p, msg) if progress_callback else None,
                ),
            )

            progress.update(100, "Enhanced domain discovery completed")

            total_subdomains = sum(len(d.subdomains) for d in result.domains)
            logger.info(
                f"✅ Enhanced Domain Discovery complete: {len(result.domains)} domains, {total_subdomains} subdomains"
            )

            if status_callback:
                status_callback(
                    "✅",
                    f"Found {len(result.domains)} domains and {total_subdomains} subdomains",
                )

        except Exception as e:
            logger.exception(f"❌ Error during Enhanced Domain Discovery: {e}")
            result.add_warning(f"Enhanced Domain Discovery Error: {e}")
            if status_callback:
                status_callback("❌", f"Domain discovery error: {e}")
            raise

    def _run_asn_discovery_phase(
        self,
        target_organization: Optional[str],
        base_domains: Optional[Set[str]],
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
        status_callback: Optional[Callable[[str, str], None]] = None,
    ):
        """Execute the enhanced ASN discovery phase."""

        logger.info(f"🌐 Phase 2: Enhanced ASN Discovery for {target_organization}")

        if status_callback:
            status_callback("🔍", f"Enhanced ASN discovery for {target_organization}")

        progress = create_progress_logger(
            "enhanced_asn_discovery", total=100, prefix="Enhanced ASN Discovery"
        )
        progress.update(0, "Starting enhanced ASN discovery...")

        try:
            self.asn_discovery.find_asns_for_organization(
                target_organization,
                base_domains,
                result,
                progress_callback=lambda p, msg: (
                    progress.update(p, msg),
                    progress_callback(p, msg) if progress_callback else None,
                ),
            )

            progress.update(100, "Enhanced ASN discovery completed")

            logger.info(f"✅ Enhanced ASN Discovery complete: {len(result.asns)} ASNs")

            if status_callback:
                status_callback("✅", f"Found {len(result.asns)} ASNs")

        except Exception as e:
            logger.exception(f"❌ Error during Enhanced ASN Discovery: {e}")
            result.add_warning(f"Enhanced ASN Discovery Error: {e}")
            if status_callback:
                status_callback("❌", f"ASN discovery error: {e}")
            raise

    def _run_ip_discovery_phase(
        self,
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
        status_callback: Optional[Callable[[str, str], None]] = None,
    ):
        """Execute the intelligent IP range discovery phase."""

        logger.info(
            f"💻 Phase 3: Intelligent IP Range Discovery for {len(result.asns)} ASNs"
        )

        if not result.asns:
            logger.warning(
                "⚠️ Phase 3 - Skipping IP Range discovery as no ASNs were found"
            )
            if progress_callback:
                progress_callback(100.0, "Skipped (no ASNs found)")
            if status_callback:
                status_callback("⚠️", "Skipping IP Range discovery (no ASNs found)")
            return

        if status_callback:
            status_callback(
                "🔍", f"Intelligent IP range mapping for {len(result.asns)} ASNs"
            )

        progress = create_progress_logger(
            "intelligent_ip_discovery", total=100, prefix="Intelligent IP Discovery"
        )
        progress.update(0, "Starting intelligent IP range discovery...")

        try:
            self.ip_discovery.find_intelligent_ip_ranges(
                result.asns,
                result,
                progress_callback=lambda p, msg: (
                    progress.update(p, msg),
                    progress_callback(p, msg) if progress_callback else None,
                ),
            )

            progress.update(100, "Intelligent IP range discovery completed")

            logger.info(
                f"✅ Intelligent IP Range Discovery complete: {len(result.ip_ranges)} IP ranges"
            )

            if status_callback:
                status_callback("✅", f"Found {len(result.ip_ranges)} IP ranges")

        except Exception as e:
            logger.exception(f"❌ Error during Intelligent IP Range Discovery: {e}")
            result.add_warning(f"Intelligent IP Range Discovery Error: {e}")
            if status_callback:
                status_callback("❌", f"IP range discovery error: {e}")
            raise

    def _run_cloud_detection_phase(
        self,
        result: ReconnaissanceResult,
        progress_callback: Optional[Callable[[float, str], None]] = None,
        status_callback: Optional[Callable[[str, str], None]] = None,
    ):
        """Execute the enhanced cloud detection phase."""

        logger.info(f"☁️ Phase 4: Enhanced Cloud Service Detection")

        if status_callback:
            status_callback("🔍", "Enhanced cloud service detection")

        progress = create_progress_logger(
            "enhanced_cloud_detection", total=100, prefix="Enhanced Cloud Detection"
        )
        progress.update(0, "Starting enhanced cloud service detection...")

        total_assets = len(result.ip_ranges) + len(result.domains)
        if total_assets == 0:
            logger.warning(
                "⚠️ Phase 4 - Skipping Cloud detection as no assets were found"
            )
            progress.update(100, "Skipped (no assets found)")
            if status_callback:
                status_callback("⚠️", "Skipping Cloud detection (no assets found)")
            return

        try:
            self.cloud_detection.detect_cloud_services(
                result,
                progress_callback=lambda p, msg: (
                    progress.update(p, msg),
                    progress_callback(p, msg) if progress_callback else None,
                ),
                status_callback=lambda emoji, msg: logger.debug(f"{emoji} {msg}"),
            )

            progress.update(100, "Enhanced cloud service detection completed")

            logger.info(
                f"✅ Enhanced Cloud Detection complete: {len(result.cloud_services)} cloud services"
            )

            if status_callback:
                status_callback(
                    "✅", f"Found {len(result.cloud_services)} cloud services"
                )

        except Exception as e:
            logger.exception(f"❌ Error during Enhanced Cloud Detection: {e}")
            result.add_warning(f"Enhanced Cloud Detection Error: {e}")
            if status_callback:
                status_callback("❌", f"Cloud detection error: {e}")
            raise

    def _log_discovery_summary(self, result: ReconnaissanceResult, duration: float):
        """Log a comprehensive summary of the discovery process."""

        total_subdomains = sum(len(d.subdomains) for d in result.domains)

        logger.info(
            f"✨ Enhanced reconnaissance completed for {result.target_organization} in {duration:.2f} seconds"
        )
        logger.info(f"📊 Discovery Summary:")
        logger.info(f"   • ASNs: {len(result.asns)}")
        logger.info(f"   • IP Ranges: {len(result.ip_ranges)}")
        logger.info(f"   • Domains: {len(result.domains)}")
        logger.info(f"   • Subdomains: {total_subdomains}")
        logger.info(f"   • Cloud Services: {len(result.cloud_services)}")

        if result.warnings:
            logger.warning(f"⚠️ Scan completed with {len(result.warnings)} warnings")
            for warning in result.warnings[:5]:  # Show first 5 warnings
                logger.warning(f"   - {warning}")
            if len(result.warnings) > 5:
                logger.warning(f"   ... and {len(result.warnings) - 5} more warnings")

        # Log phase results
        logger.info("📈 Phase Results:")
        for phase, phase_result in self.phase_results.items():
            status = "✅ SUCCESS" if phase_result.success else "❌ FAILED"
            logger.info(f"   • {phase.value}: {status} ({phase_result.duration:.2f}s)")

    def get_discovery_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about the discovery process."""

        return {
            "phase_results": {
                phase.value: {
                    "success": result.success,
                    "duration": result.duration,
                    "assets_found": result.assets_found,
                    "warnings_count": len(result.warnings),
                    "errors_count": len(result.errors),
                }
                for phase, result in self.phase_results.items()
            },
            "rate_limiter_stats": self.rate_limiter.get_metrics(),
            "cloud_provider_stats": self.cloud_detection.get_provider_statistics(),
        }


# Convenience functions for backward compatibility
def run_enhanced_discovery(
    target_organization: str,
    base_domains: Optional[Set[str]] = None,
    max_workers: int = 10,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    status_callback: Optional[Callable[[str, str], None]] = None,
) -> ReconnaissanceResult:
    """Run enhanced discovery with default configuration."""

    orchestrator = EnhancedDiscoveryOrchestrator()
    return orchestrator.run_enhanced_discovery(
        target_organization=target_organization,
        base_domains=base_domains,
        progress_callback=progress_callback,
        status_callback=status_callback,
    )


# Legacy function for backward compatibility
def run_discovery(
    target_organization: str,
    base_domains: Optional[Set[str]] = None,
    include_subdomain_discovery: bool = True,
    max_workers: int = 10,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    status_callback: Optional[Callable[[str, str], None]] = None,
) -> ReconnaissanceResult:
    """Legacy function that maps to enhanced discovery."""

    logger.info("Using enhanced discovery orchestrator for legacy discovery call")
    return run_enhanced_discovery(
        target_organization=target_organization,
        base_domains=base_domains,
        progress_callback=progress_callback,
        status_callback=status_callback,
    )


# Example usage and testing
if __name__ == "__main__":
    import sys

    sys.path.insert(0, sys.path[0] + "/../..")
    from src.utils.logging_config import setup_logging

    setup_logging(level=logging.INFO, use_enhanced_formatter=True, color_enabled=True)

    # Test with a real organization
    target = "Cloudflare, Inc."
    domains = {"cloudflare.com"}

    orchestrator = EnhancedDiscoveryOrchestrator()
    final_result = orchestrator.run_enhanced_discovery(target, domains)

    print("\n--- Enhanced Discovery Results ---")
    print(f"Target: {final_result.target_organization}")
    print(f"ASNs: {len(final_result.asns)}")
    print(f"IP Ranges: {len(final_result.ip_ranges)}")
    print(f"Domains: {len(final_result.domains)}")
    print(f"Cloud Services: {len(final_result.cloud_services)}")

    if final_result.warnings:
        print(f"\nWarnings: {len(final_result.warnings)}")
        for warning in final_result.warnings[:3]:
            print(f"  - {warning}")

    print("\n--- Discovery Statistics ---")
    stats = orchestrator.get_discovery_statistics()
    for phase_name, phase_stats in stats["phase_results"].items():
        print(
            f"{phase_name}: {'✅' if phase_stats['success'] else '❌'} ({phase_stats['duration']:.2f}s)"
        )
