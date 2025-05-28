"""
Base Discovery Classes

Core base classes and interfaces for the discovery system.
"""

import logging
import time
from typing import Generic, TypeVar, Set, Optional, Callable, List, Dict, Any
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

from .types import (
    DiscoveryCandidate,
    DiscoveryContext,
    DiscoveryMetrics,
    ConfidenceScore,
)

# Type variable for discovery assets
T = TypeVar("T")

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryConfig:
    """Configuration for discovery operations."""

    max_concurrent_requests: int = 5
    request_timeout: int = 30
    rate_limit_delay: float = 1.0
    max_retries: int = 3
    min_confidence_threshold: float = 0.3
    enable_caching: bool = True
    cache_ttl: int = 3600  # 1 hour

    # Quality filtering
    enable_quality_filtering: bool = True
    min_quality_score: float = 0.2

    # Performance limits
    max_candidates_per_source: int = 100
    max_total_candidates: int = 500


@dataclass
class DiscoveryResult(Generic[T]):
    """Result container for discovery operations."""

    context: DiscoveryContext
    assets: Set[T] = field(default_factory=set)
    candidates: List[DiscoveryCandidate] = field(default_factory=list)
    metrics: DiscoveryMetrics = field(default_factory=DiscoveryMetrics)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_asset(self, asset: T):
        """Add a validated asset to the result."""
        self.assets.add(asset)

    def add_candidate(self, candidate: DiscoveryCandidate):
        """Add a discovery candidate."""
        self.candidates.append(candidate)

    def add_error(self, error: str):
        """Add an error message."""
        self.errors.append(error)
        logger.error(f"Discovery error: {error}")

    def add_warning(self, warning: str):
        """Add a warning message."""
        self.warnings.append(warning)
        logger.warning(f"Discovery warning: {warning}")

    @property
    def success_rate(self) -> float:
        """Calculate success rate based on assets vs candidates."""
        if not self.candidates:
            return 1.0 if self.assets else 0.0
        return len(self.assets) / len(self.candidates)


class BaseDiscovery(ABC, Generic[T]):
    """
    Abstract base class for all discovery modules.

    Provides common functionality for discovery operations including:
    - Configuration management
    - Progress tracking
    - Error handling
    - Metrics collection
    """

    def __init__(self, config: Optional[DiscoveryConfig] = None):
        self.config = config or DiscoveryConfig()
        self.logger = logging.getLogger(self.__class__.__name__)
        self._start_time: Optional[float] = None

    @abstractmethod
    def discover(
        self,
        context: DiscoveryContext,
        result: Any,  # ReconnaissanceResult
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> DiscoveryResult[T]:
        """
        Main discovery method to be implemented by subclasses.

        Args:
            context: Discovery context with search terms and organization info
            result: Global reconnaissance result to update
            progress_callback: Optional callback for progress updates

        Returns:
            DiscoveryResult containing discovered assets
        """
        pass

    @abstractmethod
    def validate_candidate(self, candidate: DiscoveryCandidate) -> bool:
        """Validate a discovery candidate."""
        pass

    def _start_discovery(self, operation_name: str):
        """Start discovery operation tracking."""
        self._start_time = time.time()
        self.logger.info(f"🚀 Starting {operation_name}")

    def _finish_discovery(self, operation_name: str):
        """Finish discovery operation tracking."""
        if self._start_time:
            duration = time.time() - self._start_time
            self.logger.info(f"✅ {operation_name} completed in {duration:.2f}s")

    def _update_progress(
        self,
        progress: float,
        message: str,
        callback: Optional[Callable[[float, str], None]] = None,
    ):
        """Update progress if callback is provided."""
        if callback:
            callback(progress, message)

    def _apply_confidence_threshold(
        self, candidates: List[DiscoveryCandidate]
    ) -> List[DiscoveryCandidate]:
        """Filter candidates by confidence threshold."""
        filtered = [
            c
            for c in candidates
            if c.confidence.value >= self.config.min_confidence_threshold
        ]

        if len(filtered) < len(candidates):
            self.logger.info(
                f"🔧 Confidence filtering: {len(filtered)}/{len(candidates)} candidates remain"
            )

        return filtered

    def _handle_error(
        self, error: Exception, operation: str, critical: bool = True
    ) -> bool:
        """
        Handle discovery errors.

        Args:
            error: The exception that occurred
            operation: Name of the operation that failed
            critical: Whether this is a critical error

        Returns:
            True if error was handled and operation can continue, False otherwise
        """
        error_msg = f"{operation} failed: {str(error)}"

        if critical:
            self.logger.error(error_msg)
            return False
        else:
            self.logger.warning(error_msg)
            return True

    def _log_discovery_summary(self, result: DiscoveryResult[T], operation_name: str):
        """Log a summary of discovery results."""
        self.logger.info(f"📊 {operation_name} Summary:")
        self.logger.info(f"   Assets discovered: {len(result.assets)}")
        self.logger.info(f"   Candidates processed: {len(result.candidates)}")
        self.logger.info(f"   Success rate: {result.success_rate:.1%}")

        if result.errors:
            self.logger.warning(f"   Errors: {len(result.errors)}")
        if result.warnings:
            self.logger.info(f"   Warnings: {len(result.warnings)}")


class SourceDiscovery(ABC):
    """Base class for discovery sources."""

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @abstractmethod
    def discover(self, **kwargs) -> Any:
        """Discover assets from this source."""
        pass

    def _log_source_result(self, count: int, source_type: str):
        """Log source discovery results."""
        self.logger.info(f"🔍 {self.name}: {count} {source_type} discovered")
