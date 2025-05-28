"""
Modern Progress Components for ReconForge
=========================================

Advanced progress visualization system with modern UX principles:
- Real-time progress tracking with smooth animations
- Phase-based progress indicators
- Contextual information and time estimates
- Beautiful visual design consistent with light theme
- Responsive and accessible design
"""

import streamlit as st
import time
import threading
from typing import Optional, Callable, Dict, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum
import math

# ============================================================================
# PROGRESS COMPONENT TYPES
# ============================================================================


class ProgressType(Enum):
    """Types of progress indicators available."""

    LINEAR = "linear"
    CIRCULAR = "circular"
    STEPPED = "stepped"
    PHASE_BASED = "phase_based"
    MULTI_LEVEL = "multi_level"


class ProgressState(Enum):
    """States of progress indicators."""

    IDLE = "idle"
    RUNNING = "running"
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    PAUSED = "paused"


@dataclass
class ProgressPhase:
    """Represents a phase in a multi-phase progress indicator."""

    name: str
    description: str
    weight: float = 1.0  # Relative weight of this phase
    icon: str = "🔄"
    estimated_duration: Optional[float] = None


@dataclass
class ProgressData:
    """Complete progress state information."""

    current_progress: float = 0.0
    current_phase: Optional[str] = None
    current_message: str = ""
    state: ProgressState = ProgressState.IDLE
    start_time: Optional[float] = None
    estimated_total_time: Optional[float] = None
    phases: Optional[List[ProgressPhase]] = None
    detailed_info: Optional[Dict[str, Any]] = None


# ============================================================================
# ADVANCED PROGRESS BAR COMPONENT
# ============================================================================


class ModernProgressBar:
    """Modern, animated progress bar with advanced UX features."""

    def __init__(self, container_key: str = "default_progress"):
        self.container_key = container_key
        self.data = ProgressData()
        self.last_update_time = 0
        self._container = None
        self._initialized = False

    def initialize(
        self,
        phases: Optional[List[ProgressPhase]] = None,
        estimated_total_time: Optional[float] = None,
        show_detailed_metrics: bool = True,
    ) -> None:
        """Initialize the progress bar with configuration."""
        self.data.phases = phases or []
        self.data.estimated_total_time = estimated_total_time
        self.data.start_time = time.time()
        self.data.state = ProgressState.RUNNING
        self._show_detailed_metrics = show_detailed_metrics

        # Create the container only once during initialization
        if not self._initialized:
            self._container = st.empty()
            self._initialized = True

    def update(
        self,
        progress: float,
        message: str = "",
        current_phase: Optional[str] = None,
        detailed_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update progress with advanced information."""
        # Rate limiting to prevent excessive updates
        current_time = time.time()
        if current_time - self.last_update_time < 0.1:  # Max 10 updates per second
            return

        self.data.current_progress = max(0.0, min(100.0, progress))
        self.data.current_message = message
        self.data.current_phase = current_phase
        self.data.detailed_info = detailed_info or {}
        self.last_update_time = current_time

        self._render()

    def complete(
        self, message: str = "Complete!", state: ProgressState = ProgressState.SUCCESS
    ) -> None:
        """Mark progress as complete."""
        self.data.current_progress = 100.0
        self.data.current_message = message
        self.data.state = state
        self._render()

    def error(self, message: str = "Error occurred") -> None:
        """Mark progress as error."""
        self.data.state = ProgressState.ERROR
        self.data.current_message = message
        self._render()

    def _render(self) -> None:
        """Render the modern progress bar UI."""
        # Initialize container if not done yet
        if not self._initialized:
            self._container = st.empty()
            self._initialized = True

        # Use the container to update content in place
        if self._container:
            with self._container.container():
                self._render_modern_progress_ui()

    def _render_modern_progress_ui(self) -> None:
        """Render the complete modern progress UI."""
        # Main progress container with modern styling
        st.markdown(
            f"""
        <div style="
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 16px;
            padding: 2rem;
            margin: 1.5rem 0;
            box-shadow: 0 8px 32px rgba(31, 38, 135, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.2);
            backdrop-filter: blur(4px);
        ">
            <div style="
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 1.5rem;
            ">
                <div style="
                    font-size: 1.4rem;
                    font-weight: 700;
                    color: #2c3e50;
                    display: flex;
                    align-items: center;
                    gap: 0.75rem;
                ">
                    {self._get_state_icon()} Live Reconnaissance Progress
                </div>
                <div style="
                    font-size: 2rem;
                    font-weight: 800;
                    color: {self._get_progress_color()};
                    text-shadow: 0 2px 4px rgba(0,0,0,0.1);
                ">
                    {self.data.current_progress:.1f}%
                </div>
            </div>
        """,
            unsafe_allow_html=True,
        )

        # Animated progress bar
        self._render_animated_progress_bar()

        # Current activity and phase information
        self._render_activity_section()

        # Time estimates and performance metrics
        if self._show_detailed_metrics:
            self._render_metrics_section()

        # Phase progression (if phases are defined)
        if self.data.phases:
            self._render_phase_progression()

        # Close main container
        st.markdown("</div>", unsafe_allow_html=True)

    def _render_animated_progress_bar(self) -> None:
        """Render animated progress bar with modern styling."""
        # Calculate smooth animation values
        progress_width = self.data.current_progress
        animation_speed = "2s" if self.data.state == ProgressState.RUNNING else "0.5s"

        st.markdown(
            f"""
        <div style="
            position: relative;
            width: 100%;
            height: 12px;
            background: linear-gradient(90deg, #e9ecef 0%, #f8f9fa 100%);
            border-radius: 6px;
            overflow: hidden;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 1.5rem;
        ">
            <div style="
                position: absolute;
                top: 0;
                left: 0;
                width: {progress_width}%;
                height: 100%;
                background: {self._get_gradient_colors()};
                border-radius: 6px;
                transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
                box-shadow: 0 2px 8px rgba(0,123,255,0.3);
            ">
                <div style="
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: linear-gradient(
                        90deg,
                        transparent 0%,
                        rgba(255,255,255,0.4) 50%,
                        transparent 100%
                    );
                    animation: shimmer {animation_speed} infinite;
                ">
                </div>
            </div>
        </div>
        
        <style>
        @keyframes shimmer {{
            0% {{ transform: translateX(-100%); }}
            100% {{ transform: translateX(100%); }}
        }}
        </style>
        """,
            unsafe_allow_html=True,
        )

    def _render_activity_section(self) -> None:
        """Render current activity and status information."""
        st.markdown(
            f"""
        <div style="
            background: rgba(255, 255, 255, 0.7);
            border-radius: 12px;
            padding: 1.25rem;
            margin-bottom: 1.5rem;
            border-left: 4px solid {self._get_progress_color()};
        ">
            <div style="
                display: flex;
                align-items: center;
                gap: 0.75rem;
                margin-bottom: 0.5rem;
            ">
                <span style="font-size: 1.2rem;">{self._get_activity_icon()}</span>
                <span style="
                    font-weight: 600;
                    color: #495057;
                    font-size: 0.95rem;
                ">
                    Current Activity
                </span>
            </div>
            <div style="
                color: #2c3e50;
                font-size: 1.05rem;
                font-weight: 500;
                line-height: 1.4;
            ">
                {self.data.current_message or "Initializing..."}
            </div>
        """,
            unsafe_allow_html=True,
        )

        # Current phase indicator
        if self.data.current_phase:
            st.markdown(
                f"""
            <div style="
                margin-top: 0.75rem;
                font-size: 0.9rem;
                color: #6c757d;
                font-weight: 500;
            ">
                📍 Phase: <strong>{self.data.current_phase}</strong>
            </div>
            """,
                unsafe_allow_html=True,
            )

        st.markdown("</div>", unsafe_allow_html=True)

    def _render_metrics_section(self) -> None:
        """Render performance metrics and time estimates."""
        if not self.data.start_time:
            return

        elapsed_time = time.time() - self.data.start_time

        # Calculate time estimates
        if self.data.current_progress > 0:
            estimated_total = elapsed_time / (self.data.current_progress / 100.0)
            estimated_remaining = estimated_total - elapsed_time
        else:
            estimated_total = self.data.estimated_total_time or 0
            estimated_remaining = estimated_total

        # Format time strings
        elapsed_str = self._format_duration(elapsed_time)
        remaining_str = self._format_duration(max(0, estimated_remaining))

        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown(
                f"""
            <div style="
                background: rgba(40, 167, 69, 0.1);
                border-radius: 10px;
                padding: 1rem;
                text-align: center;
                border: 1px solid rgba(40, 167, 69, 0.2);
            ">
                <div style="font-size: 1.5rem; margin-bottom: 0.25rem;">⏱️</div>
                <div style="font-size: 0.85rem; color: #6c757d; margin-bottom: 0.25rem;">Elapsed</div>
                <div style="font-size: 1.1rem; font-weight: 600; color: #28a745;">{elapsed_str}</div>
            </div>
            """,
                unsafe_allow_html=True,
            )

        with col2:
            st.markdown(
                f"""
            <div style="
                background: rgba(0, 123, 255, 0.1);
                border-radius: 10px;
                padding: 1rem;
                text-align: center;
                border: 1px solid rgba(0, 123, 255, 0.2);
            ">
                <div style="font-size: 1.5rem; margin-bottom: 0.25rem;">⏳</div>
                <div style="font-size: 0.85rem; color: #6c757d; margin-bottom: 0.25rem;">Remaining</div>
                <div style="font-size: 1.1rem; font-weight: 600; color: #007bff;">{remaining_str}</div>
            </div>
            """,
                unsafe_allow_html=True,
            )

        with col3:
            speed = (
                self.data.current_progress / max(elapsed_time, 1)
                if elapsed_time > 0
                else 0
            )
            st.markdown(
                f"""
            <div style="
                background: rgba(255, 193, 7, 0.1);
                border-radius: 10px;
                padding: 1rem;
                text-align: center;
                border: 1px solid rgba(255, 193, 7, 0.2);
            ">
                <div style="font-size: 1.5rem; margin-bottom: 0.25rem;">🚀</div>
                <div style="font-size: 0.85rem; color: #6c757d; margin-bottom: 0.25rem;">Speed</div>
                <div style="font-size: 1.1rem; font-weight: 600; color: #ffc107;">{speed:.1f}%/s</div>
            </div>
            """,
                unsafe_allow_html=True,
            )

    def _render_phase_progression(self) -> None:
        """Render phase progression indicator."""
        if not self.data.phases:
            return

        st.markdown("### 📋 Discovery Phases")

        current_phase_index = self._get_current_phase_index()

        for i, phase in enumerate(self.data.phases):
            status = self._get_phase_status(i, current_phase_index)
            self._render_phase_step(phase, i + 1, status)

    def _render_phase_step(
        self, phase: ProgressPhase, step_num: int, status: str
    ) -> None:
        """Render individual phase step."""
        status_colors = {
            "completed": "#28a745",
            "current": "#007bff",
            "upcoming": "#6c757d",
        }

        status_icons = {"completed": "✅", "current": "🔄", "upcoming": "⏳"}

        color = status_colors.get(status, "#6c757d")
        icon = status_icons.get(status, "⏳")

        st.markdown(
            f"""
        <div style="
            display: flex;
            align-items: center;
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            background: rgba(255, 255, 255, 0.5);
            border-radius: 8px;
            border-left: 4px solid {color};
        ">
            <div style="
                width: 2.5rem;
                height: 2.5rem;
                border-radius: 50%;
                background: {color};
                color: white;
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: bold;
                margin-right: 1rem;
                font-size: 0.9rem;
            ">
                {step_num}
            </div>
            <div style="flex: 1;">
                <div style="
                    font-weight: 600;
                    color: #2c3e50;
                    margin-bottom: 0.25rem;
                ">
                    {icon} {phase.name}
                </div>
                <div style="
                    font-size: 0.9rem;
                    color: #6c757d;
                ">
                    {phase.description}
                </div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    def _get_state_icon(self) -> str:
        """Get icon for current state."""
        icons = {
            ProgressState.IDLE: "⏸️",
            ProgressState.RUNNING: "🔄",
            ProgressState.SUCCESS: "✅",
            ProgressState.ERROR: "❌",
            ProgressState.WARNING: "⚠️",
            ProgressState.PAUSED: "⏸️",
        }
        return icons.get(self.data.state, "🔄")

    def _get_activity_icon(self) -> str:
        """Get icon for current activity."""
        if self.data.state == ProgressState.RUNNING:
            # Rotate through different activity icons
            icons = ["🔍", "📡", "🌐", "☁️", "🔧"]
            return icons[int(time.time()) % len(icons)]
        return self._get_state_icon()

    def _get_progress_color(self) -> str:
        """Get color for current progress state."""
        colors = {
            ProgressState.IDLE: "#6c757d",
            ProgressState.RUNNING: "#007bff",
            ProgressState.SUCCESS: "#28a745",
            ProgressState.ERROR: "#dc3545",
            ProgressState.WARNING: "#ffc107",
            ProgressState.PAUSED: "#6f42c1",
        }
        return colors.get(self.data.state, "#007bff")

    def _get_gradient_colors(self) -> str:
        """Get gradient colors for progress bar."""
        if self.data.state == ProgressState.RUNNING:
            return "linear-gradient(90deg, #007bff 0%, #0056b3 100%)"
        elif self.data.state == ProgressState.SUCCESS:
            return "linear-gradient(90deg, #28a745 0%, #1e7e34 100%)"
        elif self.data.state == ProgressState.ERROR:
            return "linear-gradient(90deg, #dc3545 0%, #c82333 100%)"
        elif self.data.state == ProgressState.WARNING:
            return "linear-gradient(90deg, #ffc107 0%, #e0a800 100%)"
        else:
            return "linear-gradient(90deg, #6c757d 0%, #5a6268 100%)"

    def _get_current_phase_index(self) -> int:
        """Get index of current phase."""
        if not self.data.current_phase or not self.data.phases:
            return -1
        for i, phase in enumerate(self.data.phases):
            if phase.name == self.data.current_phase:
                return i
        return -1

    def _get_phase_status(self, phase_index: int, current_index: int) -> str:
        """Get status of a phase (completed, current, upcoming)."""
        if phase_index < current_index:
            return "completed"
        elif phase_index == current_index:
            return "current"
        else:
            return "upcoming"

    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            minutes = seconds // 60
            secs = seconds % 60
            return f"{minutes:.0f}m {secs:.0f}s"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours:.0f}h {minutes:.0f}m"


# ============================================================================
# STREAMLINED PROGRESS COMPONENTS
# ============================================================================


def create_modern_progress_bar(key: str = "progress") -> ModernProgressBar:
    """Create a modern progress bar component."""
    if key not in st.session_state:
        st.session_state[key] = ModernProgressBar(key)
    return st.session_state[key]


def render_quick_progress(progress: float, message: str = "", container=None):
    """Render a quick, simple progress indicator."""
    if container is None:
        container = st

    # Quick modern progress bar
    container.markdown(
        f"""
    <div style="
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 4px 16px rgba(31, 38, 135, 0.1);
    ">
        <div style="
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        ">
            <span style="
                font-weight: 600;
                color: #2c3e50;
                font-size: 1.1rem;
            ">
                {message or "Processing..."}
            </span>
            <span style="
                font-weight: 700;
                color: #007bff;
                font-size: 1.2rem;
            ">
                {progress:.1f}%
            </span>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )


def render_phase_indicator(current_phase: str, phases: List[str], container=None):
    """Render a horizontal phase indicator."""
    if container is None:
        container = st

    try:
        current_index = phases.index(current_phase)
    except ValueError:
        current_index = 0

    phase_html = (
        "<div style='display: flex; justify-content: space-between; margin: 1rem 0;'>"
    )

    for i, phase in enumerate(phases):
        if i <= current_index:
            color = "#28a745"
            icon = "✅" if i < current_index else "🔄"
        else:
            color = "#dee2e6"
            icon = "⏳"

        phase_html += f"""
        <div style="
            display: flex;
            flex-direction: column;
            align-items: center;
            flex: 1;
            padding: 0.5rem;
        ">
            <div style="
                width: 2rem;
                height: 2rem;
                border-radius: 50%;
                background: {color};
                color: white;
                display: flex;
                align-items: center;
                justify-content: center;
                margin-bottom: 0.5rem;
                font-size: 0.8rem;
            ">
                {icon}
            </div>
            <span style="
                font-size: 0.8rem;
                color: {'#2c3e50' if i <= current_index else '#6c757d'};
                font-weight: {'600' if i <= current_index else '400'};
                text-align: center;
            ">
                {phase}
            </span>
        </div>
        """

        # Add connector line (except for last phase)
        if i < len(phases) - 1:
            line_color = "#28a745" if i < current_index else "#dee2e6"
            phase_html += f"""
            <div style="
                height: 2px;
                background: {line_color};
                align-self: center;
                width: 2rem;
                margin-top: 1rem;
            "></div>
            """

    phase_html += "</div>"
    container.markdown(phase_html, unsafe_allow_html=True)


# ============================================================================
# INTEGRATION HELPERS
# ============================================================================


def setup_reconnaissance_progress() -> ModernProgressBar:
    """Setup progress bar specifically for reconnaissance operations."""
    phases = [
        ProgressPhase("Domain Discovery", "Finding domains and subdomains", icon="🌐"),
        ProgressPhase("ASN Discovery", "Identifying autonomous systems", icon="📡"),
        ProgressPhase("IP Range Discovery", "Mapping IP address ranges", icon="💻"),
        ProgressPhase("Cloud Detection", "Detecting cloud services", icon="☁️"),
    ]

    progress_bar = create_modern_progress_bar("recon_progress")
    progress_bar.initialize(
        phases=phases,
        estimated_total_time=300,  # 5 minutes estimate
        show_detailed_metrics=True,
    )

    return progress_bar


def create_progress_callbacks(
    progress_bar: ModernProgressBar,
) -> Tuple[Callable, Callable]:
    """Create progress and status callbacks for reconnaissance operations."""

    def progress_callback(progress: float, message: str):
        """Progress callback function."""
        progress_bar.update(progress, message)

    def status_callback(icon: str, message: str):
        """Status callback function."""
        # Extract phase information from message if available
        phase_keywords = {
            "domain": "Domain Discovery",
            "asn": "ASN Discovery",
            "ip": "IP Range Discovery",
            "cloud": "Cloud Detection",
        }

        current_phase = None
        for keyword, phase_name in phase_keywords.items():
            if keyword.lower() in message.lower():
                current_phase = phase_name
                break

        progress_bar.update(
            progress_bar.data.current_progress,
            f"{icon} {message}",
            current_phase=current_phase,
        )

    return progress_callback, status_callback
