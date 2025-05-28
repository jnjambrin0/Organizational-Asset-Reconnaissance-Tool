"""
Intelligent Navigation System for ReconForge
Provides contextual navigation, breadcrumbs, quick actions, and guided workflows.
"""

import streamlit as st
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import json


class IntelligentNavigation:
    """Smart navigation system that adapts to user context and provides guided workflows."""

    def __init__(self):
        self.navigation_history = []
        self.user_preferences = {}
        self.workflow_states = {}

    def render_contextual_breadcrumbs(
        self, current_page: str, scan_context: Optional[Dict] = None
    ):
        """Render intelligent breadcrumbs based on current context."""

        breadcrumb_items = self._generate_breadcrumbs(current_page, scan_context)

        if not breadcrumb_items:
            return

        breadcrumb_html = """
        <div style="
            background: #F8F9FA;
            border-radius: 8px;
            padding: 0.75rem 1rem;
            margin-bottom: 1.5rem;
            border: 1px solid #E9ECEF;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.9rem;
        ">
            <span style="color: #6C757D;">📍</span>
        """

        for i, item in enumerate(breadcrumb_items):
            if i > 0:
                breadcrumb_html += """
                <span style="color: #ADB5BD; margin: 0 0.5rem;">›</span>
                """

            if item.get("clickable", False):
                breadcrumb_html += f"""
                <span style="
                    color: #0066CC;
                    cursor: pointer;
                    text-decoration: none;
                    transition: color 0.2s ease;
                " onclick="streamlitNavigate('{item['page']}')"
                onmouseover="this.style.color='#004499'"
                onmouseout="this.style.color='#0066CC'">
                    {item['label']}
                </span>
                """
            else:
                breadcrumb_html += f"""
                <span style="color: #212529; font-weight: 500;">
                    {item['label']}
                </span>
                """

        breadcrumb_html += "</div>"

        st.html(breadcrumb_html)

    def render_quick_actions_panel(self, context: Dict):
        """Render contextual quick actions based on current state."""

        actions = self._generate_contextual_actions(context)

        if not actions:
            return

        st.html(
            """
        <div class="custom-card" style="margin-bottom: 1.5rem;">
            <div class="card-title">⚡ Quick Actions</div>
            <p style="color: #6C757D; margin-bottom: 1rem; font-size: 0.9rem;">
                Suggested actions based on your current context
            </p>
        </div>
        """
        )

        # Render actions in columns
        if len(actions) <= 2:
            cols = st.columns(len(actions))
        elif len(actions) <= 4:
            cols = st.columns(2)
        else:
            cols = st.columns(3)

        for i, action in enumerate(actions):
            col_index = i % len(cols)
            with cols[col_index]:
                self._render_action_card(action)

    def render_workflow_guide(self, current_step: str, workflow_type: str = "scan"):
        """Render a guided workflow interface."""

        workflow_steps = self._get_workflow_steps(workflow_type)
        current_step_index = next(
            (i for i, step in enumerate(workflow_steps) if step["id"] == current_step),
            0,
        )

        st.html(
            """
        <div class="custom-card" style="margin-bottom: 1.5rem;">
            <div class="card-title">🗺️ Workflow Guide</div>
            <p style="color: #6C757D; margin-bottom: 1rem; font-size: 0.9rem;">
                Follow these steps for optimal reconnaissance results
            </p>
        </div>
        """
        )

        # Progress indicator
        progress_percentage = ((current_step_index + 1) / len(workflow_steps)) * 100

        st.html(
            f"""
        <div style="
            background: #F0F3F7;
            border-radius: 20px;
            height: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        ">
            <div style="
                background: linear-gradient(90deg, #0066CC, #004499);
                height: 100%;
                width: {progress_percentage}%;
                border-radius: 20px;
                transition: width 0.6s ease;
            "></div>
        </div>
        """
        )

        # Step cards
        for i, step in enumerate(workflow_steps):
            status = self._get_step_status(i, current_step_index)
            self._render_workflow_step(step, status, i + 1)

    def render_navigation_sidebar_enhancement(self):
        """Enhance sidebar with intelligent navigation features."""

        st.sidebar.markdown("---")

        # Recent activity
        st.sidebar.markdown(
            """
        <div style="
            background: #F0F8FF;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            border: 1px solid #B0D4F1;
        ">
            <div style="
                font-size: 0.9rem;
                font-weight: 600;
                color: #1a5490;
                margin-bottom: 0.5rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            ">
                🕒 Recent Activity
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        recent_activities = self._get_recent_activities()
        for activity in recent_activities:
            st.sidebar.markdown(
                f"""
            <div style="
                background: white;
                border-radius: 6px;
                padding: 0.75rem;
                margin-bottom: 0.5rem;
                border: 1px solid #E9ECEF;
                cursor: pointer;
                transition: all 0.2s ease;
            " onclick="loadActivity('{activity['id']}')"
            onmouseover="this.style.backgroundColor='#F8F9FA'"
            onmouseout="this.style.backgroundColor='white'">
                <div style="font-weight: 500; color: #212529; font-size: 0.85rem;">
                    {activity['icon']} {activity['title']}
                </div>
                <div style="color: #6C757D; font-size: 0.75rem; margin-top: 0.25rem;">
                    {activity['time']}
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )

        # Navigation shortcuts
        st.sidebar.markdown("### 🚀 Quick Navigation")

        nav_shortcuts = [
            {"label": "New Scan", "icon": "🎯", "page": "scan"},
            {"label": "View Results", "icon": "📊", "page": "results"},
            {"label": "Export Data", "icon": "📥", "page": "export"},
            {"label": "Analytics", "icon": "📈", "page": "analytics"},
        ]

        for shortcut in nav_shortcuts:
            if st.sidebar.button(
                f"{shortcut['icon']} {shortcut['label']}",
                key=f"nav_{shortcut['page']}",
                use_container_width=True,
            ):
                st.session_state.current_tab = shortcut["page"]
                st.rerun()

    def _generate_breadcrumbs(
        self, current_page: str, scan_context: Optional[Dict] = None
    ) -> List[Dict]:
        """Generate intelligent breadcrumbs based on context."""

        breadcrumbs = [{"label": "Home", "page": "dashboard", "clickable": True}]

        if current_page == "scan":
            breadcrumbs.append(
                {"label": "Reconnaissance", "page": "scan", "clickable": False}
            )
            if scan_context and scan_context.get("target_organization"):
                breadcrumbs.append(
                    {
                        "label": scan_context["target_organization"],
                        "page": "scan_results",
                        "clickable": False,
                    }
                )

        elif current_page == "results":
            breadcrumbs.append(
                {"label": "Results", "page": "results", "clickable": False}
            )
            if scan_context and scan_context.get("scan_id"):
                breadcrumbs.append(
                    {
                        "label": f"Scan #{scan_context['scan_id']}",
                        "page": "scan_detail",
                        "clickable": False,
                    }
                )

        elif current_page == "analytics":
            breadcrumbs.append(
                {"label": "Analytics", "page": "analytics", "clickable": False}
            )

        elif current_page == "export":
            breadcrumbs.append(
                {"label": "Export", "page": "export", "clickable": False}
            )

        return breadcrumbs

    def _generate_contextual_actions(self, context: Dict) -> List[Dict]:
        """Generate contextual quick actions based on current state."""

        actions = []

        # Default actions
        if context.get("page") == "dashboard":
            actions.extend(
                [
                    {
                        "title": "Start New Scan",
                        "description": "Begin reconnaissance for a new organization",
                        "icon": "🎯",
                        "action": "new_scan",
                        "priority": "high",
                    },
                    {
                        "title": "View Latest Results",
                        "description": "Check your most recent scan results",
                        "icon": "📊",
                        "action": "latest_results",
                        "priority": "medium",
                    },
                ]
            )

        # Scan context actions
        if context.get("scan_running"):
            actions.append(
                {
                    "title": "Monitor Progress",
                    "description": "View real-time scan progress and metrics",
                    "icon": "📈",
                    "action": "monitor_scan",
                    "priority": "high",
                }
            )

        # Results context actions
        if context.get("has_results"):
            actions.extend(
                [
                    {
                        "title": "Export Results",
                        "description": "Download scan data in various formats",
                        "icon": "📥",
                        "action": "export_results",
                        "priority": "medium",
                    },
                    {
                        "title": "Compare Scans",
                        "description": "Compare with previous scan results",
                        "icon": "🔍",
                        "action": "compare_scans",
                        "priority": "low",
                    },
                ]
            )

        return actions

    def _render_action_card(self, action: Dict):
        """Render an individual action card."""

        priority_colors = {
            "high": {"bg": "#E6F3FF", "border": "#0066CC", "button": "#0066CC"},
            "medium": {"bg": "#FFF8E1", "border": "#FFC107", "button": "#F57C00"},
            "low": {"bg": "#F0F9FF", "border": "#17A2B8", "button": "#17A2B8"},
        }

        colors = priority_colors.get(
            action.get("priority", "medium"), priority_colors["medium"]
        )

        st.html(
            f"""
    <div style="
        background: {colors['bg']};
        border: 1px solid {colors['border']};
        border-radius: 12px;
        padding: 1rem;
        margin-bottom: 1rem;
        transition: all 0.3s ease;
        cursor: pointer;
    " onclick="executeAction('{action['action']}')"
    onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 8px 25px rgba(0,0,0,0.1)'"
    onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='none'">
        <div style="font-size: 1.5rem; margin-bottom: 0.5rem; text-align: center;">
            {action['icon']}
        </div>
        <div style="font-weight: 600; color: #212529; margin-bottom: 0.5rem; text-align: center;">
            {action['title']}
        </div>
        <div style="color: #6C757D; font-size: 0.85rem; text-align: center; line-height: 1.4;">
            {action['description']}
        </div>
    </div>
    """
        )

    def _get_workflow_steps(self, workflow_type: str) -> List[Dict]:
        """Get workflow steps for different types of workflows."""

        workflows = {
            "scan": [
                {
                    "id": "setup",
                    "title": "Setup Target",
                    "description": "Configure organization name and scan parameters",
                    "icon": "⚙️",
                },
                {
                    "id": "discovery",
                    "title": "Asset Discovery",
                    "description": "Discover domains, ASNs, and cloud services",
                    "icon": "🔍",
                },
                {
                    "id": "analysis",
                    "title": "Analysis",
                    "description": "Analyze discovered assets and generate insights",
                    "icon": "📊",
                },
                {
                    "id": "results",
                    "title": "Results",
                    "description": "Review findings and export data",
                    "icon": "✅",
                },
            ],
            "analysis": [
                {
                    "id": "data_review",
                    "title": "Data Review",
                    "description": "Review discovered assets and their relationships",
                    "icon": "📋",
                },
                {
                    "id": "security_assessment",
                    "title": "Security Assessment",
                    "description": "Identify potential security concerns and risks",
                    "icon": "🔒",
                },
                {
                    "id": "recommendations",
                    "title": "Recommendations",
                    "description": "Generate actionable security recommendations",
                    "icon": "💡",
                },
            ],
        }

        return workflows.get(workflow_type, [])

    def _get_step_status(self, step_index: int, current_index: int) -> str:
        """Determine the status of a workflow step."""

        if step_index < current_index:
            return "completed"
        elif step_index == current_index:
            return "current"
        else:
            return "pending"

    def _render_workflow_step(self, step: Dict, status: str, step_number: int):
        """Render an individual workflow step."""

        status_styles = {
            "completed": {
                "bg": "#E6F9EA",
                "border": "#28A745",
                "icon_bg": "#28A745",
                "text_color": "#212529",
            },
            "current": {
                "bg": "#E6F3FF",
                "border": "#0066CC",
                "icon_bg": "#0066CC",
                "text_color": "#212529",
            },
            "pending": {
                "bg": "#F8F9FA",
                "border": "#DEE2E6",
                "icon_bg": "#6C757D",
                "text_color": "#6C757D",
            },
        }

        style = status_styles[status]
        status_icon = (
            "✅" if status == "completed" else "🔄" if status == "current" else "⏳"
        )

        st.html(
            f"""
        <div style="
            background: {style['bg']};
            border: 2px solid {style['border']};
            border-radius: 12px;
            padding: 1rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            transition: all 0.3s ease;
        ">
            <div style="
                background: {style['icon_bg']};
                color: white;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 600;
                font-size: 0.9rem;
                flex-shrink: 0;
            ">
                {step_number}
            </div>
            
            <div style="flex-grow: 1;">
                <div style="
                    font-weight: 600;
                    color: {style['text_color']};
                    margin-bottom: 0.25rem;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                ">
                    {step['icon']} {step['title']}
                    <span style="font-size: 1rem;">{status_icon}</span>
                </div>
                <div style="
                    color: #6C757D;
                    font-size: 0.9rem;
                    line-height: 1.4;
                ">
                    {step['description']}
                </div>
            </div>
        </div>
        """
        )

    def _get_recent_activities(self) -> List[Dict]:
        """Get recent user activities for sidebar display."""

        # This would normally come from database or session state
        return [
            {
                "id": "scan_001",
                "title": "Microsoft Corporation",
                "icon": "🎯",
                "time": "2 hours ago",
            },
            {
                "id": "export_001",
                "title": "Exported AWS Results",
                "icon": "📥",
                "time": "1 day ago",
            },
            {
                "id": "scan_002",
                "title": "Google LLC",
                "icon": "🔍",
                "time": "3 days ago",
            },
        ]


def render_smart_navigation_header():
    """Render a smart navigation header with contextual information."""

    # Get current context
    current_page = st.session_state.get("current_tab", "🎯 Dashboard")
    scan_running = st.session_state.get("scan_running", False)
    has_results = st.session_state.get("scan_results") is not None

    st.html(
        f"""
    <div style="
        background: linear-gradient(135deg, #F8F9FA 0%, #E9ECEF 100%);
        border-radius: 12px;
        padding: 1rem 1.5rem;
        margin-bottom: 1.5rem;
        border: 1px solid #DEE2E6;
        display: flex;
        justify-content: space-between;
        align-items: center;
    ">
        <div>
            <h4 style="margin: 0; color: #212529; font-size: 1.1rem; font-weight: 600;">
                {current_page}
            </h4>
            <p style="margin: 0; color: #6C757D; font-size: 0.9rem;">
                {"🔄 Scan in progress..." if scan_running else "📊 Ready for analysis" if has_results else "🎯 Ready to start reconnaissance"}
            </p>
        </div>
        
        <div style="display: flex; align-items: center; gap: 1rem;">
            <div style="
                background: {'#FFF8E1' if scan_running else '#E6F9EA' if has_results else '#E6F3FF'};
                color: {'#F57C00' if scan_running else '#28A745' if has_results else '#0066CC'};
                padding: 0.5rem 1rem;
                border-radius: 20px;
                font-size: 0.85rem;
                font-weight: 500;
                border: 1px solid {'#FFC107' if scan_running else '#28A745' if has_results else '#0066CC'};
            ">
                {"⏳ Processing" if scan_running else "✅ Data Available" if has_results else "🚀 Ready"}
            </div>
        </div>
    </div>
    """
    )


# Global navigation instance
navigation = IntelligentNavigation()
