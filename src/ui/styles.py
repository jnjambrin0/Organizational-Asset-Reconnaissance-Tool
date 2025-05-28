"""
Modern Professional Light Theme CSS for ReconForge.
Based on Streamlit best practices 2024.
"""


def get_custom_css():
    """Return modern professional light theme CSS."""

    return """
    <style>
    /* ===== IMPORT MODERN FONTS ===== */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    /* ===== MODERN LIGHT THEME VARIABLES ===== */
    :root {
        /* Primary Colors */
        --primary-blue: #0066CC;
        --primary-blue-hover: #0052A3;
        --primary-blue-light: #E6F3FF;
        
        /* Background Colors */
        --bg-primary: #FFFFFF;
        --bg-secondary: #F8F9FA;
        --bg-tertiary: #E9ECEF;
        --bg-hover: #F1F3F4;
        
        /* Text Colors */
        --text-primary: #212529;
        --text-secondary: #6C757D;
        --text-muted: #ADB5BD;
        
        /* Border Colors */
        --border-light: #DEE2E6;
        --border-medium: #CED4DA;
        --border-dark: #ADB5BD;
        
        /* Status Colors */
        --success: #28A745;
        --warning: #FFC107;
        --danger: #DC3545;
        --info: #17A2B8;
        
        /* Shadows */
        --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
        --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        
        /* Border Radius */
        --radius-sm: 4px;
        --radius-md: 8px;
        --radius-lg: 12px;
        
        /* Spacing */
        --space-xs: 0.25rem;
        --space-sm: 0.5rem;
        --space-md: 1rem;
        --space-lg: 1.5rem;
        --space-xl: 2rem;
        
        /* Progress System Colors */
        --progress-bg: #F0F3F7;
        --progress-fill: linear-gradient(135deg, #0066CC 0%, #0052A3 100%);
        --progress-success: linear-gradient(135deg, #28A745 0%, #20A038 100%);
        --progress-warning: linear-gradient(135deg, #FFC107 0%, #E6AC00 100%);
        --progress-error: linear-gradient(135deg, #DC3545 0%, #C63637 100%);
    }
    
    /* ===== GLOBAL APP STYLES ===== */
    .stApp {
        background-color: var(--bg-primary) !important;
        color: var(--text-primary) !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif !important;
    }
    
    /* ===== FIX MAIN CONTAINER MARGINS AND PADDING ===== */
    /* Modern Streamlit main container - more compact */
    div[data-testid="stMainBlockContainer"] {
        padding: var(--space-md) var(--space-lg) !important;
        max-width: 1400px !important;
    }
    
    /* Remove excessive top padding */
    section[data-testid="stMain"] {
        padding-top: var(--space-sm) !important;
    }
    
    /* Fix block container spacing - more compact */
    .block-container {
        padding: var(--space-sm) var(--space-md) !important;
        margin: 0 auto !important;
    }
    
    /* ===== SIDEBAR IMPROVEMENTS ===== */
    section[data-testid="stSidebar"] {
        background-color: var(--bg-secondary) !important;
        border-right: 1px solid var(--border-light) !important;
    }
    
    .css-1d391kg {
        background-color: var(--bg-secondary) !important;
        padding: var(--space-lg) !important;
    }
    
    /* ===== HEADER STYLES ===== */
    .main-header {
        background: linear-gradient(135deg, #0066CC 0%, #004499 100%);
        color: white;
        padding: var(--space-lg) var(--space-xl);
        border-radius: var(--radius-lg);
        margin-bottom: var(--space-md);
        box-shadow: var(--shadow-md);
    }
    
    .main-header h1 {
        font-size: 2.25rem;
        font-weight: 700;
        margin-bottom: var(--space-xs);
        color: white !important;
        line-height: 1.2;
    }
    
    .main-header h3 {
        font-size: 1.1rem;
        font-weight: 500;
        margin-bottom: var(--space-xs);
        opacity: 0.9;
        color: white !important;
        line-height: 1.3;
    }
    
    .main-header p {
        font-size: 0.95rem;
        opacity: 0.8;
        color: white !important;
        margin-bottom: 0;
        line-height: 1.4;
    }
    
    /* ===== CARD COMPONENTS ===== */
    .custom-card {
        background: var(--bg-primary);
        border: 1px solid var(--border-light);
        border-radius: var(--radius-md);
        padding: var(--space-md);
        margin-bottom: var(--space-md);
        box-shadow: var(--shadow-sm);
        transition: all 0.2s ease;
    }
    
    .custom-card:hover {
        box-shadow: var(--shadow-md);
        border-color: var(--border-medium);
        transform: translateY(-1px);
    }
    
    .card-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: var(--space-sm);
        display: flex;
        align-items: center;
        gap: var(--space-sm);
    }
    
    /* Feature cards specific styling */
    .feature-card {
        transition: all 0.3s ease;
    }
    
    .feature-card:hover {
        transform: translateY(-3px);
        box-shadow: var(--shadow-lg);
        border-color: var(--primary-blue);
    }
    
    /* ===== METRIC CARDS ===== */
    .metric-card {
        background: var(--bg-primary);
        border: 1px solid var(--border-light);
        border-radius: var(--radius-md);
        padding: var(--space-lg);
        text-align: center;
        transition: all 0.2s ease;
        box-shadow: var(--shadow-sm);
        position: relative;
        overflow: hidden;
    }
    
    .metric-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: var(--primary-blue);
        opacity: 0;
        transition: opacity 0.2s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: var(--shadow-md);
        border-color: var(--primary-blue);
    }
    
    .metric-card:hover::before {
        opacity: 1;
    }
    
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: var(--primary-blue);
        margin-bottom: var(--space-xs);
        line-height: 1.2;
    }
    
    .metric-label {
        font-size: 0.875rem;
        color: var(--text-secondary);
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .metric-icon {
        font-size: 1.5rem;
        margin-bottom: var(--space-sm);
        display: block;
    }
    
    /* ===== MODERN PROGRESS SYSTEM ===== */
    .progress-system {
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        border-radius: 16px;
        padding: 2rem;
        margin: 1.5rem 0;
        box-shadow: 0 8px 32px rgba(31, 38, 135, 0.15);
        border: 1px solid rgba(255, 255, 255, 0.2);
        backdrop-filter: blur(4px);
    }
    
    .progress-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 1.5rem;
    }
    
    .progress-title {
        font-size: 1.4rem;
        font-weight: 700;
        color: #2c3e50;
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
    
    .progress-percentage {
        font-size: 2rem;
        font-weight: 800;
        text-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .progress-bar-modern {
        position: relative;
        width: 100%;
        height: 12px;
        background: var(--progress-bg);
        border-radius: 6px;
        overflow: hidden;
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
        margin-bottom: 1.5rem;
    }
    
    .progress-fill-modern {
        height: 100%;
        background: var(--progress-fill);
        border-radius: 6px;
        position: relative;
        transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    .progress-shimmer {
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, 
            transparent, 
            rgba(255, 255, 255, 0.4), 
            transparent);
        animation: shimmer 2s infinite;
    }
    
    @keyframes shimmer {
        0% { transform: translateX(-100%); }
        100% { transform: translateX(100%); }
    }
    
    .progress-activity {
        background: #f0f9ff;
        border: 1px solid #b0d4f1;
        border-radius: 12px;
        padding: 1rem 1.5rem;
        margin-bottom: 1rem;
    }
    
    .progress-activity-header {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 0.5rem;
    }
    
    .progress-activity-icon {
        font-size: 1.25rem;
        animation: rotate 2s linear infinite;
    }
    
    @keyframes rotate {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
    
    .progress-activity-title {
        font-size: 1rem;
        font-weight: 600;
        color: #1a5490;
    }
    
    .progress-activity-message {
        color: #5a7ba7;
        font-size: 0.9rem;
        font-style: italic;
    }
    
    .progress-metrics {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
        gap: 1rem;
        margin-bottom: 1rem;
    }
    
    .progress-metric {
        text-align: center;
        padding: 0.75rem;
        background: rgba(255, 255, 255, 0.7);
        border-radius: 8px;
        border: 1px solid rgba(0, 102, 204, 0.1);
    }
    
    .progress-metric-label {
        font-size: 0.75rem;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 0.25rem;
    }
    
    .progress-metric-value {
        font-size: 1.1rem;
        font-weight: 600;
        color: var(--primary-blue);
    }
    
    .progress-phases {
        display: flex;
        align-items: center;
        gap: 1rem;
        padding: 1rem;
        background: rgba(255, 255, 255, 0.5);
        border-radius: 12px;
        border: 1px solid rgba(0, 102, 204, 0.1);
        overflow-x: auto;
    }
    
    .progress-phase {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.5rem 1rem;
        border-radius: 8px;
        font-size: 0.875rem;
        font-weight: 500;
        white-space: nowrap;
        transition: all 0.2s ease;
    }
    
    .progress-phase-completed {
        background: #d4edda;
        color: #155724;
        border: 1px solid #c3e6cb;
    }
    
    .progress-phase-active {
        background: #cce5ff;
        color: #0066cc;
        border: 1px solid #99d1ff;
        box-shadow: 0 0 0 2px rgba(0, 102, 204, 0.2);
    }
    
    .progress-phase-pending {
        background: #f8f9fa;
        color: #6c757d;
        border: 1px solid #dee2e6;
    }
    
    /* ===== BUTTONS ===== */
    .stButton > button {
        background: var(--primary-blue) !important;
        color: white !important;
        border: none !important;
        border-radius: var(--radius-md) !important;
        padding: var(--space-sm) var(--space-lg) !important;
        font-weight: 500 !important;
        font-size: 0.95rem !important;
        transition: all 0.2s ease !important;
        box-shadow: var(--shadow-sm) !important;
    }
    
    .stButton > button:hover {
        background: var(--primary-blue-hover) !important;
        transform: translateY(-1px) !important;
        box-shadow: var(--shadow-md) !important;
    }
    
    .stButton > button:active {
        transform: translateY(0) !important;
    }
    
    /* ===== INPUTS ===== */
    .stTextInput > div > div > input {
        background: var(--bg-primary) !important;
        border: 1px solid var(--border-medium) !important;
        border-radius: var(--radius-md) !important;
        color: var(--text-primary) !important;
        padding: var(--space-sm) var(--space-md) !important;
        font-size: 0.95rem !important;
        transition: all 0.2s ease !important;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: var(--primary-blue) !important;
        box-shadow: 0 0 0 3px var(--primary-blue-light) !important;
    }
    
    .stTextArea > div > div > textarea {
        background: var(--bg-primary) !important;
        border: 1px solid var(--border-medium) !important;
        border-radius: var(--radius-md) !important;
        color: var(--text-primary) !important;
        padding: var(--space-md) !important;
        font-size: 0.95rem !important;
        transition: all 0.2s ease !important;
    }
    
    .stTextArea > div > div > textarea:focus {
        border-color: var(--primary-blue) !important;
        box-shadow: 0 0 0 3px var(--primary-blue-light) !important;
    }
    
    /* ===== SELECTBOX ===== */
    .stSelectbox > div > div > select {
        background: var(--bg-primary) !important;
        border: 1px solid var(--border-medium) !important;
        border-radius: var(--radius-md) !important;
        color: var(--text-primary) !important;
        padding: var(--space-sm) var(--space-md) !important;
    }
    
    /* ===== TABS ===== */
    .stTabs > div > div > div > div {
        background: var(--bg-secondary) !important;
        border-radius: var(--radius-md) !important;
        border: 1px solid var(--border-light) !important;
        padding: var(--space-xs) !important;
    }
    
    .stTabs > div > div > div > div > button {
        background: transparent !important;
        color: var(--text-secondary) !important;
        border-radius: var(--radius-sm) !important;
        margin: 0 !important;
        padding: var(--space-sm) var(--space-md) !important;
        font-weight: 500 !important;
        transition: all 0.2s ease !important;
        border: none !important;
    }
    
    .stTabs > div > div > div > div > button[aria-selected="true"] {
        background: var(--primary-blue) !important;
        color: white !important;
        box-shadow: var(--shadow-sm) !important;
    }
    
    .stTabs > div > div > div > div > button:hover {
        background: var(--bg-hover) !important;
        color: var(--text-primary) !important;
    }
    
    /* ===== EXPANDER ===== */
    .streamlit-expanderHeader {
        background: var(--bg-secondary) !important;
        border: 1px solid var(--border-light) !important;
        border-radius: var(--radius-md) !important;
        color: var(--text-primary) !important;
        font-weight: 500 !important;
        padding: var(--space-md) !important;
        transition: all 0.2s ease !important;
    }
    
    .streamlit-expanderHeader:hover {
        background: var(--bg-hover) !important;
        border-color: var(--border-medium) !important;
    }
    
    .streamlit-expanderContent {
        background: var(--bg-primary) !important;
        border: 1px solid var(--border-light) !important;
        border-top: none !important;
        border-radius: 0 0 var(--radius-md) var(--radius-md) !important;
        padding: var(--space-lg) !important;
    }
    
    /* ===== DATAFRAME ===== */
    .stDataFrame {
        background: var(--bg-primary) !important;
        border-radius: var(--radius-md) !important;
        overflow: hidden !important;
        border: 1px solid var(--border-light) !important;
        box-shadow: var(--shadow-sm) !important;
    }
    
    /* ===== ALERTS ===== */
    .stAlert {
        background: var(--bg-primary) !important;
        border: 1px solid var(--border-light) !important;
        border-radius: var(--radius-md) !important;
        color: var(--text-primary) !important;
        padding: var(--space-md) !important;
    }
    
    .stSuccess {
        background: #F8F9FA !important;
        border-color: var(--success) !important;
        border-left: 4px solid var(--success) !important;
    }
    
    .stWarning {
        background: #FFF9E6 !important;
        border-color: var(--warning) !important;
        border-left: 4px solid var(--warning) !important;
    }
    
    .stError {
        background: #FFF5F5 !important;
        border-color: var(--danger) !important;
        border-left: 4px solid var(--danger) !important;
    }
    
    .stInfo {
        background: #F0F9FF !important;
        border-color: var(--info) !important;
        border-left: 4px solid var(--info) !important;
    }
    
    /* ===== STATUS INDICATORS ===== */
    .status-indicator {
        display: inline-flex;
        align-items: center;
        gap: var(--space-sm);
        padding: var(--space-xs) var(--space-md);
        border-radius: var(--radius-lg);
        font-size: 0.875rem;
        font-weight: 500;
        border: 1px solid;
    }
    
    .status-online {
        background: #F0FDF4;
        color: var(--success);
        border-color: var(--success);
    }
    
    .status-warning {
        background: #FFFBEB;
        color: var(--warning);
        border-color: var(--warning);
    }
    
    .status-error {
        background: #FEF2F2;
        color: var(--danger);
        border-color: var(--danger);
    }

    /* ===== INTELLIGENT DASHBOARD COMPONENTS ===== */
    .intelligent-dashboard {
        margin-bottom: 2rem;
    }
    
    .dashboard-header h2 {
        color: #212529;
        font-size: 1.75rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
    }
    
    .dashboard-header p {
        color: #6C757D;
        font-size: 1rem;
        margin-bottom: 1.5rem;
    }
    
    .insight-metric-card {
        transition: transform 0.3s ease, box-shadow 0.3s ease !important;
        cursor: pointer;
    }
    
    .insight-metric-card:hover {
        transform: translateY(-5px) !important;
        box-shadow: 0 15px 30px rgba(0, 102, 204, 0.15) !important;
    }
    
    /* Shimmer animation for insight cards */
    @keyframes shimmer {
        0% { transform: translateX(-100%) rotate(45deg); }
        100% { transform: translateX(200%) rotate(45deg); }
    }
    
    /* ===== ENHANCED SEARCH AND FILTER COMPONENTS ===== */
    .search-filter-container {
        background: var(--bg-secondary);
        border-radius: var(--radius-md);
        padding: var(--space-md);
        margin-bottom: var(--space-lg);
        border: 1px solid var(--border-light);
    }
    
    .filter-chip {
        display: inline-block;
        background: var(--primary-blue-light);
        color: var(--primary-blue);
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.875rem;
        font-weight: 500;
        margin: 0.25rem 0.25rem 0.25rem 0;
        cursor: pointer;
        transition: all 0.2s ease;
        border: 1px solid var(--primary-blue);
    }
    
    .filter-chip:hover {
        background: var(--primary-blue);
        color: white;
        transform: translateY(-1px);
    }
    
    .filter-chip.active {
        background: var(--primary-blue);
        color: white;
    }
    
    /* ===== NETWORK GRAPH STYLING ===== */
    .network-graph-container {
        background: var(--bg-primary);
        border: 1px solid var(--border-light);
        border-radius: var(--radius-lg);
        padding: var(--space-lg);
        margin-bottom: var(--space-lg);
        min-height: 400px;
    }
    
    /* ===== SECURITY INSIGHTS PANEL ===== */
    .security-alert {
        transition: all 0.3s ease;
        cursor: pointer;
    }
    
    .security-alert:hover {
        transform: translateX(5px);
        box-shadow: var(--shadow-md);
    }
    
    .insight-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        background: var(--bg-secondary);
        border: 1px solid var(--border-light);
        border-radius: 20px;
        padding: 0.5rem 1rem;
        font-size: 0.875rem;
        font-weight: 500;
        margin-bottom: 0.5rem;
        transition: all 0.2s ease;
    }
    
    .insight-badge:hover {
        background: var(--primary-blue-light);
        border-color: var(--primary-blue);
        transform: translateY(-1px);
    }
    
    /* ===== COMPARISON DASHBOARD ===== */
    .comparison-metric {
        position: relative;
        overflow: hidden;
    }
    
    .comparison-metric::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
        transition: left 0.6s ease;
    }
    
    .comparison-metric:hover::before {
        left: 100%;
    }
    
    /* ===== INTERACTIVE ELEMENTS ===== */
    .interactive-element {
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        cursor: pointer;
    }
    
    .interactive-element:hover {
        transform: scale(1.02);
        box-shadow: var(--shadow-lg);
    }
    
    .interactive-element:active {
        transform: scale(0.98);
    }
    
    /* ===== ENHANCED TOOLTIPS ===== */
    .enhanced-tooltip {
        position: relative;
        cursor: help;
    }
    
    .enhanced-tooltip::after {
        content: attr(data-tooltip);
        position: absolute;
        bottom: 100%;
        left: 50%;
        transform: translateX(-50%);
        background: #333;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 6px;
        font-size: 0.875rem;
        white-space: nowrap;
        opacity: 0;
        visibility: hidden;
        transition: all 0.3s ease;
        z-index: 1000;
    }
    
    .enhanced-tooltip:hover::after {
        opacity: 1;
        visibility: visible;
        bottom: 110%;
    }
    
    /* ===== LOADING STATES ===== */
    .loading-shimmer {
        background: linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%);
        background-size: 200% 100%;
        animation: loading-shimmer 1.5s infinite;
    }
    
    @keyframes loading-shimmer {
        0% { background-position: -200% 0; }
        100% { background-position: 200% 0; }
    }
    
    /* ===== RESPONSIVE ENHANCEMENTS ===== */
    @media (max-width: 768px) {
        .insight-metric-card {
            margin-bottom: 1rem;
        }
        
        .dashboard-header h2 {
            font-size: 1.5rem;
        }
        
        .network-graph-container {
            min-height: 300px;
            padding: var(--space-md);
        }
        
        .comparison-metric {
            margin-bottom: 1rem;
        }
    }
    
    /* ===== ACCESSIBILITY ENHANCEMENTS ===== */
    .focus-visible {
        outline: 2px solid var(--primary-blue) !important;
        outline-offset: 2px !important;
    }
    
    @media (prefers-reduced-motion: reduce) {
        .insight-metric-card,
        .interactive-element,
        .security-alert {
            animation: none !important;
            transition: none !important;
        }
        
        .shimmer,
        .loading-shimmer {
            animation: none !important;
        }
    }
    
    /* ===== ANIMATIONS ===== */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    @keyframes slideIn {
        from { transform: translateX(-10px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.7; }
    }
    
    .animate-fade-in {
        animation: fadeIn 0.4s ease-out;
    }
    
    .animate-slide-in {
        animation: slideIn 0.3s ease-out;
    }
    
    .animate-pulse {
        animation: pulse 2s ease-in-out infinite;
    }
    
    /* ===== UTILITIES ===== */
    .text-primary { color: var(--text-primary) !important; }
    .text-secondary { color: var(--text-secondary) !important; }
    .text-muted { color: var(--text-muted) !important; }
    
    .bg-primary { background-color: var(--bg-primary) !important; }
    .bg-secondary { background-color: var(--bg-secondary) !important; }
    
    .border-light { border-color: var(--border-light) !important; }
    .border-medium { border-color: var(--border-medium) !important; }
    
    .shadow-sm { box-shadow: var(--shadow-sm) !important; }
    .shadow-md { box-shadow: var(--shadow-md) !important; }
    .shadow-lg { box-shadow: var(--shadow-lg) !important; }
    
    /* ===== RESPONSIVE DESIGN ===== */
    @media (max-width: 768px) {
        div[data-testid="stMainBlockContainer"] {
            padding: var(--space-sm) var(--space-sm) !important;
        }
        
        .main-header {
            padding: var(--space-md);
        }
        
        .main-header h1 {
            font-size: 1.75rem;
        }
        
        .main-header h3 {
            font-size: 1rem;
        }
        
        .metric-value {
            font-size: 1.25rem;
        }
        
        .custom-card {
            padding: var(--space-sm);
            margin-bottom: var(--space-sm);
        }
        
        .feature-card {
            min-height: 160px !important;
        }
        
        .progress-phases {
            flex-direction: column;
            align-items: stretch;
        }
        
        .progress-phase {
            justify-content: center;
        }
    }
    
    @media (min-width: 769px) and (max-width: 1024px) {
        div[data-testid="stMainBlockContainer"] {
            max-width: 1200px !important;
            padding: var(--space-md) var(--space-lg) !important;
        }
        
        .main-header h1 {
            font-size: 2rem;
        }
    }
    
    @media (min-width: 1025px) {
        div[data-testid="stMainBlockContainer"] {
            max-width: 1400px !important;
        }
        
        .feature-card {
            min-height: 180px;
        }
    }
    
    /* ===== CUSTOM SCROLLBAR ===== */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: var(--bg-tertiary);
        border-radius: var(--radius-sm);
    }
    
    ::-webkit-scrollbar-thumb {
        background: var(--border-dark);
        border-radius: var(--radius-sm);
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: var(--text-secondary);
    }
    
    /* ===== SPACING FIXES FOR ELEMENTS ===== */
    /* Fix spacing between elements - more compact */
    div[data-testid="stVerticalBlock"] > div {
        margin-bottom: 0 !important;
    }
    
    /* Fix horizontal block spacing */
    div[data-testid="stHorizontalBlock"] {
        gap: var(--space-sm) !important;
    }
    
    /* Fix column spacing */
    div[data-testid="stColumn"] {
        padding: 0 var(--space-xs) !important;
    }
    
    /* Fix metric spacing */
    div[data-testid="stMetric"] {
        background: var(--bg-primary);
        border: 1px solid var(--border-light);
        border-radius: var(--radius-md);
        padding: var(--space-sm);
        margin-bottom: 0;
        transition: all 0.2s ease;
    }
    
    div[data-testid="stMetric"]:hover {
        transform: translateY(-1px);
        box-shadow: var(--shadow-sm);
        border-color: var(--border-medium);
    }
    
    /* Reduce excessive spacing in Streamlit markdown */
    .stMarkdown > div > p {
        margin-bottom: var(--space-sm) !important;
    }
    
    /* Optimize header spacing */
    .stMarkdown > div > h1, 
    .stMarkdown > div > h2, 
    .stMarkdown > div > h3 {
        margin-top: var(--space-sm) !important;
        margin-bottom: var(--space-sm) !important;
    }
    
    /* Compact expander spacing */
    .streamlit-expanderContent {
        padding: var(--space-md) !important;
    }
    
    /* ===== MODERN MICRO-INTERACTIONS ===== */
    .stButton > button, .metric-card, .custom-card {
        transform-origin: center;
        will-change: transform, box-shadow;
    }
    
    /* ===== GLASSMORPHISM EFFECTS ===== */
    .glass-effect {
        background: rgba(255, 255, 255, 0.25);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.18);
        box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
    }
    </style>
    """


def get_custom_js():
    """Return enhanced JavaScript for professional interactions."""

    return """
    <script>
    // Enhanced UI interactions with modern UX principles
    document.addEventListener('DOMContentLoaded', function() {
        // Add smooth scrolling
        document.documentElement.style.scrollBehavior = 'smooth';
        
        // Progressive loading animation for cards
        const cards = document.querySelectorAll('.custom-card, .metric-card');
        const observer = new IntersectionObserver((entries) => {
            entries.forEach((entry, index) => {
                if (entry.isIntersecting) {
            setTimeout(() => {
                        entry.target.classList.add('animate-fade-in');
                    }, index * 50);
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });
        
        cards.forEach(card => observer.observe(card));
        
        // Enhanced focus states with smooth transitions
        const inputs = document.querySelectorAll('input, textarea, select');
        inputs.forEach(input => {
            input.addEventListener('focus', function() {
                this.parentElement.style.transform = 'scale(1.01)';
                this.parentElement.style.transition = 'transform 0.2s ease';
            });
            
            input.addEventListener('blur', function() {
                this.parentElement.style.transform = 'scale(1)';
            });
        });
        
        // Add ripple effect to buttons
        const buttons = document.querySelectorAll('button');
        buttons.forEach(button => {
            button.addEventListener('click', function(e) {
                const ripple = document.createElement('span');
                const rect = this.getBoundingClientRect();
                const size = Math.max(rect.width, rect.height);
                const x = e.clientX - rect.left - size / 2;
                const y = e.clientY - rect.top - size / 2;
                
                ripple.style.width = ripple.style.height = size + 'px';
                ripple.style.left = x + 'px';
                ripple.style.top = y + 'px';
                ripple.style.position = 'absolute';
                ripple.style.borderRadius = '50%';
                ripple.style.background = 'rgba(255, 255, 255, 0.3)';
                ripple.style.transform = 'scale(0)';
                ripple.style.animation = 'ripple 0.6s linear';
                ripple.style.pointerEvents = 'none';
                
                this.style.position = 'relative';
                this.style.overflow = 'hidden';
                this.appendChild(ripple);
                
                setTimeout(() => {
                    ripple.remove();
                }, 600);
            });
        });
        
        // Auto-hide progress system when complete
        const progressSystems = document.querySelectorAll('.progress-system');
        progressSystems.forEach(system => {
            const percentage = system.querySelector('.progress-percentage');
            if (percentage && percentage.textContent.includes('100')) {
                setTimeout(() => {
                    system.style.transition = 'opacity 0.5s ease';
                    system.style.opacity = '0.8';
                }, 2000);
            }
        });
        
        // Dynamic favicon update based on progress
        function updateFavicon(progress) {
            if (progress >= 100) {
                document.title = '✅ ReconForge Professional - Complete';
            } else if (progress > 0) {
                document.title = `🔄 ReconForge Professional - ${progress}%`;
            } else {
                document.title = '🎯 ReconForge Professional';
            }
        }
        
        // Smooth page transitions
        window.addEventListener('beforeunload', function() {
            document.body.style.opacity = '0';
            document.body.style.transition = 'opacity 0.3s ease';
        });
    });
    
    // Custom CSS animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes ripple {
            to {
                transform: scale(4);
                opacity: 0;
            }
        }
        
        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-5px); }
        }
        
        .floating {
            animation: float 3s ease-in-out infinite;
        }
    `;
    document.head.appendChild(style);
    </script>
    """
