import logging
import sys
import io
import time
import re
import os
import threading
import json
import traceback
from typing import Optional, Dict, Any, List, Union, Callable
from datetime import datetime, timedelta
from contextlib import contextmanager
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import subprocess

# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED COLOR SYSTEM WITH GRADIENT SUPPORT
# ═══════════════════════════════════════════════════════════════════════════════

class Colors:
    """Enhanced ANSI color codes with gradient and style support"""
    # Reset and styles
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"
    STRIKETHROUGH = "\033[9m"
    
    # Standard foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Bright foreground colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"
    
    # Bright background colors
    BG_BRIGHT_BLACK = "\033[100m"
    BG_BRIGHT_RED = "\033[101m"
    BG_BRIGHT_GREEN = "\033[102m"
    BG_BRIGHT_YELLOW = "\033[103m"
    BG_BRIGHT_BLUE = "\033[104m"
    BG_BRIGHT_MAGENTA = "\033[105m"
    BG_BRIGHT_CYAN = "\033[106m"
    BG_BRIGHT_WHITE = "\033[107m"
    
    # Custom RGB colors (256-color mode)
    @staticmethod
    def rgb(r: int, g: int, b: int) -> str:
        """Generate RGB color code"""
        return f"\033[38;2;{r};{g};{b}m"
    
    @staticmethod
    def bg_rgb(r: int, g: int, b: int) -> str:
        """Generate RGB background color code"""
        return f"\033[48;2;{r};{g};{b}m"

class CyberColors:
    """Cybersecurity-themed color palette"""
    # Primary theme colors
    MATRIX_GREEN = Colors.rgb(0, 255, 65)
    TERMINAL_GREEN = Colors.rgb(0, 255, 0)
    CYBER_BLUE = Colors.rgb(0, 150, 255)
    ELECTRIC_CYAN = Colors.rgb(0, 255, 255)
    NEON_PURPLE = Colors.rgb(138, 43, 226)
    HACKER_ORANGE = Colors.rgb(255, 140, 0)
    DANGER_RED = Colors.rgb(255, 69, 58)
    WARNING_AMBER = Colors.rgb(255, 214, 0)
    SUCCESS_GREEN = Colors.rgb(52, 199, 89)
    INFO_BLUE = Colors.rgb(0, 122, 255)
    
    # Gradient combinations
    FIREWALL_GRADIENT = [Colors.rgb(255, 69, 58), Colors.rgb(255, 140, 0)]
    SCAN_GRADIENT = [Colors.rgb(0, 150, 255), Colors.rgb(138, 43, 226)]
    SUCCESS_GRADIENT = [Colors.rgb(52, 199, 89), Colors.rgb(0, 255, 65)]
    CRITICAL_GRADIENT = [Colors.rgb(255, 69, 58), Colors.rgb(255, 0, 0)]

class LogLevel(Enum):
    """Enhanced log levels with cyber themes"""
    TRACE = 5
    DEBUG = 10
    INFO = 20
    SUCCESS = 25
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    AUDIT = 60

class Symbols:
    """Enhanced Unicode symbols for professional logging"""
    # Log level symbols
    TRACE = "🔬"
    DEBUG = "🔍"
    INFO = "💡"
    SUCCESS = "✅"
    WARNING = "⚠️"
    ERROR = "❌"
    CRITICAL = "💥"
    AUDIT = "📋"
    
    # Operation symbols
    ROCKET = "🚀"
    GEAR = "⚙️"
    SHIELD = "🛡️"
    TARGET = "🎯"
    RADAR = "📡"
    BOLT = "⚡"
    FIRE = "🔥"
    MAGIC = "✨"
    STAR = "⭐"
    DIAMOND = "💎"
    
    # Infrastructure symbols
    DATABASE = "💾"
    NETWORK = "🌐"
    DOMAIN = "🌍"
    IP = "📡"
    CLOUD = "☁️"
    LOCK = "🔒"
    SERVER = "🖥️"
    API = "🔌"
    
    # Progress and status
    ARROW_RIGHT = "→"
    ARROW_LEFT = "←"
    ARROW_UP = "↑"
    ARROW_DOWN = "↓"
    BULLET = "•"
    CHECK = "✓"
    CROSS = "✗"
    HOURGLASS = "⏳"
    STOPWATCH = "⏱️"
    
    # Special operations
    SCAN = "🔎"
    ANALYZE = "🧪"
    DISCOVER = "🕵️"
    MONITOR = "👁️"
    ATTACK = "⚔️"
    DEFEND = "🛡️"

# ═══════════════════════════════════════════════════════════════════════════════
# PERFORMANCE MONITORING SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PerformanceRecord:
    """Record for tracking operation performance"""
    operation: str
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    thread_id: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    
    def complete(self) -> float:
        """Mark operation as complete and return duration"""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        return self.duration

class AdvancedMetrics:
    """Advanced performance and logging metrics system"""
    
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.start_time = time.time()
        self.operations = {}
        self.completed_operations = deque(maxlen=max_history)
        self.counters = defaultdict(int)
        self.gauges = {}
        self.histograms = defaultdict(list)
        self._lock = threading.Lock()
        
    def start_operation(self, name: str, context: Dict[str, Any] = None) -> str:
        """Start tracking an operation"""
        with self._lock:
            operation_id = f"{name}_{int(time.time() * 1000000)}"
            record = PerformanceRecord(
                operation=name,
                start_time=time.time(),
                thread_id=threading.current_thread().name,
                context=context or {}
            )
            self.operations[operation_id] = record
            return operation_id
    
    def complete_operation(self, operation_id: str) -> Optional[float]:
        """Complete an operation and return duration"""
        with self._lock:
            if operation_id in self.operations:
                record = self.operations[operation_id]
                duration = record.complete()
                self.completed_operations.append(record)
                self.histograms[record.operation].append(duration)
                del self.operations[operation_id]
                return duration
            return None
    
    def increment_counter(self, name: str, value: int = 1, tags: Dict[str, str] = None):
        """Increment a counter metric"""
        with self._lock:
            key = f"{name}_{tags}" if tags else name
            self.counters[key] += value
    
    def set_gauge(self, name: str, value: float, tags: Dict[str, str] = None):
        """Set a gauge metric"""
        with self._lock:
            key = f"{name}_{tags}" if tags else name
            self.gauges[key] = value
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        with self._lock:
            stats = {
                "uptime": time.time() - self.start_time,
                "active_operations": len(self.operations),
                "completed_operations": len(self.completed_operations),
                "counters": dict(self.counters),
                "gauges": dict(self.gauges),
                "operation_stats": {}
            }
            
            # Calculate operation statistics
            for op_name, durations in self.histograms.items():
                if durations:
                    stats["operation_stats"][op_name] = {
                        "count": len(durations),
                        "avg_duration": sum(durations) / len(durations),
                        "min_duration": min(durations),
                        "max_duration": max(durations),
                        "total_duration": sum(durations)
                    }
            
            return stats

# Global metrics instance
metrics = AdvancedMetrics()

# ═══════════════════════════════════════════════════════════════════════════════
# ENVIRONMENT DETECTION AND CAPABILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def is_streamlit_environment() -> bool:
    """Detect if running in Streamlit environment"""
    return (
        'streamlit' in sys.modules or
        'STREAMLIT_SERVER_PORT' in os.environ or
        any('streamlit' in str(arg).lower() for arg in sys.argv) or
        os.environ.get('STREAMLIT_SERVER_RUN_ON_SAVE') is not None
    )

def is_jupyter_environment() -> bool:
    """Detect if running in Jupyter notebook"""
    return 'ipykernel' in sys.modules

def supports_ansi_colors() -> bool:
    """Advanced ANSI color support detection"""
    if is_streamlit_environment() or is_jupyter_environment():
        return False
    
    # Check environment variables
    if os.environ.get('NO_COLOR'):
        return False
    
    if os.environ.get('FORCE_COLOR'):
        return True
    
    # Check terminal capabilities
    term = os.environ.get('TERM', '').lower()
    if 'color' in term or term in ['xterm', 'xterm-256color', 'screen', 'tmux']:
        return True
    
    # Check if stdout supports colors
    return (
        hasattr(sys.stdout, 'isatty') and 
        sys.stdout.isatty() and
        hasattr(sys.stderr, 'isatty') and 
        sys.stderr.isatty()
    )

def get_terminal_size() -> tuple:
    """Get terminal size with fallback"""
    try:
        return os.get_terminal_size()
    except:
        return os.terminal_size((80, 24))  # Default fallback

# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED BANNER AND VISUALIZATION SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

class AdvancedBannerSystem:
    """Professional banner and visualization system"""
    
    @staticmethod
    def create_gradient_text(text: str, colors: List[str]) -> str:
        """Create text with gradient colors"""
        if not colors or not supports_ansi_colors():
            return text
        
        if len(colors) == 1:
            return f"{colors[0]}{text}{Colors.RESET}"
        
        # Simple gradient simulation
        text_len = len(text)
        result = ""
        for i, char in enumerate(text):
            color_index = int((i / max(text_len - 1, 1)) * (len(colors) - 1))
            result += f"{colors[color_index]}{char}"
        
        return f"{result}{Colors.RESET}"
    
    @staticmethod
    def create_box(content: List[str], style: str = "heavy", color: str = None) -> str:
        """Create a beautiful box around content"""
        if not supports_ansi_colors():
            width = max(len(line) for line in content) + 4
            result = "=" * width + "\n"
            for line in content:
                result += f"  {line}\n"
            result += "=" * width
            return result
        
        # Box drawing characters
        styles = {
            "light": {"tl": "┌", "tr": "┐", "bl": "└", "br": "┘", "h": "─", "v": "│"},
            "heavy": {"tl": "┏", "tr": "┓", "bl": "┗", "br": "┛", "h": "━", "v": "┃"},
            "double": {"tl": "╔", "tr": "╗", "bl": "╚", "br": "╝", "h": "═", "v": "║"},
            "rounded": {"tl": "╭", "tr": "╮", "bl": "╰", "br": "╯", "h": "─", "v": "│"}
        }
        
        chars = styles.get(style, styles["heavy"])
        color_code = color or ""
        reset = Colors.RESET if color else ""
        
        # Calculate box width
        content_width = max(len(line) for line in content) if content else 0
        box_width = content_width + 4
        
        # Build box
        result = f"{color_code}{chars['tl']}{chars['h'] * (box_width - 2)}{chars['tr']}{reset}\n"
        
        for line in content:
            padding = box_width - len(line) - 4
            result += f"{color_code}{chars['v']}{reset}  {line}{' ' * padding}  {color_code}{chars['v']}{reset}\n"
        
        result += f"{color_code}{chars['bl']}{chars['h'] * (box_width - 2)}{chars['br']}{reset}"
        
        return result
    
    @staticmethod
    def create_startup_banner() -> str:
        """Create professional startup banner"""
        if not supports_ansi_colors():
            return """
══════════════════════════════════════════════════════════════
    RECONFORGE - ENTERPRISE ASSET INTELLIGENCE PLATFORM
══════════════════════════════════════════════════════════════
"""
        
        # Create banner content
        banner_lines = [
            "",
            AdvancedBannerSystem.create_gradient_text(
                "RECONFORGE", 
                [CyberColors.CYBER_BLUE, CyberColors.ELECTRIC_CYAN, CyberColors.MATRIX_GREEN]
            ),
            f"{Colors.DIM}Enterprise Asset Intelligence Platform{Colors.RESET}",
            "",
            f"{Symbols.SHIELD} {Colors.BRIGHT_GREEN}Security Assessment Suite{Colors.RESET}",
            f"{Symbols.RADAR} {Colors.BRIGHT_BLUE}Advanced Reconnaissance Engine{Colors.RESET}",
            f"{Symbols.BOLT} {Colors.BRIGHT_YELLOW}Intelligent Discovery System{Colors.RESET}",
            "",
            f"{Colors.DIM}Python {sys.version.split()[0]} • Enhanced Logging • Real-time Metrics{Colors.RESET}",
            ""
        ]
        
        return AdvancedBannerSystem.create_box(banner_lines, "double", CyberColors.CYBER_BLUE)

# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED LOGGING FORMATTER
# ═══════════════════════════════════════════════════════════════════════════════

class CyberSecurityFormatter(logging.Formatter):
    """Advanced formatter with cybersecurity themes and rich formatting"""
    
    def __init__(
        self, 
        use_colors: bool = True, 
        show_thread: bool = False,
        show_performance: bool = True,
        compact_mode: bool = False,
        show_context: bool = True
    ):
        super().__init__()
        self.use_colors = use_colors and supports_ansi_colors()
        self.show_thread = show_thread
        self.show_performance = show_performance
        self.compact_mode = compact_mode
        self.show_context = show_context
        
        # Enhanced log level styles
        self.level_styles = {
            LogLevel.TRACE.value: {
                "symbol": Symbols.TRACE, 
                "color": CyberColors.INFO_BLUE if self.use_colors else "",
                "bg": "",
                "style": Colors.DIM if self.use_colors else ""
            },
            LogLevel.DEBUG.value: {
                "symbol": Symbols.DEBUG, 
                "color": CyberColors.ELECTRIC_CYAN if self.use_colors else "",
                "bg": "",
                "style": ""
            },
            LogLevel.INFO.value: {
                "symbol": Symbols.INFO, 
                "color": CyberColors.MATRIX_GREEN if self.use_colors else "",
                "bg": "",
                "style": ""
            },
            LogLevel.SUCCESS.value: {
                "symbol": Symbols.SUCCESS, 
                "color": CyberColors.SUCCESS_GREEN if self.use_colors else "",
                "bg": "",
                "style": Colors.BOLD if self.use_colors else ""
            },
            LogLevel.WARNING.value: {
                "symbol": Symbols.WARNING, 
                "color": CyberColors.WARNING_AMBER if self.use_colors else "",
                "bg": "",
                "style": Colors.BOLD if self.use_colors else ""
            },
            LogLevel.ERROR.value: {
                "symbol": Symbols.ERROR, 
                "color": CyberColors.DANGER_RED if self.use_colors else "",
                "bg": "",
                "style": Colors.BOLD if self.use_colors else ""
            },
            LogLevel.CRITICAL.value: {
                "symbol": Symbols.CRITICAL, 
                "color": Colors.BRIGHT_WHITE if self.use_colors else "",
                "bg": Colors.BG_RED if self.use_colors else "",
                "style": Colors.BOLD if self.use_colors else ""
            },
            LogLevel.AUDIT.value: {
                "symbol": Symbols.AUDIT, 
                "color": CyberColors.NEON_PURPLE if self.use_colors else "",
                "bg": "",
                "style": Colors.BOLD if self.use_colors else ""
            }
        }
    
    def format_timestamp(self, record) -> str:
        """Format timestamp with enhanced styling"""
        timestamp = self.formatTime(record, "%H:%M:%S.%f")[:-3]  # Include milliseconds
        
        if self.use_colors:
            return f"{Colors.DIM}{timestamp}{Colors.RESET}"
        return timestamp
    
    def format_level(self, record) -> str:
        """Format log level with styling"""
        style = self.level_styles.get(record.levelno, self.level_styles[LogLevel.INFO.value])
        
        if self.use_colors:
            return (
                f"{style['bg']}{style['style']}{style['color']}"
                f"{style['symbol']} {record.levelname}"
                f"{Colors.RESET}"
            )
        else:
            return f"{style['symbol']} {record.levelname}"
    
    def format_module(self, record) -> str:
        """Format module name with context"""
        module_name = record.name.split('.')[-1] if '.' in record.name else record.name
        
        if self.use_colors:
            return f"[{CyberColors.CYBER_BLUE}{Symbols.GEAR} {module_name}{Colors.RESET}]"
        else:
            return f"[{Symbols.GEAR} {module_name}]"
    
    def format_thread(self, record) -> str:
        """Format thread information"""
        if not self.show_thread or threading.current_thread().name == "MainThread":
            return ""
        
        thread_name = threading.current_thread().name
        if self.use_colors:
            return f" {Colors.DIM}[{thread_name}]{Colors.RESET}"
        else:
            return f" [{thread_name}]"
    
    def format_performance(self, record) -> str:
        """Add performance context if available"""
        if not self.show_performance:
            return ""
        
        # Check if this is a performance-related log
        msg = record.getMessage()
        if "completed in" in msg.lower() and "s" in msg:
            if self.use_colors:
                return f" {Colors.DIM}{Symbols.STOPWATCH}{Colors.RESET}"
            else:
                return f" {Symbols.STOPWATCH}"
        
        return ""
    
    def format_message(self, record) -> str:
        """Enhanced message formatting with context highlighting"""
        message = record.getMessage()
        
        if not self.use_colors:
            return message
        
        # Highlight special patterns
        patterns = {
            r'\b(SUCCESS|COMPLETE|ACCOMPLISHED)\b': CyberColors.SUCCESS_GREEN,
            r'\b(ERROR|FAILED|FAILURE)\b': CyberColors.DANGER_RED,
            r'\b(WARNING|WARN)\b': CyberColors.WARNING_AMBER,
            r'\b(CRITICAL|FATAL)\b': CyberColors.DANGER_RED,
            r'\b(STARTING|BEGIN|LAUNCH)\b': CyberColors.CYBER_BLUE,
            r'\b(FOUND|DISCOVERED|DETECTED)\b': CyberColors.MATRIX_GREEN,
            r'\b(\d+\.\d+s|\d+ms)\b': CyberColors.WARNING_AMBER,  # Time durations
            r'\b(\d+\.\d+\.\d+\.\d+)\b': CyberColors.ELECTRIC_CYAN,  # IP addresses
            r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b': CyberColors.INFO_BLUE,  # Domains
        }
        
        for pattern, color in patterns.items():
            message = re.sub(
                pattern, 
                f"{color}\\g<0>{Colors.RESET}", 
                message, 
                flags=re.IGNORECASE
            )
        
        return message
    
    def format(self, record) -> str:
        """Main formatting method"""
        # Build log line components
        timestamp = self.format_timestamp(record)
        level = self.format_level(record)
        module = self.format_module(record)
        thread = self.format_thread(record)
        performance = self.format_performance(record)
        message = self.format_message(record)
        
        # Assemble log line
        if self.compact_mode:
            log_line = f"{timestamp} {level} {message}"
        else:
            log_line = f"{timestamp}{thread} {level} {module}{performance} {message}"
        
        # Handle exceptions
        if record.exc_info:
            if self.use_colors:
                exception_text = f"\n{CyberColors.DANGER_RED}{self.formatException(record.exc_info)}{Colors.RESET}"
            else:
                exception_text = f"\n{self.formatException(record.exc_info)}"
            log_line += exception_text
        
        return log_line

# ═══════════════════════════════════════════════════════════════════════════════
# STREAMLIT-SAFE HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

class StreamlitSafeHandler(logging.StreamHandler):
    """Enhanced handler for Streamlit that strips ANSI codes and adds UI formatting"""
    
    def __init__(self, string_io):
        super().__init__(string_io)
        self.string_io = string_io
        self.setFormatter(CyberSecurityFormatter(use_colors=False, compact_mode=True))
        
        # ANSI escape sequence regex
        self.ansi_escape = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    
    def format(self, record) -> str:
        """Format record and ensure no ANSI codes"""
        msg = super().format(record)
        # Strip any ANSI codes that might have leaked through
        clean_msg = self.ansi_escape.sub('', msg)
        return clean_msg
    
    def emit(self, record):
        """Enhanced emit with error handling"""
        try:
            msg = self.format(record)
            self.string_io.write(msg + '\n')
            self.flush()
        except Exception:
            self.handleError(record)

class RealTimeMetricsHandler(logging.Handler):
    """Handler that collects real-time metrics from log messages"""
    
    def __init__(self):
        super().__init__()
        self.metrics = {
            'log_counts': defaultdict(int),
            'error_count': 0,
            'warning_count': 0,
            'last_error': None,
            'performance_data': [],
        }
    
    def emit(self, record):
        """Collect metrics from log records"""
        try:
            self.metrics['log_counts'][record.levelname] += 1
            
            if record.levelno >= logging.ERROR:
                self.metrics['error_count'] += 1
                self.metrics['last_error'] = {
                    'time': datetime.now(),
                    'message': record.getMessage(),
                    'module': record.name
                }
            elif record.levelno >= logging.WARNING:
                self.metrics['warning_count'] += 1
            
            # Extract performance data
            msg = record.getMessage()
            if "completed in" in msg.lower():
                try:
                    # Extract duration from message
                    import re
                    duration_match = re.search(r'(\d+\.?\d*)s', msg)
                    if duration_match:
                        duration = float(duration_match.group(1))
                        self.metrics['performance_data'].append({
                            'operation': record.name,
                            'duration': duration,
                            'timestamp': datetime.now()
                        })
                        
                        # Keep only last 100 performance records
                        if len(self.metrics['performance_data']) > 100:
                            self.metrics['performance_data'] = self.metrics['performance_data'][-100:]
                except:
                    pass
                    
        except Exception:
            pass  # Silently handle metrics errors
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        return dict(self.metrics)

# ═══════════════════════════════════════════════════════════════════════════════
# CONTEXT MANAGERS AND UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

@contextmanager
def operation_timer(logger, operation_name: str, context: Dict[str, Any] = None):
    """Enhanced context manager for timing operations with rich logging"""
    operation_id = metrics.start_operation(operation_name, context)
    start_time = time.time()
    
    if hasattr(logger, 'info'):
        logger.info(f"{Symbols.ROCKET} Starting {operation_name}")
    
    try:
        yield
        duration = metrics.complete_operation(operation_id)
        
        if hasattr(logger, 'info') and duration is not None:
            if duration > 10:
                level_func = logger.warning
                symbol = Symbols.WARNING
            elif duration > 1:
                level_func = logger.info
                symbol = Symbols.BOLT
            else:
                level_func = logger.info
                symbol = Symbols.SUCCESS
                
            level_func(f"{symbol} {operation_name} completed in {duration:.3f}s")
            
    except Exception as e:
        duration = time.time() - start_time
        if operation_id in metrics.operations:
            metrics.complete_operation(operation_id)
            
        if hasattr(logger, 'error'):
            logger.error(f"{Symbols.ERROR} {operation_name} failed after {duration:.3f}s: {e}")
        raise

@contextmanager
def log_section(logger, section_name: str, symbol: str = None):
    """Context manager for logging sections with professional formatting"""
    symbol = symbol or Symbols.GEAR
    
    if hasattr(logger, 'info'):
        if supports_ansi_colors():
            header = f"\n{CyberColors.CYBER_BLUE}{'━' * 12}{Colors.RESET} {symbol} {Colors.BOLD}{section_name}{Colors.RESET} {CyberColors.CYBER_BLUE}{'━' * 12}{Colors.RESET}"
        else:
            header = f"\n{'━' * 12} {symbol} {section_name} {'━' * 12}"
        logger.info(header)
    
    try:
        yield
    finally:
        if hasattr(logger, 'info'):
            if supports_ansi_colors():
                footer = f"{CyberColors.CYBER_BLUE}{'━' * (28 + len(section_name))}{Colors.RESET}\n"
            else:
                footer = f"{'━' * (28 + len(section_name))}\n"
            logger.info(footer)

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SETUP FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Global state tracking
_LOGGING_INITIALIZED = False
_cleanup_registered = False
_metrics_handler = None

def cleanup_logging():
    """Enhanced cleanup of logging resources"""
    global _LOGGING_INITIALIZED, _cleanup_registered, _metrics_handler
    
    try:
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            try:
                handler.close()
                root_logger.removeHandler(handler)
            except:
                pass
        
        # Reset global state
        _LOGGING_INITIALIZED = False
        _cleanup_registered = False
        _metrics_handler = None
        
    except:
        pass

def setup_logging(
    level: int = logging.INFO,
    show_banner: bool = True,
    show_thread: bool = False,
    show_performance: bool = True,
    use_colors: Optional[bool] = None,
    compact_mode: bool = False,
    enable_metrics: bool = True,
    log_file: Optional[str] = None,
    stream_handler: Optional[logging.Handler] = None
):
    """
    Advanced logging setup with comprehensive features
    
    Args:
        level: Logging level
        show_banner: Show startup banner
        show_thread: Include thread info in logs
        show_performance: Show performance metrics
        use_colors: Force color usage (auto-detect if None)
        compact_mode: Use compact log format
        enable_metrics: Enable real-time metrics collection
        log_file: Optional log file path
        stream_handler: Custom stream handler (for UI integration)
    """
    global _LOGGING_INITIALIZED, _cleanup_registered, _metrics_handler
    
    # Prevent multiple initializations
    if _LOGGING_INITIALIZED:
        return
    
    # Auto-detect color support
    if use_colors is None:
        use_colors = supports_ansi_colors()
    
    # Show enhanced banner
    if show_banner and supports_ansi_colors():
        print(AdvancedBannerSystem.create_startup_banner())
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create advanced formatter
    formatter = CyberSecurityFormatter(
        use_colors=use_colors,
        show_thread=show_thread,
        show_performance=show_performance,
        compact_mode=compact_mode
    )
    
    # Add terminal handler
    if not is_streamlit_environment():
        try:
            terminal_handler = logging.StreamHandler(sys.stderr)
            terminal_handler.setFormatter(formatter)
            terminal_handler.setLevel(level)
            root_logger.addHandler(terminal_handler)
        except Exception:
            # Fallback to basic config
            logging.basicConfig(
                level=level,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
    
    # Add custom stream handler (for UI)
    if stream_handler:
        root_logger.addHandler(stream_handler)
    
    # Add file handler if specified
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_formatter = CyberSecurityFormatter(
                use_colors=False,
                show_thread=show_thread,
                show_performance=show_performance,
                compact_mode=False
            )
            file_handler.setFormatter(file_formatter)
            file_handler.setLevel(level)
            root_logger.addHandler(file_handler)
        except Exception as e:
            root_logger.warning(f"Failed to setup file logging: {e}")
    
    # Add metrics handler
    if enable_metrics:
        _metrics_handler = RealTimeMetricsHandler()
        _metrics_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(_metrics_handler)
    
    # Register cleanup
    if not _cleanup_registered:
        import atexit
        atexit.register(cleanup_logging)
        _cleanup_registered = True
    
    _LOGGING_INITIALIZED = True

def get_enhanced_logger(name: str) -> logging.Logger:
    """Get an enhanced logger with additional methods"""
    logger = logging.getLogger(name)
    
    # Add custom log levels
    logging.addLevelName(LogLevel.TRACE.value, "TRACE")
    logging.addLevelName(LogLevel.SUCCESS.value, "SUCCESS")
    logging.addLevelName(LogLevel.AUDIT.value, "AUDIT")
    
    # Add convenience methods
    def trace(msg, *args, **kwargs):
        logger.log(LogLevel.TRACE.value, msg, *args, **kwargs)
    
    def success(msg, *args, **kwargs):
        logger.log(LogLevel.SUCCESS.value, msg, *args, **kwargs)
    
    def audit(msg, *args, **kwargs):
        logger.log(LogLevel.AUDIT.value, msg, *args, **kwargs)
    
    def operation_start(operation_name: str, context: Dict[str, Any] = None):
        return operation_timer(logger, operation_name, context)
    
    def section(section_name: str, symbol: str = None):
        return log_section(logger, section_name, symbol)
    
    def performance_log(operation: str, duration: float, context: Dict[str, Any] = None):
        if duration > 5.0:
            logger.warning(f"{Symbols.WARNING} Slow operation: {operation} took {duration:.3f}s")
        elif duration > 1.0:
            logger.info(f"{Symbols.BOLT} {operation} completed in {duration:.3f}s")
        else:
            logger.info(f"{Symbols.SUCCESS} {operation} completed quickly ({duration:.3f}s)")
    
    # Attach methods to logger
    logger.trace = trace
    logger.success = success
    logger.audit = audit
    logger.operation_start = operation_start
    logger.section = section
    logger.performance_log = performance_log
    
    return logger

def get_metrics() -> Dict[str, Any]:
    """Get comprehensive logging and performance metrics"""
    result = {
        "system_metrics": metrics.get_stats(),
        "log_metrics": {}
    }
    
    if _metrics_handler:
        result["log_metrics"] = _metrics_handler.get_metrics()
    
    return result

# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS AND ALIASES
# ═══════════════════════════════════════════════════════════════════════════════

# Convenience aliases for backward compatibility
get_logger = get_enhanced_logger
SafeStringHandler = StreamlitSafeHandler

def log_discovery_start(logger, target: str):
    """Log discovery operation start"""
    logger.info(f"{Symbols.RADAR} Starting discovery for: {target}")

def log_discovery_complete(logger, target: str, duration: float, assets_found: int):
    """Log discovery operation completion"""
    logger.success(f"{Symbols.SUCCESS} Discovery complete for {target}")
    logger.info(f"  {Symbols.TARGET} Assets found: {assets_found}")
    logger.performance_log(f"discovery_{target}", duration)

def log_section_start(logger, section_name: str):
    """Log section start (convenience function)"""
    with logger.section(section_name):
        pass

def create_progress_logger(logger_name: str, **kwargs):
    """Create a progress logger (simplified for compatibility)"""
    return get_enhanced_logger(logger_name)

def reset_logging():
    """Reset logging configuration"""
    cleanup_logging()

# For demonstration and testing
if __name__ == "__main__":
    # Demo the enhanced logging system
    setup_logging(level=logging.DEBUG, show_banner=True, enable_metrics=True)
    
    logger = get_enhanced_logger("demo")
    
    logger.trace("This is a trace message")
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.success("This is a success message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.audit("This is an audit message")
    
    with logger.operation_start("demo_operation"):
        time.sleep(0.1)
        logger.info("Operation in progress...")
    
    print("\nMetrics:", get_metrics()) 