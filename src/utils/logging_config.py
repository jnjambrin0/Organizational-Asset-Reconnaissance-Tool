import logging
import sys
import io
import time
import re
from typing import Optional, Dict, Any, List
from datetime import datetime

# ANSI Color Codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    
    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Bright foreground
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

# Log Symbols and Styles for different log levels
class LogStyle:
    DEBUG = {
        "symbol": "🔍",
        "color": Colors.BRIGHT_BLUE,
        "name": Colors.BOLD + Colors.BRIGHT_BLUE + "DEBUG" + Colors.RESET
    }
    INFO = {
        "symbol": "ℹ️",
        "color": Colors.BRIGHT_GREEN,
        "name": Colors.BOLD + Colors.BRIGHT_GREEN + "INFO" + Colors.RESET
    }
    WARNING = {
        "symbol": "⚠️",
        "color": Colors.BRIGHT_YELLOW,
        "name": Colors.BOLD + Colors.BRIGHT_YELLOW + "WARNING" + Colors.RESET
    }
    ERROR = {
        "symbol": "❌",
        "color": Colors.BRIGHT_RED,
        "name": Colors.BOLD + Colors.BRIGHT_RED + "ERROR" + Colors.RESET
    }
    CRITICAL = {
        "symbol": "💥",
        "color": Colors.BG_RED + Colors.WHITE,
        "name": Colors.BOLD + Colors.BG_RED + Colors.WHITE + "CRITICAL" + Colors.RESET
    }
    
    # Component/Module styles
    COMPONENTS = {
        "app": {"symbol": "🖥️", "color": Colors.BRIGHT_MAGENTA},
        "db": {"symbol": "💾", "color": Colors.BRIGHT_CYAN},
        "discovery": {"symbol": "🔎", "color": Colors.BRIGHT_GREEN},
        "orchestration": {"symbol": "🎭", "color": Colors.BRIGHT_YELLOW},
        "visualization": {"symbol": "📊", "color": Colors.BRIGHT_BLUE},
        "core": {"symbol": "⚙️", "color": Colors.WHITE},
        "utils": {"symbol": "🛠️", "color": Colors.BRIGHT_BLACK},
        "asn": {"symbol": "🌐", "color": Colors.BRIGHT_MAGENTA},
        "ip": {"symbol": "📡", "color": Colors.BRIGHT_CYAN},
        "domain": {"symbol": "🌍", "color": Colors.BRIGHT_BLUE},
        "subdomain": {"symbol": "🔗", "color": Colors.BLUE},
        "cloud": {"symbol": "☁️", "color": Colors.WHITE},
    }

# Custom progress logger for terminal operations
class ProgressLogger:
    def __init__(self, logger, total=100, prefix="Progress", length=30):
        self.logger = logger
        self.total = total
        self.prefix = prefix
        self.length = length
        self.start_time = time.time()
        self.last_percent = -1
        self.last_update_time = 0
        self.update_interval = 0.5  # Minimum seconds between progress updates
        
    def update(self, current, message=""):
        """Update progress bar if enough time has passed or it's the first/last update"""
        current_time = time.time()
        percent = int((current / self.total) * 100)
        
        # Only update if: first update, last update, significant change, or enough time passed
        if (percent != self.last_percent and 
            (self.last_percent == -1 or percent == 100 or 
             current_time - self.last_update_time > self.update_interval)):
            
            elapsed = current_time - self.start_time
            
            # Calculate ETA
            if current > 0:
                eta = elapsed * (self.total / current - 1)
                eta_str = f"{eta:.1f}s remaining" if eta < 60 else f"{eta/60:.1f}m remaining"
            else:
                eta_str = "Calculating..."
                
            # Create progress bar
            filled_length = int(self.length * current // self.total)
            bar = (Colors.BRIGHT_GREEN + '█' * filled_length + 
                   Colors.BRIGHT_BLACK + '░' * (self.length - filled_length) + 
                   Colors.RESET)
            
            # Log the progress
            self.logger.info(f"{self.prefix} |{bar}| {percent}% • {message} • {eta_str}")
            
            self.last_percent = percent
            self.last_update_time = current_time

# Custom formatter that dramatically improves log readability with colors and symbols
class EnhancedFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None, style='%'):
        super().__init__(fmt, datefmt, style)
        self.styles = {
            logging.DEBUG: LogStyle.DEBUG,
            logging.INFO: LogStyle.INFO,
            logging.WARNING: LogStyle.WARNING,
            logging.ERROR: LogStyle.ERROR,
            logging.CRITICAL: LogStyle.CRITICAL
        }
        
    def format(self, record):
        # Get the appropriate style for this log level
        style = self.styles.get(record.levelno, LogStyle.INFO)
        
        # Handle the module/component highlighting
        module_parts = record.name.split('.')
        module_base = module_parts[-1] if module_parts else record.name
        component = "unknown"
        
        # Try to identify component from module name
        for comp_name, comp_style in LogStyle.COMPONENTS.items():
            if comp_name in record.name.lower():
                component = comp_name
                component_style = comp_style
                break
        else:
            # Default style if no component match
            component_style = LogStyle.COMPONENTS.get("utils")
        
        # Format timestamp
        timestamp = self.formatTime(record, self.datefmt)
        
        # Format the record message with contextual colors
        formatted_msg = record.getMessage()
        
        # Add special highlighting for key information in the message
        # Highlight paths, IPs, domains, etc.
        formatted_msg = self._highlight_patterns(formatted_msg)
        
        # Create the log line with enhanced formatting
        log_line = (
            f"{Colors.DIM}{timestamp}{Colors.RESET} "
            f"{style['symbol']} {style['name']} "
            f"[{component_style['color']}{component_style['symbol']} {module_base}{Colors.RESET}] "
            f"{style['color']}{formatted_msg}{Colors.RESET}"
        )
        
        # Handle exceptions with traceback highlighting
        if record.exc_info:
            log_line += '\n' + self._format_traceback(record)
            
        return log_line
    
    def _highlight_patterns(self, message):
        """Highlight specific patterns in log messages"""
        # Highlight file paths
        message = re.sub(r'((?:/[^/\s:]+)+(?:\.\w+)?)', 
                         f"{Colors.BRIGHT_CYAN}\\1{Colors.RESET}", message)
        
        # Highlight domains
        message = re.sub(r'(\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)', 
                         f"{Colors.BRIGHT_BLUE}\\1{Colors.RESET}", message)
        
        # Highlight IPs
        message = re.sub(r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)', 
                         f"{Colors.BRIGHT_MAGENTA}\\1{Colors.RESET}", message)
        
        # Highlight numbers and metrics
        message = re.sub(r'(\b\d+(?:\.\d+)?\s*(?:ms|s|m|KB|MB|GB|TB)?\b)', 
                         f"{Colors.BRIGHT_YELLOW}\\1{Colors.RESET}", message)
        
        return message
    
    def _format_traceback(self, record):
        """Format exception traceback with syntax highlighting"""
        import traceback
        
        # Get the traceback text
        tb_text = ''.join(traceback.format_exception(*record.exc_info))
        
        # Add colors to different parts of the traceback
        colored_tb = (
            f"{Colors.BRIGHT_RED}Traceback:{Colors.RESET}\n"
        )
        
        # Process each line
        for line in tb_text.split('\n'):
            if "File " in line:
                # Highlight file and line info
                colored_tb += re.sub(r'(File ".*", line \d+.*)', 
                                    f"{Colors.BRIGHT_CYAN}\\1{Colors.RESET}", line) + '\n'
            elif line.strip().startswith('raise '):
                # Highlight raise statements
                colored_tb += f"{Colors.BRIGHT_RED}{line}{Colors.RESET}\n"
            elif ': ' in line and not line.startswith(' '):
                # Highlight exception type and message
                exception_parts = line.split(': ', 1)
                colored_tb += (f"{Colors.BOLD}{Colors.BRIGHT_RED}{exception_parts[0]}{Colors.RESET}: "
                              f"{Colors.BRIGHT_YELLOW}{exception_parts[1]}{Colors.RESET}\n")
            else:
                colored_tb += line + '\n'
                
        return colored_tb

# Custom handler to write logs to a StringIO object
class StringLogHandler(logging.StreamHandler):
    def __init__(self, string_io):
        super().__init__(string_io)
        self.string_io = string_io

def create_progress_logger(logger_name, total=100, prefix="Progress"):
    """Helper function to create a progress logger quickly"""
    logger = logging.getLogger(logger_name)
    return ProgressLogger(logger, total, prefix)

def setup_logging(level=logging.INFO, log_format=None, date_format=None, stream_handler=None, 
                  use_enhanced_formatter=True, color_enabled=True):
    """Configures logging for the application with enhanced formatting.
    
    Args:
        level: The minimum logging level (default: INFO)
        log_format: Custom log format string (ignored if use_enhanced_formatter=True)
        date_format: Custom date format string (default: '%Y-%m-%d %H:%M:%S')
        stream_handler: Optional custom stream handler (e.g., for UI)
        use_enhanced_formatter: Whether to use the enhanced colorful formatter (default: True)
        color_enabled: Whether to enable ANSI colors in terminal output (default: True)
    """
    if date_format is None:
        date_format = '%Y-%m-%d %H:%M:%S'

    # Create appropriate formatter based on settings
    if use_enhanced_formatter and color_enabled:
        formatter = EnhancedFormatter(datefmt=date_format)
    else:
        if log_format is None:
            log_format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
        formatter = logging.Formatter(log_format, datefmt=date_format)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # --- Configure Terminal Handler --- 
    # Check if a terminal handler already exists
    has_terminal_handler = any(
        isinstance(h, logging.StreamHandler) and h.stream in (sys.stdout, sys.stderr) 
        for h in root_logger.handlers
    )
    
    if not has_terminal_handler:
        terminal_handler = logging.StreamHandler(sys.stderr)
        terminal_handler.setLevel(level)
        terminal_handler.setFormatter(formatter)
        root_logger.addHandler(terminal_handler)
        
        # Log a test message to confirm formatter is working - but only if we're NOT
        # being called early in the application startup
        if root_logger.level <= logging.DEBUG:
            logging.debug("Enhanced terminal logging initialized")
    else:
        # Update existing terminal handler's formatter if needed
        for handler in root_logger.handlers:
            if isinstance(handler, logging.StreamHandler) and handler.stream in (sys.stdout, sys.stderr):
                handler.setFormatter(formatter)

    # --- Configure Custom Stream Handler (e.g., for UI) --- 
    if stream_handler:
        # For UI stream handler, always use simple formatter without colors
        simple_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', 
                                            datefmt=date_format)
        stream_handler.setLevel(level)
        stream_handler.setFormatter(simple_formatter)
        
        # Add the custom handler if it doesn't exist yet
        if not any(isinstance(h, type(stream_handler)) for h in root_logger.handlers):
             root_logger.addHandler(stream_handler)

def get_logger(name):
    """Helper function to get a configured logger for a component"""
    return logging.getLogger(name)

# Example usage with progress bar:
"""
from src.utils.logging_config import setup_logging, create_progress_logger
import time

# Configure logging
setup_logging(level=logging.DEBUG)

# Get a logger for your component
logger = logging.getLogger("demo")

# Log some messages
logger.debug("This is a debug message")
logger.info("Starting the process")
logger.warning("This is a warning message")

# Create a progress logger
progress = create_progress_logger("demo", total=100, prefix="Processing")

# Simulate a long operation
for i in range(101):
    progress.update(i, f"Step {i}/100")
    time.sleep(0.05)

logger.info("Process complete!")

try:
    # Cause an exception
    result = 10 / 0
except Exception as e:
    logger.error(f"An error occurred during calculation", exc_info=True)

logger.critical("Critical system failure detected!")
"""

# Call setup_logging() early in your application entry point (e.g., app.py) 