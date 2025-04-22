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
                   Colors.DIM + '░' * (self.length - filled_length) +
                   Colors.RESET)
            
            # Log the progress
            self.logger.info(f"{self.prefix} |{bar}| {percent}% • {message} • {eta_str}")
            
            self.last_percent = percent
            self.last_update_time = current_time

# Regular expression to match ANSI escape codes
ANSI_ESCAPE_REGEX = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')

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
        component_style = LogStyle.COMPONENTS.get("utils") # Default style

        # Try to identify component more specifically
        # Check from longest path backwards to find the most specific component match
        current_path = ""
        for i, part in enumerate(module_parts):
            current_path = f"{current_path}.{part}" if current_path else part
            potential_component = part # Check the individual part
            if potential_component in LogStyle.COMPONENTS:
                 component = potential_component
                 component_style = LogStyle.COMPONENTS[potential_component]
                 # Keep searching for more specific matches further down the path if needed
                 # If the last part matches, it's likely the most specific one
                 if i == len(module_parts) - 1:
                     module_base = part # Use the component name as base if it's the last part

        # Format timestamp
        timestamp = self.formatTime(record, self.datefmt)
        
        # Get the raw message
        raw_msg = record.getMessage()

        # Strip any existing ANSI codes from the raw message first
        cleaned_msg = ANSI_ESCAPE_REGEX.sub('', raw_msg)

        # Format the cleaned record message with contextual colors
        formatted_msg = self._highlight_patterns(cleaned_msg)
        
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
        # Highlight file paths (more robust: handles relative/absolute, common extensions)
        # Ensure it doesn't capture parts of other highlighted items like domains with .html
        # Apply path highlighting first to avoid conflicts
        path_pattern = r'((?:\b[\w\.\-\/]+[\/\\])?[\w\.\-]+\.(?:html|py|json|txt|log|csv|db|sqlite|png|jpg|jpeg|gif))\b'
        message = re.sub(path_pattern,
                         f"{Colors.BRIGHT_CYAN}\\1{Colors.RESET}", message)

        # Highlight domains (avoid matching filenames like .html)
        domain_pattern = r'(\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?!html\b|py\b|json\b|txt\b|log\b|csv\b|db\b|sqlite\b|png\b|jpe?g\b|gif\b)[a-zA-Z]{2,}\b)'
        message = re.sub(domain_pattern,
                         f"{Colors.BRIGHT_BLUE}\\1{Colors.RESET}", message)

        # Highlight IPs (IPv4)
        message = re.sub(r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)',
                         f"{Colors.BRIGHT_MAGENTA}\\1{Colors.RESET}", message)

        # Highlight IPv6 Addresses (various forms)
        # Basic regex, might need refinement for edge cases like embedded IPv4
        ipv6_pattern = r'(\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}:){0,6}\b|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b)'
        message = re.sub(ipv6_pattern,
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
            if line.strip().startswith("File "):
                # Dim file and line info
                colored_tb += re.sub(r'(File ".*", line \d+, in .*)',
                                     f"{Colors.DIM}\\1{Colors.RESET}", line) + '\n'
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
        # Use a simple formatter without ANSI codes for the UI log stream
        self.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
            datefmt="%Y-%m-%d %H:%M:%S"
        ))

    def format(self, record):
        """Override format to strip ANSI codes after standard formatting."""
        # Get the formatted message from the base class/formatter
        msg = super().format(record)
        # Ensure any potential ANSI codes are stripped
        return ANSI_ESCAPE_REGEX.sub('', msg)

def create_progress_logger(logger_name, total=100, prefix="Progress"):
    """Helper function to create a progress logger quickly"""
    logger = logging.getLogger(logger_name)
    return ProgressLogger(logger, total, prefix)

def setup_logging(level=logging.INFO, log_format=None, date_format=None, stream_handler=None, 
                  use_enhanced_formatter=True, color_enabled=True):
    """Sets up root logger configuration with optional handlers and enhanced formatting.

    Args:
        level: The logging level (e.g., logging.INFO).
        log_format: The format string for logs (overrides enhanced formatter).
        date_format: The format string for timestamps.
        stream_handler: An optional pre-configured stream handler (e.g., for StringIO).
        use_enhanced_formatter: Whether to use the custom EnhancedFormatter.
        color_enabled: Whether to enable color output (relevant for EnhancedFormatter).
    """
    # Get the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers from the root logger to avoid duplication
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    # Determine the formatter
    if log_format:
        formatter = logging.Formatter(fmt=log_format, datefmt=date_format)
    elif use_enhanced_formatter:
        # Pass color_enabled to the formatter if needed (currently EnhancedFormatter handles color internally)
        formatter = EnhancedFormatter(datefmt=date_format or "%Y-%m-%d %H:%M:%S")
    else:
        # Default basic formatter
        formatter = logging.Formatter(fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                                      datefmt=date_format)

    # --- Configure Handlers --- 

    # 1. Add the provided stream_handler (e.g., StringLogHandler for UI)
    if stream_handler:
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(level)
        root_logger.addHandler(stream_handler)
        print(f"DEBUG: Added provided stream_handler ({type(stream_handler).__name__}) to root logger.")

    # 2. Add a standard StreamHandler to stderr for terminal output (for debugging)
    # This ensures logs also appear in the console where the app might be run
    try:
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setFormatter(formatter)
        stderr_handler.setLevel(level)
        root_logger.addHandler(stderr_handler)
        # Use print for this debug message as logging might not be fully configured yet
        print("DEBUG: Added standard StreamHandler(stderr) to root logger for terminal visibility.")
    except Exception as e:
        print(f"DEBUG: Failed to add stderr_handler: {e}")

    # Log a confirmation message using the now configured logger
    root_logger.debug("Logging configured with level %s and formatter %s", 
                     logging.getLevelName(level), type(formatter).__name__)

    # Configure logging for libraries that might interfere
    # Example: Quieten noisy libraries if needed
    # logging.getLogger('urllib3').setLevel(logging.WARNING)
    # logging.getLogger('ipwhois').setLevel(logging.INFO) # Or WARNING if too verbose

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