import logging
import sys
import io
from typing import Optional

# Custom handler to capture logs in a string buffer
class StringLogHandler(logging.Handler):
    def __init__(self, log_stream):
        super().__init__()
        self.log_stream = log_stream

    def emit(self, record):
        try:
            msg = self.format(record)
            self.log_stream.write(msg + "\n")
        except Exception:
            self.handleError(record)

def setup_logging(level=logging.INFO, stream_handler: Optional[logging.Handler] = None):
    """Configure logging for the application.

    Args:
        level: The logging level.
        stream_handler: An optional additional handler (e.g., StringLogHandler).
    """
    log_format = "%(asctime)s - %(levelname)s - %(name)s - %(message)s"
    handlers = [logging.StreamHandler(sys.stdout)] # Log to stdout by default
    if stream_handler:
        handlers.append(stream_handler)
        
    # Remove existing handlers to avoid duplication if called multiple times
    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        for handler in root_logger.handlers[:]:
             root_logger.removeHandler(handler)
             
    logging.basicConfig(level=level,
                        format=log_format,
                        handlers=handlers,
                        force=True # Override existing config
                        )

    logger = logging.getLogger(__name__)
    logger.debug("Logging configured.")

# Example usage:
# from io import StringIO
# log_capture_string = StringIO()
# string_handler = StringLogHandler(log_capture_string)
# string_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")) # Simple format for UI
# setup_logging(level=logging.INFO, stream_handler=string_handler)
# ... run code ...
# captured_logs = log_capture_string.getvalue()

# Call setup_logging() early in your application entry point (e.g., app.py) 