"""Custom exception classes for the reconnaissance tool."""

class ReconToolError(Exception):
    """Base class for exceptions in this application."""
    pass

class DataSourceError(ReconToolError):
    """Raised when there's an error interacting with an external data source."""
    def __init__(self, source: str, message: str):
        self.source = source
        self.message = message
        super().__init__(f"Error from {source}: {message}")

class RateLimitError(DataSourceError):
    """Raised when a data source indicates a rate limit has been exceeded."""
    pass

class ConfigurationError(ReconToolError):
    """Raised for configuration-related problems (e.g., missing API key)."""
    pass

class ValidationError(ReconToolError):
    """Raised when input data or discovered data fails validation."""
    pass 