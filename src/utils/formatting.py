"""
Formatting utilities for ReconForge application.
"""

from datetime import datetime
from typing import Union

def format_datetime_for_ui(dt: Union[datetime, str, None], format_str: str = '%Y-%m-%d %H:%M') -> str:
    """
    Format datetime objects for UI display with safe handling.
    
    Args:
        dt: Datetime object, string, or None
        format_str: strftime format string
        
    Returns:
        Formatted datetime string
    """
    if dt is None:
        return "N/A"
    
    if isinstance(dt, datetime):
        return dt.strftime(format_str)
    
    # If it's already a string, return as is (or truncate if needed)
    dt_str = str(dt)
    if len(dt_str) > 16:
        return dt_str[:16]
    
    return dt_str

def safe_slice_datetime(dt: Union[datetime, str, None], length: int = 16) -> str:
    """
    Safely slice datetime for display, handling both datetime objects and strings.
    
    Args:
        dt: Datetime object, string, or None
        length: Maximum length of returned string
        
    Returns:
        Truncated datetime string
    """
    if dt is None:
        return "N/A"
    
    if isinstance(dt, datetime):
        # Format datetime and then slice if needed
        formatted = dt.strftime('%Y-%m-%d %H:%M:%S')
        return formatted[:length] if len(formatted) > length else formatted
    
    # Handle string case
    dt_str = str(dt)
    return dt_str[:length] if len(dt_str) > length else dt_str

def format_scan_display_date(dt: Union[datetime, str, None]) -> str:
    """
    Format datetime specifically for scan display in UI.
    
    Args:
        dt: Datetime object, string, or None
        
    Returns:
        Formatted datetime string suitable for scan display
    """
    return format_datetime_for_ui(dt, '%Y-%m-%d %H:%M')

def format_file_timestamp(dt: Union[datetime, str, None]) -> str:
    """
    Format datetime for use in filenames.
    
    Args:
        dt: Datetime object, string, or None
        
    Returns:
        Filename-safe datetime string
    """
    if dt is None:
        return "unknown"
    
    if isinstance(dt, datetime):
        return dt.strftime('%Y%m%d_%H%M%S')
    
    # Clean string for filename use
    dt_str = str(dt).replace(':', '').replace('-', '').replace(' ', '_')
    return dt_str[:15]  # Reasonable length for filenames 