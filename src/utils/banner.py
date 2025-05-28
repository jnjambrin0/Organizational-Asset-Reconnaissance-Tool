"""
Enhanced Terminal Banner System for ReconForge
Author: jnjambrino
Advanced ASCII art and visual effects for professional reconnaissance tool
"""

import time
import sys
from .logging_config import Colors, CyberColors, Symbols, AdvancedBannerSystem

def print_ascii_logo():
    """Print the enhanced ASCII logo with gradient effects."""
    logo = f"""
{CyberColors.CYBER_BLUE}    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██║{Colors.RESET}{CyberColors.MATRIX_GREEN}███████╗ ██████╗ ██████╗  ██████╗ ███████╗{Colors.RESET}
{CyberColors.CYBER_BLUE}    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║{Colors.RESET}{CyberColors.MATRIX_GREEN}██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝{Colors.RESET}
{CyberColors.CYBER_BLUE}    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║{Colors.RESET}{CyberColors.MATRIX_GREEN}█████╗  ██║   ██║██████╔╝██║  ███╗█████╗{Colors.RESET}
{CyberColors.CYBER_BLUE}    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║{Colors.RESET}{CyberColors.MATRIX_GREEN}██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝{Colors.RESET}
{CyberColors.CYBER_BLUE}    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║{Colors.RESET}{CyberColors.MATRIX_GREEN}██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗{Colors.RESET}
{CyberColors.CYBER_BLUE}    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{Colors.RESET}{CyberColors.MATRIX_GREEN}╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝{Colors.RESET}
    """
    return logo

def print_enhanced_banner():
    """Print the complete enhanced banner with animations and system info."""
    width = 88
    
    # Clear screen effect (optional)
    # print("\033[2J\033[H", end="")
    
    # Top border with gradient
    print(f"{CyberColors.CYBER_BLUE}{'═' * width}{Colors.RESET}")
    
    # Main logo
    print(print_ascii_logo())
    
    # Subtitle with cyberpunk styling
    subtitle_line = f"{Colors.BOLD}{CyberColors.NEON_PURPLE}Enterprise Asset Intelligence & Discovery Platform{Colors.RESET}"
    subtitle_padding = (width - len("Enterprise Asset Intelligence & Discovery Platform") - 4) // 2
    print(f"{' ' * subtitle_padding}{subtitle_line}")
    
    # Version and author info
    version_info = f"{Colors.DIM}v2.0 - Advanced Reconnaissance System{Colors.RESET}"
    author_info = f"{Colors.ITALIC}{CyberColors.WARNING_AMBER}by jnjambrino{Colors.RESET}"
    
    print(f"{' ' * ((width - 30) // 2)}{version_info}")
    print(f"{' ' * ((width - 15) // 2)}{author_info}")
    
    # Separator
    print(f"{CyberColors.CYBER_BLUE}{'═' * width}{Colors.RESET}")
    
    # Mission briefing section
    print(f"\n{Symbols.SHIELD} {Colors.BOLD}{CyberColors.SUCCESS_GREEN}MISSION BRIEFING{Colors.RESET}")
    print(f"{CyberColors.CYBER_BLUE}{'━' * 20}{Colors.RESET}")
    
    mission_points = [
        f"{Symbols.TARGET} {Colors.BOLD}OBJECTIVE:{Colors.RESET} Comprehensive organizational asset reconnaissance",
        f"{Symbols.RADAR} {Colors.BOLD}SCOPE:{Colors.RESET} Autonomous systems, domains, cloud infrastructure",
        f"{Symbols.BOLT} {Colors.BOLD}CAPABILITY:{Colors.RESET} Intelligent learning and adaptive discovery",
        f"{Symbols.LOCK} {Colors.BOLD}CLASSIFICATION:{Colors.RESET} {CyberColors.DANGER_RED}AUTHORIZED PERSONNEL ONLY{Colors.RESET}"
    ]
    
    for point in mission_points:
        print(f"  {point}")
    
    # System status indicators
    print(f"\n{Symbols.GEAR} {Colors.BOLD}{CyberColors.SUCCESS_GREEN}SYSTEM STATUS{Colors.RESET}")
    print(f"{CyberColors.CYBER_BLUE}{'━' * 20}{Colors.RESET}")
    
    status_items = [
        (f"{Symbols.ROCKET} Discovery Engine", f"{CyberColors.MATRIX_GREEN}ONLINE{Colors.RESET}"),
        (f"{Symbols.DATABASE} Intelligence Database", f"{CyberColors.MATRIX_GREEN}READY{Colors.RESET}"),
        (f"{Symbols.NETWORK} Network Modules", f"{CyberColors.MATRIX_GREEN}ACTIVE{Colors.RESET}"),
        (f"{Symbols.MAGIC} AI Learning System", f"{CyberColors.SUCCESS_GREEN}ENABLED{Colors.RESET}"),
        (f"{Symbols.SHIELD} Security Framework", f"{CyberColors.MATRIX_GREEN}SECURED{Colors.RESET}")
    ]
    
    for label, status in status_items:
        print(f"  {label:<25} [{status}]")
    
    # Warning notice
    print(f"\n{CyberColors.DANGER_RED}{'▼' * width}{Colors.RESET}")
    print(f"{Colors.BOLD}{CyberColors.DANGER_RED}⚠️  OPERATIONAL SECURITY NOTICE{Colors.RESET}")
    print(f"{Colors.DIM}This tool performs active reconnaissance. Ensure proper authorization before use.{Colors.RESET}")
    print(f"{Colors.DIM}Rate limiting and respectful scanning practices are enforced.{Colors.RESET}")
    print(f"{CyberColors.DANGER_RED}{'▲' * width}{Colors.RESET}")
    
    # Bottom border
    print(f"\n{CyberColors.CYBER_BLUE}{'═' * width}{Colors.RESET}")
    print(f"{Colors.BOLD}{CyberColors.SUCCESS_GREEN}{' ' * ((width - 30) // 2)}🚀 READY FOR OPERATIONS 🚀{Colors.RESET}")
    print(f"{CyberColors.CYBER_BLUE}{'═' * width}{Colors.RESET}\n")

def print_mission_header(target_organization: str):
    """Print a mission-specific header."""
    width = 80
    
    print(f"\n{CyberColors.NEON_PURPLE}{'◆' * width}{Colors.RESET}")
    print(f"{Symbols.TARGET} {Colors.BOLD}{CyberColors.SUCCESS_GREEN}NEW MISSION INITIALIZED{Colors.RESET}")
    print(f"{CyberColors.NEON_PURPLE}{'◆' * width}{Colors.RESET}")
    
    # Target info
    target_line = f"TARGET: {CyberColors.CYBER_BLUE}{target_organization}{Colors.RESET}"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC")
    timestamp_line = f"TIMESTAMP: {CyberColors.WARNING_AMBER}{timestamp}{Colors.RESET}"
    
    print(f"  {target_line}")
    print(f"  {timestamp_line}")
    print(f"  MISSION ID: {CyberColors.SUCCESS_GREEN}{hash(target_organization + timestamp) % 10000:04d}{Colors.RESET}")
    
    print(f"{CyberColors.NEON_PURPLE}{'◆' * width}{Colors.RESET}")
    
    # Operation phases
    phases = [
        f"{Symbols.RADAR} Phase 1: Intelligence Gathering",
        f"{Symbols.NETWORK} Phase 2: Network Enumeration", 
        f"{Symbols.CLOUD} Phase 3: Cloud Infrastructure Analysis",
        f"{Symbols.MAGIC} Phase 4: AI-Powered Asset Discovery"
    ]
    
    print(f"\n{Colors.BOLD}MISSION PHASES:{Colors.RESET}")
    for phase in phases:
        print(f"  {phase}")
    
    print(f"\n{CyberColors.SUCCESS_GREEN}{'─' * width}{Colors.RESET}")
    print(f"{Symbols.BOLT} {Colors.BOLD}COMMENCING RECONNAISSANCE OPERATIONS...{Colors.RESET}")
    print(f"{CyberColors.SUCCESS_GREEN}{'─' * width}{Colors.RESET}\n")

def print_mission_complete(target_organization: str, duration: float, assets_discovered: int):
    """Print mission completion banner."""
    width = 80
    
    print(f"\n{CyberColors.MATRIX_GREEN}{'★' * width}{Colors.RESET}")
    print(f"{Symbols.SUCCESS} {Colors.BOLD}{CyberColors.MATRIX_GREEN}MISSION ACCOMPLISHED{Colors.RESET}")
    print(f"{CyberColors.MATRIX_GREEN}{'★' * width}{Colors.RESET}")
    
    # Mission summary
    summary_items = [
        f"TARGET: {CyberColors.CYBER_BLUE}{target_organization}{Colors.RESET}",
        f"DURATION: {CyberColors.WARNING_AMBER}{duration:.2f} seconds{Colors.RESET}",
        f"ASSETS DISCOVERED: {CyberColors.SUCCESS_GREEN}{assets_discovered}{Colors.RESET}",
        f"STATUS: {CyberColors.MATRIX_GREEN}COMPLETE{Colors.RESET}"
    ]
    
    for item in summary_items:
        print(f"  {item}")
    
    print(f"{CyberColors.MATRIX_GREEN}{'★' * width}{Colors.RESET}")
    print(f"{Colors.BOLD}Intelligence successfully archived for future analysis.{Colors.RESET}")
    print(f"{CyberColors.MATRIX_GREEN}{'★' * width}{Colors.RESET}\n")

def print_error_banner(error_message: str):
    """Print an error banner."""
    width = 80
    
    print(f"\n{CyberColors.DANGER_RED}{'!!' * (width // 2)}{Colors.RESET}")
    print(f"{Symbols.ERROR} {Colors.BOLD}{CyberColors.DANGER_RED}MISSION FAILURE{Colors.RESET}")
    print(f"{CyberColors.DANGER_RED}{'!!' * (width // 2)}{Colors.RESET}")
    
    print(f"  ERROR: {CyberColors.WARNING_AMBER}{error_message}{Colors.RESET}")
    print(f"  STATUS: {CyberColors.DANGER_RED}ABORTED{Colors.RESET}")
    
    print(f"{CyberColors.DANGER_RED}{'!!' * (width // 2)}{Colors.RESET}")
    print(f"{Colors.DIM}Review logs for detailed error information.{Colors.RESET}")
    print(f"{CyberColors.DANGER_RED}{'!!' * (width // 2)}{Colors.RESET}\n")

def animated_typewriter_effect(text: str, delay: float = 0.03):
    """Print text with typewriter animation effect."""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def print_loading_animation(message: str = "Initializing systems", duration: float = 3.0):
    """Print a loading animation."""
    spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]  # Using default spinner since Symbols.SPINNER doesn't exist
    end_time = time.time() + duration
    i = 0
    
    while time.time() < end_time:
        spinner = spinner_chars[i % len(spinner_chars)]
        print(f"\r{spinner} {CyberColors.SUCCESS_GREEN}{message}...{Colors.RESET}", end='', flush=True)
        time.sleep(0.1)
        i += 1
    
    print(f"\r{Symbols.SUCCESS} {CyberColors.MATRIX_GREEN}{message} complete!{Colors.RESET}")

if __name__ == "__main__":
    # Demo of the enhanced banner system
    print_enhanced_banner()
    time.sleep(1)
    print_loading_animation("System initialization", 2.0)
    time.sleep(0.5)
    print_mission_header("example.com")
    time.sleep(1)
    print_mission_complete("example.com", 45.6, 127)
