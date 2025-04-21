# Product Requirements Document: Organizational Asset Reconnaissance Tool (MVP)

## 1. Introduction/Overview

This document outlines the requirements for the Minimum Viable Product (MVP) of the Organizational Asset Reconnaissance Tool. The tool aims to automate the discovery of an organization's publicly exposed digital assets, providing an initial view of its external attack surface. The primary problem it solves is the lack of visibility organizations often have into their complete online footprint, which creates security risks from unmonitored assets.

## 2. Goals

*   Provide users with an automated way to discover ASNs, IP ranges, and basic domain/subdomain information related to a target organization.
*   Enable internal security teams, pentesters, and consultants to perform initial, passive reconnaissance.
*   Offer simple export capabilities (CSV/text) for discovered assets.
*   Present discovered data in a clear, understandable format within the Streamlit interface.
*   Establish a modular foundation for future enhancements (e.g., cloud detection, advanced visualizations).

## 3. User Stories

*   **As an internal security analyst,** I want to input my organization's name and known domains so that I can quickly identify associated ASNs and IP ranges we own or operate.
*   **As a penetration tester,** I want to provide a target organization's name so that I can get a list of their potential domains and subdomains to investigate further.
*   **As a security consultant,** I want to generate a basic report of discovered assets (ASNs, IPs, Domains) in CSV format so that I can analyze it offline or include it in my assessment findings.
*   **As any user,** I want to see the progress of the reconnaissance scan so that I know the tool is working and how long it might take.
*   **As a manager reviewing the results,** I want to see a simple summary chart (e.g., pie chart of asset types) so that I can quickly grasp the overall composition of the discovered footprint.

## 4. Functional Requirements

1.  **Input:** The system must accept the target organization's name as the primary input.
2.  **Input (Optional):** The system should allow users to optionally provide known base domain names for the organization.
3.  **ASN Discovery:** The system must query public sources (e.g., BGP.HE.NET, WHOIS) to identify Autonomous System Numbers (ASNs) associated with the organization's name or domains.
4.  **IP Range Mapping:** The system must identify IPv4 and IPv6 network ranges (CIDR blocks) associated with the discovered ASNs or known domains.
5.  **Domain/Subdomain Enumeration (Basic):** The system must perform basic enumeration using public sources (e.g., crt.sh, DNSDumpster, passive DNS) to find domains and subdomains linked to the organization name or base domains.
6.  **Data Sources:** The system must utilize passive, publicly available data sources only (as defined in `project_context`).
7.  **Interface (Display):** The system must display discovered ASNs, IP ranges, and domains/subdomains in clear tables within the Streamlit UI.
8.  **Interface (Progress):** The system should provide visual feedback indicating that a scan is in progress.
9.  **Data Storage (Session):** The system must store discovered asset data for the duration of the user's session.
10. **Data Export:** The system must allow users to export the discovered assets list into CSV or plain text format. The export should contain the critical information defined (See section 6 below).
11. **Relationships (Implicit):** The system should implicitly store relationships by grouping results (e.g., show subdomains under their parent domain, show IPs associated with an ASN).

## 5. Non-Goals (Out of Scope for MVP)

*   Active port scanning or service identification.
*   Vulnerability scanning or exploitation attempts.
*   Brute-force attacks or credential testing.
*   Advanced cloud provider detection and resource mapping.
*   Complex network topology visualizations or relationship graphs.
*   Persistent database storage beyond the user session.
*   User authentication or multi-user support.
*   Advanced subdomain enumeration techniques (e.g., DNS zone transfers, permutation scanning).
*   Any actions causing significant network traffic or potentially disrupting services.
*   HTML or Markdown report formats (only CSV/text for MVP).

## 6. Design Considerations

*   **UI:** Use Streamlit to provide a clean, user-friendly, and "bright" web interface as per `project_context`.
*   **MVP Visualizations:**
    *   Tables for ASNs, IP Ranges, Domains/Subdomains.
    *   Simple Pie Chart showing the count distribution by asset type (ASN, IP, Domain).
    *   Basic Tree View for domain/subdomain hierarchy.
*   **Report Content (CSV/Text):**
    *   **ASNs:** ASN Number, Organization Name, Description, Data Source.
    *   **IP Ranges:** CIDR Notation, IP Version (v4/v6), Associated ASN (if known), Country.
    *   **Domains:** Domain Name, Registrar (if available), Associated IPs (if resolved).
    *   **Subdomains:** Full Subdomain Name, Status (e.g., 'Active' if resolvable), Associated IPs (if resolved).

## 7. Technical Considerations

*   **Language:** Python 3.13 (`project_context`).
*   **Environment:** Use `venv` (`project_context`).
*   **Modularity:** Structure the code into distinct modules for each discovery type (ASN, IP, Domain) and for data source interaction (`project_context`).
*   **Dependencies:** Manage dependencies via `requirements.txt` (`project_context`).
*   **Data Sources:** Interface with external APIs/sources like BGP.HE.NET, crt.sh, DNSDumpster, WHOIS (ensure compliance with their terms of service).
*   **Error Handling:** Implement basic error handling for external API calls or data parsing issues.
*   **Testing:** Unit tests are required for core discovery logic (`project_context`).

## 8. Success Metrics

*   Successful discovery of known ASNs/IPs/Domains for test organizations.
*   User feedback indicating ease of use and clarity of results.
*   Ability to export data correctly in specified formats.
*   Codebase adheres to modularity and testing requirements outlined in `project_context`.

## 9. Open Questions

*   Are there specific rate limits or API keys required for the chosen data sources that need to be managed?
*   How should the "Status" of a subdomain (active/inactive) be determined reliably for the MVP (e.g., simple DNS resolution)?
*   What is the acceptable duration for a typical scan in the MVP? 