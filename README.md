# Organizational Asset Reconnaissance Tool

[![Python Version](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Author](https://img.shields.io/badge/Author-jnjambrino-brightgreen.svg)](https://github.com/jnjambrino)

**Note:** This project is primarily developed for academic and educational purposes to explore techniques for organizational asset reconnaissance.

This tool automates the discovery and mapping of digital assets associated with an organization, providing a comprehensive view of its potential external digital footprint.

## Features

*   🔍 **ASN Discovery**: Identifies Autonomous System Numbers (ASNs) linked to an organization name (primarily via BGP.HE.NET).
*   🌐 **IP Range Mapping**: Retrieves and lists network blocks (CIDRs) announced by the discovered ASNs (via BGP.HE.NET).
*   🔗 **Domain/Subdomain Enumeration**: Finds registered domains potentially related to the organization and enumerates subdomains using public sources (like crt.sh). Includes basic DNS resolution checks.
*   ☁️ **Cloud Provider Detection**: Attempts to identify potential cloud hosting providers (AWS, Azure, GCP) based on known IP ranges and common domain patterns.
*   📊 **Visualizations**: Provides basic charts including:
    *   Asset type distribution (pie chart).
    *   ASN counts (bar chart).
    *   An interactive network graph showing relationships between the organization, ASNs, domains, and IP ranges (via Pyvis).
*   📄 **Reporting**: Allows exporting discovered assets:
    *   To individual CSV files per asset type (ASNs, IP Ranges, Domains, Subdomains, Cloud Services).
    *   As a consolidated plain text summary report.
    *   As a JSON file containing the complete result data.
*   ✨ **Web Interface**: Features an interactive user interface built with Streamlit for easy configuration and result navigation.
*   💾 **Scan History**: Saves scan results to a local database (`recon_results.db`) for later review.
*   ⚙️ **Process Logging**: Displays detailed logs of the reconnaissance process within the web UI.

## Setup

Ensure you have Python 3.13 or newer installed.

1.  **Clone the repository:**
    ```bash
    # Replace <your-repository-url> with the actual URL if forked
    git clone <your-repository-url>
    cd org-recon
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    # Using Python 3.13 or your specific Python 3.13+ command
    python3.13 -m venv venv
    # Activate the environment
    source venv/bin/activate  # On Linux/macOS
    # venv\Scripts\activate    # On Windows CMD/PowerShell
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **(Optional) Install development dependencies:**
    If you plan to contribute or run tests, install the development requirements:
    ```bash
    pip install -r requirements-dev.txt
    ```

5.  **(Optional) Setup Environment Variables:**
    While the current version primarily uses public data sources that may not require API keys, future integrations might. It's good practice to set up an environment file:
    ```bash
    # If an .env.example file exists, copy it:
    # cp .env.example .env
    # Then edit the .env file with any required keys.
    ```

## Usage

1.  **Activate the virtual environment** (if not already active):
    ```bash
    source venv/bin/activate  # Or the Windows equivalent
    ```

2.  **Run the Streamlit application:**
    The terminal will display a banner, and the application will start.
    ```bash
    streamlit run src/app.py
    ```

3.  **Open your web browser** to the local URL provided by Streamlit (typically `http://localhost:8501`).

4.  **Navigate the UI:**
    *   Use the sidebar to start a **New Scan** or view **History**.
    *   When starting a new scan, enter the **Target Organization Name**.
    *   (Optional) Provide known **Base Domains** (one per line) to focus the domain search.
    *   (Optional) Adjust **Advanced Options** like the maximum number of worker threads.
    *   Click **Start Reconnaissance**.

5.  **View Results:**
    *   Monitor the **Process** tab for live logs and progress updates.
    *   Explore discovered assets in the **Summary**, **ASNs & IPs**, **Domains**, and **Cloud** tabs.
    *   Interact with visualizations in the **Visualizations** tab.
    *   Download reports (Text, JSON, CSVs) and view logs in the **Reports & Logs** tab.

## Development & Testing

*   **Running Tests:**
    ```bash
    pytest
    ```
*   **Code Style:** The codebase aims to adhere to [PEP 8](https://www.python.org/dev/peps/pep-0008/). We recommend using code formatters like `black` and linters like `ruff` (see `CONTRIBUTING.md`).

## Contributing

Contributions are welcome! Please refer to the [CONTRIBUTING.md](CONTRIBUTING.md) file for detailed guidelines on how to get involved, report issues, suggest features, and submit pull requests.

## Authors

*   **jnjambrino** - *Initial work & Maintainer* - [GitHub Profile](https://github.com/jnjambrino)

## Disclaimer

⚠️ **Important Notice:** This tool is developed and intended strictly for **educational purposes** and for use in authorized security auditing or research scenarios where explicit permission has been granted. 

Performing unauthorized reconnaissance or scanning activities on networks or systems you do not own or have permission to test is **illegal and unethical**. The creator and contributors of this tool assume **no liability** and are not responsible for any misuse, damage, or legal consequences arising from the use of this software. 

**Use responsibly and ethically.**

## License

This project is licensed under the **Apache License 2.0**. See the `LICENSE` file for full details.