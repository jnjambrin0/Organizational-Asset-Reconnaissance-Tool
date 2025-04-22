# Organizational Asset Reconnaissance Tool

[![Python Version](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Author](https://img.shields.io/badge/Author-jnjambrino-brightgreen.svg)](https://github.com/jnjambrino)

This tool automates the discovery of digital assets belonging to an organization, providing a comprehensive view of its digital footprint on the Internet.

## Features (MVP)

*   🔍 **ASN Discovery**: Identifies autonomous systems (via BGP.HE.NET).
*   🌐 **IP Range Mapping**: Lists network blocks announced by discovered ASNs (via BGP.HE.NET).
*   🔗 **Domain/Subdomain Enumeration**: Finds domains and subdomains (via crt.sh) and checks basic DNS resolution status.
*   ☁️ **Cloud Provider Detection**: Identifies potential cloud services based on known IP ranges (AWS, Azure, GCP) and domain patterns.
*   📊 **Basic Visualizations**: Includes an asset type distribution pie chart and ASN bar chart.
*   📄 **Reporting**: Export discovered assets to CSV (per asset type) or a consolidated Text report.
*   ✨ **Web Interface**: Interactive UI built with Streamlit.

## Setup

1.  **Clone the repository:**
```bash
    git clone <your-repository-url>
cd org-recon
    ```

2.  **Create and activate virtual environment (Python 3.13 required):**
    ```bash
    python3.13 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **(Optional) Install development dependencies:**
    ```bash
    pip install -r requirements-dev.txt 
    ```

5.  **(Optional) Setup Environment Variables:**
    If any data sources require API keys in the future, copy `.env.example` to `.env` and add your keys:
    ```bash
    cp .env.example .env 
    # Edit .env with your keys
    ```
    *Note: The current implementation primarily uses public sources that may not require keys, but this is good practice.* 

## Usage

1.  **Ensure the virtual environment is activated:**
    ```bash
    source venv/bin/activate 
    ```

2.  **Run the Streamlit application:**
    ```bash
    streamlit run src/app.py
    ```

3.  **Open your web browser** to the URL provided by Streamlit (usually `http://localhost:8501`).

4.  **Enter the Target Organization Name** in the sidebar.

5.  **(Optional) Enter known Base Domains** (one per line) to help focus the search.

6.  **Click "Start Scan"**.

7.  View the results in the different tabs and use the "Export Reports" tab to download data.

## Development & Testing

*   **Run tests:**
    ```bash
    pytest
    ```
*   **Code Style:** Adheres to PEP 8 (consider using `black` or `ruff` formatters).

## Disclaimer

This tool is intended for legitimate security auditing and research purposes only, with proper authorization. Unauthorized scanning of networks is illegal and unethical. The developers assume no liability and are not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the MIT License - see the LICENSE file for details.