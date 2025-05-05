# Security Assessment Tool

A specialized security assessment tool that performs passive domain analysis focused on header-based fingerprinting and DNS configuration analysis, generating professional HTML/PDF reports.

## Overview

This tool is designed to help security professionals and IT administrators perform monthly security assessments on domains for client websites. It produces comprehensive, professional-looking reports that highlight security issues and provide actionable recommendations.

### Key Features

- **Passive, Non-Intrusive Scanning**: Analyzes domains without active probing or testing
- **DNS Configuration Analysis**: 
  - SPF, DKIM, DMARC record validation
  - DNSSEC implementation checking
  - Name server configuration assessment
- **Header-Based Fingerprinting**:
  - Server technology identification
  - Security header evaluation
  - SSL/TLS certificate analysis
  - Cookie security assessment
- **Professional Reporting**:
  - Detailed HTML reports with severity-based findings
  - PDF report generation
  - Executive summary and remediation recommendations

## Installation

### Prerequisites

- Python 3.9 or higher
- Pip package manager

### Setup

1. Clone this repository or download the source code
2. Create a virtual environment (recommended)
3. Install the required dependencies

```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements-security-assessment.txt
```

### Template Setup

The tool requires a template directory for generating reports:

```bash
# Create a templates directory
mkdir templates

# Copy the report template
cp report_template.html templates/
```

## Usage

### Basic Usage

Run the tool on a list of domains:

```bash
python security_assessment.py domains.csv --client "Client Name" --output ./reports
```

By default, this will:
- Read domains from the specified CSV file
- Run a security assessment on each domain
- Generate HTML and PDF reports in the specified output directory

### Input Formats

The tool accepts two main input formats:

1. **CSV file** with domains in a column (preferably named "domain", "title", or "url")
2. **Text file** with one domain per line

### Command Line Options

```bash
python security_assessment.py [input_file] [options]

Options:
  --output DIR       Output directory for reports (default: ./output)
  --client NAME      Client name for the report (default: "Client")
  --workers N        Maximum number of concurrent workers (default: 1)
  --delay N          Delay between requests in seconds (default: 2)
  --verbose          Enable verbose logging
```

### Example

```bash
python security_assessment.py client_domains.csv --client "Acme Corporation" --output ./reports/acme --workers 2 --delay 3
```

## Output

The tool generates the following outputs in the specified directory:

1. **HTML Report** - Detailed interactive report with all findings
2. **PDF Report** - Printable version of the same report
3. **Logs** - Detailed logs of the assessment process in `security_assessment.log`

## Understanding the Reports

### Security Finding Severity Levels

- **Critical**: Immediate security threats requiring urgent attention
- **High**: Significant security issues that should be addressed quickly
- **Medium**: Important security concerns to fix in the near term
- **Low**: Minor security issues that should be addressed when convenient
- **Info**: Informational findings that may warrant attention

### Report Sections

1. **Executive Summary**: Overview of findings with metrics
2. **Detailed Findings by Domain**: Domain-specific analysis and issues
3. **Remediation Recommendations**: Specific guidance to address identified issues
4. **Methodology**: Explanation of assessment techniques

## Use Cases

This tool is particularly valuable for:

1. **Monthly Client Security Reviews**: Regular security posture assessments
2. **Security Compliance Checks**: Verifying basic security controls are in place
3. **New Client Onboarding**: Initial security assessment of client domains
4. **Pre-Acquisition Due Diligence**: Basic security assessment of acquisition targets
5. **Post-Implementation Verification**: Confirming security controls were properly implemented

## Limitations

- This is a passive assessment tool and does not perform active security testing
- It focuses on header-based and DNS configuration issues, not application-level vulnerabilities
- The tool respects rate limits and may take time when scanning multiple domains

## Security Considerations

When using this tool, please keep in mind:

- Always get permission before scanning domains
- Keep reports confidential as they contain security information
- Store API keys and credentials securely
- Use reasonable delays between requests to avoid tripping security systems

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

This tool uses several open-source Python libraries:
- requests
- dnspython
- pandas
- python-whois
- cryptography
- ipwhois
- jinja2
- weasyprint

## Contact

For questions or support, please contact cyber@cyberpools.org
