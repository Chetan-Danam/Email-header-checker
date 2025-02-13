# Email Header Analyzer for Phishing Detection

This Python tool analyzes email headers for common phishing indicators. It helps identify potential phishing attempts by examining email header fields, including the "From" address, "Reply-To" field, subject line, and email authentication records (SPF, DKIM, and DMARC).

## Features
- Analyzes the "From" and "Reply-To" fields to check for mismatches (common phishing tactic).
- Detects phishing keywords in the subject line (e.g., "Urgent", "Account Suspended").
- Checks the number of "Received" headers to identify suspicious routing.
- Verifies email authentication records (SPF, DKIM, and DMARC).

## Installation

1. Clone this repository to your local machine:
    ```bash
    git clone https://github.com/yourusername/email-header-analyzer.git
    ```

2. Navigate into the project directory:
    ```bash
    cd email-header-analyzer
    ```

3. Ensure you have Python 3.x installed. This script uses Python's built-in libraries, so no additional dependencies are required.

## Usage

1. Copy your email header (or load it from a file) and paste it into the script.
2. Run the script:
    ```bash
    python email_header_analyzer.py
    ```

3. The tool will analyze the email header and display results, such as:
    - Whether the "From" address looks suspicious.
    - Whether the "Reply-To" field mismatches the "From" field.
    - Whether the subject line contains phishing keywords.
    - Whether SPF, DKIM, and DMARC records are valid.

### Example Output:

