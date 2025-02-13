import re
from email.parser import Parser
from email.header import decode_header

# Helper function to decode the subject header
def decode_subject(subject):
    decoded_parts = decode_header(subject)
    decoded_subject = ''.join([str(part[0], part[1] if part[1] else 'utf-8') for part in decoded_parts])
    return decoded_subject

# Function to analyze the email header
def analyze_email_header(header):
    analysis_results = {}

    # Parse the email header
    parser = Parser()
    email_message = parser.parsestr(header)
    
    # Get the necessary fields from the header
    from_address = email_message['From']
    to_address = email_message['To']
    subject = email_message['Subject']
    received_headers = email_message.get_all('Received', [])
    reply_to = email_message.get('Reply-To', '')
    spf_record = email_message.get('X-SPF', '')
    dkim_record = email_message.get('DKIM-Signature', '')
    dmarc_record = email_message.get('DMARC-Policy', '')

    # Analyzing the 'From' address
    analysis_results['From Address'] = {'address': from_address}
    suspicious_from = re.match(r"[^@]+@([^@]+)", from_address)
    if suspicious_from and suspicious_from.group(1) not in ['gmail.com', 'yahoo.com', 'company.com']:  # Expected domains
        analysis_results['From Address']['status'] = 'Suspicious'
    else:
        analysis_results['From Address']['status'] = 'Legitimate'

    # Analyzing the "Reply-To" field
    analysis_results['Reply-To'] = {'address': reply_to}
    if reply_to and reply_to != from_address:
        analysis_results['Reply-To']['status'] = 'Suspicious (Mismatch with "From" field)'
    else:
        analysis_results['Reply-To']['status'] = 'Matches "From" field'

    # Analyzing the subject line for urgency keywords (phishing red flags)
    decoded_subject = decode_subject(subject)
    analysis_results['Subject'] = {'subject': decoded_subject}
    phishing_keywords = ['urgent', 'suspended', 'immediate action required', 'account', 'verify']
    if any(keyword in decoded_subject.lower() for keyword in phishing_keywords):
        analysis_results['Subject']['status'] = 'Suspicious (Phishing Keywords Found)'
    else:
        analysis_results['Subject']['status'] = 'Normal'

    # Analyzing Received headers (multiple hops may indicate suspicious routing)
    analysis_results['Received Headers'] = {'count': len(received_headers)}
    if len(received_headers) > 3:  # Arbitrary threshold for suspicious hops
        analysis_results['Received Headers']['status'] = 'Suspicious (Multiple hops detected)'
    else:
        analysis_results['Received Headers']['status'] = 'Normal'

    # SPF, DKIM, and DMARC records
    analysis_results['SPF'] = {'record': spf_record, 'status': 'Pass' if spf_record else 'Fail'}
    analysis_results['DKIM'] = {'record': dkim_record, 'status': 'Pass' if dkim_record else 'Fail'}
    analysis_results['DMARC'] = {'record': dmarc_record, 'status': 'Pass' if dmarc_record else 'Fail'}

    return analysis_results


def display_analysis_results(results):
    print("\nEmail Header Analysis Results:")
    for field, details in results.items():
        print(f"\n{field}: {details['status']}")
        print(f"  Address/Record: {details['address' if 'address' in details else 'record']}")
        print(f"  Status: {details['status']}")


# Example usage:
if __name__ == "__main__":
    # Example email header (could be read from a file)
    email_header = """From: example@phishing.com
    To: victim@example.com
    Subject: Urgent: Your account has been suspended!
    Reply-To: no-reply@phishing.com
    X-SPF: Pass
    DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=phishing.com; s=google;
    DMARC-Policy: Reject
    Received: from spamserver.com by mailserver.com (Postfix, from userid 1001)
    """

    # Run the header analysis
    results = analyze_email_header(email_header)
    
    # Display the results
    display_analysis_results(results)
