SENTINELA

Web Security Analysis Tool

SENTINELA is a Python-based tool designed to inspect basic web security configurations through HTTP response analysis, with optional Tor network integration.

Requirements

- Python 3
- Termux (Android) or another Python-compatible environment
- Tor service (if you don't use Tor, don't work)

Installation

Clone the repository:

git clone https://github.com/Beliroth/SENTINELA.git

Enter the project directory:

cd SENTINELA

Install the required dependencies:

pip install requests pysocks

If the project uses additional Python libraries, install them according to the requirements file.

Usage

Start SENTINELA:

python sentinela.py

Follow the instructions displayed in the terminal.

When prompted, enter the target website URL.

Example:

https://example.com

Use only websites and servers you own or have explicit authorization to assess.

Tor Integration

SENTINELA supports Tor routing through a local SOCKS5 proxy.

Default proxy configuration:

TOR_PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}

Tor must be running locally before this feature can work.

The SOCKS5 hostname resolution is delegated to Tor through "socks5h".

Tor routing does not guarantee complete anonymity or eliminate all forms of network identification.

Security Checks

SENTINELA checks for the presence of the following HTTP security headers:

Header| Purpose
Content-Security-Policy| Helps mitigate certain XSS attacks
Strict-Transport-Security| Enforces HTTPS in supporting browsers
X-Frame-Options| Helps mitigate clickjacking
X-Content-Type-Options| Prevents MIME-type sniffing
Referrer-Policy| Controls referrer information

Understanding Results

- Detected: The HTTP response contains the checked header.
- Not detected: The checked header was not found.
- HTTP Status: Indicates the HTTP response status returned by the server.

A detected header does not necessarily mean that it is correctly configured or effective.

Limitations

SENTINELA is a basic HTTP security configuration analyzer.

It does not currently perform a comprehensive vulnerability assessment, penetration test, or guarantee the detection of security weaknesses.

Legal Notice

SENTINELA is intended exclusively for educational purposes and authorized security assessments.

Users are responsible for obtaining permission before testing systems they do not own or administer.

See "DISCLAIMER.md" (DISCLAIMER.md) for additional information.

License

See the "LICENSE" (LICENSE) file for licensing terms.
