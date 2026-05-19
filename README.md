 # UZUMAKI

Advanced Reconnaissance & OSINT Framework

UZUMAKI is a lightweight cybersecurity reconnaissance framework designed for automated attack surface mapping, OSINT gathering, DNS intelligence, technology fingerprinting, and HTML/PDF reporting.

## Features

- Subdomain Enumeration
- Email Harvesting
- DNS Reconnaissance
- Technology Fingerprinting
- WHOIS Lookup
- SSL Certificate Analysis
- HTTP Header Collection
- Shodan Integration
- JSON Export
- HTML/PDF Report Generation
- Cyberpunk Styled Reporting

  ## Installation

```bash
git clone https://github.com/shrikrishnah/Uzumaki-Recon-Framework.git

cd uzumaki-recon-framework

pip install -r requirements.txt


---

# TOOL DEPENDENCIES

VERY IMPORTANT.
## External Dependencies

UZUMAKI uses the following external tools:

- Sublist3r
- theHarvester

Clone them inside the project directory:

```bash
git clone https://github.com/aboul3la/Sublist3r.git

git clone https://github.com/laramies/theHarvester.git
#Create a shodan account and paste your API key in the code
**##RUN**
python3 uzumaki.py

UZUMAKI generates:

- HTML Recon Reports
- PDF Reports
- JSON Intelligence Exports
- Raw Recon Data

Reports are saved in the current working directory

