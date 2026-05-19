import subprocess
import json
import os
import whois
import shodan
import httpx
import ssl
import socket
import re
import dns.resolver
import webbrowser
from datetime import datetime
from jinja2 import Template
from colorama import Fore, init

init(autoreset=True)

print(Fore.GREEN + """

██╗   ██╗███████╗██╗   ██╗███╗   ███╗ █████╗ ██╗  ██╗██╗
██║   ██║╚══███╔╝██║   ██║████╗ ████║██╔══██╗██║ ██╔╝██║
██║   ██║  ███╔╝ ██║   ██║██╔████╔██║███████║█████╔╝ ██║
██║   ██║ ███╔╝  ██║   ██║██║╚██╔╝██║██╔══██║██╔═██╗ ██║
╚██████╔╝███████╗╚██████╔╝██║ ╚═╝ ██║██║  ██║██║  ██╗██║
 ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝

 Automated Recon & OSINT Framework
 Developed By Shrikrishna Hegde

""")

TARGET = input(Fore.CYAN + "Enter target domain: ").strip()

SHODAN_KEY = "ADD-YOUR-API-KEY"

OUTPUT_DIR = os.path.expanduser(
    f"~/UZUMAKI/recon_{TARGET}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)

results = {
    "target": TARGET,
    "subdomains": [],
    "emails": [],
    "shodan": [],
    "whois": "",
    "tech": [],
    "dns": {},
    "headers": {},
    "status_code": "",
    "title": "",
    "ssl_issuer": ""
}

print(Fore.GREEN + "[✓] Initializing UZUMAKI Engine...")
print(Fore.YELLOW + "[*] Loading Recon Modules...")
print(Fore.YELLOW + "[*] Connecting Intelligence Sources...")
print(Fore.YELLOW + "[*] Preparing Attack Surface Scan...")

print(Fore.CYAN + "\n[*] Running Sublist3r...")

sub_output = f"{OUTPUT_DIR}/subdomains.txt"

sub_cmd = [
    "python3",
    "Sublist3r/sublist3r.py",
    "-d", TARGET,
    "-o", sub_output,
    "-n",
    "-v",
    "-t", "50"
]

sub_result = subprocess.run(
    sub_cmd,
    capture_output=True,
    text=True
)

print(sub_result.stdout)
print(sub_result.stderr)

if os.path.exists(sub_output):
    with open(sub_output) as f:
        results["subdomains"] = [
            line.strip()
            for line in f
            if line.strip()
        ]

print(Fore.GREEN + f"[✓] Found {len(results['subdomains'])} subdomains")

print(Fore.CYAN + "\n[*] Running theHarvester...")

harvest_out = f"{OUTPUT_DIR}/harvest"

harvest_cmd = [
    "python3",
    "theHarvester/theHarvester.py",
    "-d", TARGET,
    "-b", "crtsh,bing,duckduckgo,yahoo",
    "-f", harvest_out,
    "-l", "200"
]

harvest_result = subprocess.run(
    harvest_cmd,
    capture_output=True,
    text=True
)

print(harvest_result.stdout)
print(harvest_result.stderr)

json_file = harvest_out + ".json"

if os.path.exists(json_file):
    with open(json_file) as f:
        data = json.load(f)
        results["emails"] = data.get("emails", [])

print(Fore.GREEN + f"[✓] Found {len(results['emails'])} emails")

print(Fore.CYAN + "\n[*] Querying Shodan...")

try:
    if SHODAN_KEY:
        api = shodan.Shodan(SHODAN_KEY)

        search = api.search(f"hostname:{TARGET}")

        for match in search["matches"][:10]:
            results["shodan"].append({
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "org": match.get("org", "N/A"),
                "banner": match.get("data", "")[:300]
            })

        print(Fore.GREEN + f"[✓] Found {len(results['shodan'])} Shodan results")

except Exception as e:
    print(Fore.RED + f"[!] Shodan Error: {e}")

print(Fore.CYAN + "\n[*] Fetching WHOIS...")

try:
    w = whois.whois(TARGET)
    results["whois"] = str(w)

except Exception as e:
    results["whois"] = str(e)

print(Fore.CYAN + "\n[*] Fingerprinting Technologies...")

headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/122 Safari/537.36"
    )
}

try:
    r = httpx.get(
        f"https://{TARGET}",
        headers=headers,
        timeout=15,
        follow_redirects=True,
        verify=False
    )

    results["status_code"] = r.status_code

    page_headers = dict(r.headers)

    results["headers"] = page_headers

    title = re.search(
        r"<title>(.*?)</title>",
        r.text,
        re.IGNORECASE
    )

    if title:
        results["title"] = title.group(1)

    tech = set()

    body = r.text.lower()

    if "wordpress" in body:
        tech.add("WordPress")

    if "react" in body:
        tech.add("React")

    if "__next" in body:
        tech.add("Next.js")

    if "vue" in body:
        tech.add("Vue.js")

    if "bootstrap" in body:
        tech.add("Bootstrap")

    if "jquery" in body:
        tech.add("jQuery")

    server = page_headers.get("server", "").lower()

    if "nginx" in server:
        tech.add("Nginx")

    if "apache" in server:
        tech.add("Apache")

    if "cloudflare" in server:
        tech.add("Cloudflare")

    if "php" in page_headers.get("x-powered-by", "").lower():
        tech.add("PHP")

    results["tech"] = list(tech) or ["Could not detect"]

except Exception as e:
    results["tech"] = [f"Connection failed: {e}"]

print(Fore.CYAN + "\n[*] Fetching DNS Records...")

records = ["A", "MX", "TXT", "NS"]

for record in records:
    try:
        answers = dns.resolver.resolve(TARGET, record)

        results["dns"][record] = [
            str(answer)
            for answer in answers
        ]

    except:
        results["dns"][record] = []

print(Fore.CYAN + "\n[*] Fetching SSL Info...")

try:
    ctx = ssl.create_default_context()

    with ctx.wrap_socket(
        socket.socket(),
        server_hostname=TARGET
    ) as s:

        s.settimeout(5)
        s.connect((TARGET, 443))

        cert = s.getpeercert()

        results["ssl_issuer"] = cert.get("issuer")

except Exception as e:
    results["ssl_issuer"] = str(e)

with open(f"{OUTPUT_DIR}/results.json", "w") as f:
    json.dump(results, f, indent=4)

print(Fore.CYAN + "\n[*] Generating HTML Report...")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>UZUMAKI Recon Report</title>

<style>

body{
background:#000;
color:#00ff88;
font-family:Consolas,monospace;
padding:2rem;
}

h1{
color:#00ff88;
text-shadow:0 0 10px #00ff88;
}

h2{
color:#ffaa00;
border-bottom:1px solid #333;
padding-bottom:5px;
margin-top:30px;
}

.card{
background:#111;
padding:1rem;
margin:10px 0;
border-left:4px solid #00ff88;
border-radius:8px;
box-shadow:0 0 10px #00ff8844;
}

.tag{
display:inline-block;
padding:5px 10px;
margin:5px;
background:#002b1f;
border:1px solid #00ff88;
border-radius:5px;
}

pre{
white-space:pre-wrap;
color:#ccc;
}

</style>

</head>

<body>

<h1>🔍 UZUMAKI Recon Report: {{ target }}</h1>

<p>Generated: {{ timestamp }}</p>

<h2>🌐 Status Code</h2>
<div class="card">{{ status_code }}</div>

<h2>📄 Page Title</h2>
<div class="card">{{ title }}</div>

<h2>📡 Subdomains ({{ subdomains|length }})</h2>

{% for s in subdomains %}
<div class="card">{{ s }}</div>
{% endfor %}

<h2>📧 Emails ({{ emails|length }})</h2>

{% for e in emails %}
<div class="card">{{ e }}</div>
{% endfor %}

<h2>🛠 Technologies</h2>

{% for t in tech %}
<span class="tag">{{ t }}</span>
{% endfor %}

<h2>🌐 Shodan Results ({{ shodan|length }})</h2>

{% for s in shodan %}

<div class="card">
<b>{{ s.ip }}:{{ s.port }}</b><br>
{{ s.org }}

<pre>{{ s.banner }}</pre>

</div>

{% endfor %}

<h2>📋 DNS Records</h2>

{% for record, values in dns.items() %}

<div class="card">

<b>{{ record }}</b>

<pre>
{% for v in values %}
{{ v }}
{% endfor %}
</pre>

</div>

{% endfor %}

<h2>🔒 SSL Issuer</h2>

<div class="card">
<pre>{{ ssl_issuer }}</pre>
</div>

<h2>📑 Headers</h2>

<div class="card">
<pre>{{ headers }}</pre>
</div>

<h2>📋 WHOIS</h2>

<div class="card">
<pre>{{ whois }}</pre>
</div>

</body>
</html>
"""

tmpl = Template(HTML_TEMPLATE)

html = tmpl.render(
    **results,
    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
)

report_html = f"{OUTPUT_DIR}/report.html"

with open(report_html, "w") as f:
    f.write(html)

try:
    from weasyprint import HTML

    HTML(string=html).write_pdf(
        f"{OUTPUT_DIR}/report.pdf"
    )

    print(Fore.GREEN + f"[✓] PDF saved")

except Exception as e:
    print(Fore.RED + f"[!] PDF Error: {e}")

print(Fore.GREEN + f"\n[✓] HTML Report: {report_html}")
print(Fore.GREEN + f"[✓] Results saved in: {OUTPUT_DIR}")

webbrowser.open(report_html)
