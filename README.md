🦅 SQLi-PREDATOR v4.0
Advanced SQL Injection Detection Engine — Multi-Vector, Polymorphic, OOB & Statistical Analysis



A full-stack web application for detecting SQL injection vulnerabilities in authorized lab targets (DVWA, bWAPP, Juice Shop, etc.). Built with Next.js 15, TypeScript, and Tailwind CSS.

✨ Features


Feature	Description
8 Detection Methods	Error-Based, Boolean Blind, Time-Based (Statistical), UNION Probe, OOB DNS/HTTP, Second-Order, Stacked Query, Status Anomaly
460+ Base Payloads	Polymorphic mutation engine generates infinite variants — comment injection, hex encoding, case mutation, URL encoding
7 Injection Vectors	GET, POST, Cookies, User-Agent, Referer, X-Forwarded-For, X-Forwarded-Host
Statistical Time Analysis	Multiple samples, z-score, p-value confidence scoring
OOB Callback Detection	Interactsh integration for DNS/HTTP out-of-band detection
WAF Bypass Engine	Polymorphic transformations to evade signature-based filters
Dark-Mode UI	Professional Tailwind CSS design — shareable scan results with live progress
Exportable Reports	JSON download with full detail on every finding
🚀 Quick Start
1. Deploy to Vercel (one click)
Deploy with Vercel

Or manually:

bash



git clone https://github.com/KushGupta/sqli-predator-web.git
cd sqli-predator-web
npm install
npm run dev
2. Run against a lab target
bash



# DVWA
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# OWASP Juice Shop
docker run --rm -it -p 3000:3000 bkimminich/juice-shop

# bWAPP
docker run --rm -it -p 80:80 raesene/bwapp
3. Open the web UI



http://localhost:3000
Enter your target URL, configure options, and start scanning.

🧪 What It Detects



⚡ ERROR-BASED     ── Triggers DB errors, extracts info via error messages
🔍 BOOLEAN-BASED   ── Compares TRUE/FALSE responses, blind extraction
⏱️ TIME-BASED      ── Statistical delay analysis with z-score/p-value
🔗 UNION PROBE     ── Column enumeration via UNION SELECT NULL
🌐 OOB DNS/HTTP    ── Out-of-band callback detection
🔄 SECOND-ORDER    ── Stored injection that triggers on subsequent requests
📚 STACKED QUERY   ── Multiple statement execution
📊 STATUS ANOMALY  ── HTTP status code differential analysis
🏗️ Project Structure



sqli-predator-web/
├── app/
│   ├── layout.tsx            # Root layout with header/nav
│   ├── page.tsx              # Home — scan form + hero
│   ├── globals.css           # Tailwind + custom styles
│   ├── scans/
│   │   ├── page.tsx          # Scan history
│   │   └── [id]/
│   │       └── page.tsx      # Scan detail + findings
│   └── api/
│       ├── scan/
│       │   ├── start/route.ts         # POST — start scan
│       │   └── status/[id]/route.ts   # GET — poll progress
│       └── report/[id]/route.ts       # GET — full results
├── components/
│   ├── Header.tsx            # Navigation bar
│   └── ScanForm.tsx          # Scan configuration form
├── lib/
│   ├── sqli-engine.ts        # Core detection engine (TypeScript)
│   ├── types.ts              # TypeScript type definitions
│   └── store.ts              # In-memory scan store
├── vercel.json               # Function timeout config
└── package.json
📋 Configuration
Vercel Function Timeout
The scan API supports up to 5 minutes (Hobby) or 30 minutes (Pro) via Fluid Compute:

json



{
  "functions": {
    "app/api/scan/start/route.ts": {
      "maxDuration": 300,
      "fluid": true
    }
  }
}
Environment Variables


Variable	Description	Required
NEXT_PUBLIC_APP_URL	Public URL of your deployment (for links in reports)	No
🔒 Scope & Compliance
Authorized use only — tool displays a warning before every scan
Lab targets only — designed for DVWA, bWAPP, Juice Shop, HackTheBox, TryHackMe
No destructive payloads — detection only (DROP/INSERT/UPDATE explicitly excluded)
Rate limiting — configurable delay between requests to avoid overwhelming targets
⚠️ Unauthorized scanning of production systems is illegal. You are responsible for complying with all applicable laws.

📸 Screenshots
(Add screenshots here after deployment)

Home page — Scan form with all configuration options
Live scan — Progress bar with phase descriptions
Results — Severity summary cards + per-finding detail views
Finding detail — Payload used, DB type, error signatures, AI explanation, remediation steps
🤝 Contributing
Fork the repository
Create a feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request
📝 License
Educational Use Only.

This software is provided for authorized security testing and educational purposes. Users are responsible for compliance with all applicable laws. Unauthorized use against production systems or third-party applications is illegal.

