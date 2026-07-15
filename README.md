# 🦅 SQLi-PREDATOR v4.0

### Advanced SQL Injection Detection Engine

**Multi-Vector • Polymorphic Payload Generation • OOB Detection • Statistical Analysis**

SQLi-PREDATOR is a full-stack web application designed for detecting SQL injection vulnerabilities in **authorized training environments and security labs** such as DVWA, bWAPP, OWASP Juice Shop, Hack The Box, and TryHackMe.

Built using **Next.js 15**, **TypeScript**, and **Tailwind CSS**, the platform combines multiple SQL injection detection methodologies with a modern web interface and detailed reporting capabilities.

---

## ✨ Features

| Feature                       | Description                                                                                                                                                 |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **8 Detection Techniques**    | Error-Based, Boolean Blind, Time-Based Statistical Analysis, UNION Probe, OOB DNS/HTTP, Second-Order, Stacked Query Detection, and Status Anomaly Detection |
| **460+ Base Payloads**        | Polymorphic mutation engine generates virtually unlimited payload variations using encoding, comments, and case transformations                             |
| **7 Injection Vectors**       | GET, POST, Cookies, User-Agent, Referer, X-Forwarded-For, and X-Forwarded-Host                                                                              |
| **Statistical Time Analysis** | Uses multiple samples, z-scores, and p-value confidence scoring for reliable timing attacks                                                                 |
| **OOB Callback Detection**    | Supports Interactsh integration for DNS and HTTP callback monitoring                                                                                        |
| **WAF Bypass Engine**         | Payload mutations designed to evaluate signature-based filtering mechanisms                                                                                 |
| **Dark Mode Interface**       | Professional Tailwind CSS interface with live scan progress updates                                                                                         |
| **Exportable Reports**        | Download complete scan findings in JSON format                                                                                                              |

---

## 🔍 Detection Capabilities

### ⚡ Error-Based Detection

Identifies SQL errors returned by the application and extracts useful database information from error messages.

### 🔍 Boolean-Based Blind Detection

Performs TRUE/FALSE response comparisons to determine injectable parameters without relying on visible errors.

### ⏱️ Time-Based Detection

Uses statistically significant response delays combined with confidence scoring to identify time-based blind SQL injection.

### 🔗 UNION-Based Enumeration

Attempts column enumeration and database fingerprinting using UNION SELECT techniques.

### 🌐 Out-of-Band Detection

Uses DNS and HTTP callbacks to identify vulnerabilities that do not produce direct application responses.

### 🔄 Second-Order Injection Detection

Detects payloads stored by the application that execute during later interactions.

### 📚 Stacked Query Detection

Tests for support of multiple SQL statements in a single request.

### 📊 HTTP Status Analysis

Monitors unexpected changes in response status codes that may indicate successful injection.

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/KushGupta/sqli-predator-web.git
cd sqli-predator-web
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Start the Development Server

```bash
npm run dev
```

The application will be available at:

```text
http://localhost:3000
```

---

## 🐳 Lab Targets

SQLi-PREDATOR is designed exclusively for **authorized environments and intentionally vulnerable applications**.

### DVWA

```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

### OWASP Juice Shop

```bash
docker run --rm -it -p 3000:3000 bkimminich/juice-shop
```

### bWAPP

```bash
docker run --rm -it -p 80:80 raesene/bwapp
```

---

## 🏗️ Project Structure

```text
sqli-predator-web/
├── app/
│   ├── layout.tsx
│   ├── page.tsx
│   ├── globals.css
│   ├── scans/
│   │   ├── page.tsx
│   │   └── [id]/
│   │       └── page.tsx
│   └── api/
│       ├── scan/
│       │   ├── start/route.ts
│       │   └── status/[id]/route.ts
│       └── report/[id]/route.ts
│
├── components/
│   ├── Header.tsx
│   └── ScanForm.tsx
│
├── lib/
│   ├── sqli-engine.ts
│   ├── types.ts
│   └── store.ts
│
├── vercel.json
└── package.json
```

---

## ⚙️ Configuration

### Vercel Function Configuration

For long-running scans, configure Vercel Fluid Compute:

```json
{
  "functions": {
    "app/api/scan/start/route.ts": {
      "maxDuration": 300,
      "fluid": true
    }
  }
}
```

---

## 🌍 Environment Variables

| Variable              | Description                                     | Required |
| --------------------- | ----------------------------------------------- | -------- |
| `NEXT_PUBLIC_APP_URL` | Public deployment URL used in generated reports | No       |

---

## 📈 Reporting Features

Each scan report includes:

* Vulnerability severity assessment
* Injection vector identification
* Payload details
* Response comparisons
* Database fingerprinting results
* Statistical confidence scores
* OOB callback evidence
* Recommended remediation guidance

Reports can be exported as JSON for further analysis or documentation.

---

## 📸 Screenshots

Add screenshots after deployment:

* Home page with scan configuration
* Live scan progress dashboard
* Findings summary view
* Detailed vulnerability report page
* Exported JSON report example

---

## 🤝 Contributing

Contributions are welcome.

1. Fork the repository
2. Create a new feature branch

```bash
git checkout -b feature/amazing-feature
```

3. Commit your changes

```bash
git commit -m "Add amazing feature"
```

4. Push to your branch

```bash
git push origin feature/amazing-feature
```

5. Open a Pull Request

---

## 🔒 Responsible Use

SQLi-PREDATOR is intended solely for:

* Security education
* Training environments
* Capture The Flag platforms
* Authorized penetration testing
* Personal laboratory environments

The project intentionally excludes destructive payloads such as:

* `DROP`
* `DELETE`
* `INSERT`
* `UPDATE`
* `TRUNCATE`

Users are solely responsible for ensuring compliance with all applicable laws and regulations.

---

## ⚠️ Legal Disclaimer

This software is provided strictly for **educational purposes and authorized security testing**.

Unauthorized scanning or testing of systems without explicit permission may violate local, national, or international laws. The authors and contributors assume no liability for misuse or damages resulting from the use of this software.

---

## 📄 License

**Educational Use Only**

Copyright © 2026 Kush Gupta

This project is provided for learning, research, and authorized security assessments only.
