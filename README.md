# Notify-PT 🛡️

**🏆 1st Place — BU Cyber Fortress Challenge**

An AI-based cybersecurity browser extension that performs real-time risk analysis of web pages to detect and prevent phishing attempts before users submit their credentials.

## Overview

Notify-PT analyzes web pages as users browse, evaluating structural signals, URL anomalies, and known phishing-related patterns to flag suspicious sites in real time. When a page is identified as high-risk — particularly right before a user is about to submit a login form — the extension issues a pre-emptive warning, giving users a chance to stop and verify the site before their credentials are compromised.

## Features

- **Real-time page analysis** — evaluates web pages as they load, without requiring manual scans
- **URL anomaly detection** — flags suspicious domain patterns, typosquatting, and other URL-based red flags
- **Structural signal analysis** — inspects page structure for common phishing page characteristics
- **Pre-emptive credential warnings** — alerts users before they submit sensitive information on a flagged page
- **Lightweight, browser-native experience** — built directly on Chrome Extension APIs with no heavy external dependencies

## Tech Stack

- JavaScript
- Chrome Extension APIs (Manifest V3)

## How It Works

1. The extension monitors pages as they load in the browser.
2. It evaluates a combination of structural and URL-based signals to calculate a risk score for the page.
3. If a page crosses the risk threshold, Notify-PT displays a warning to the user.
4. If the user attempts to submit a form (e.g., a login page) on a flagged site, an additional pre-emptive alert is triggered before submission goes through.

## Installation (Developer Mode)

1. Clone this repository:
```bash
   git clone https://github.com/amsaibah/Notify-PT.git
```
2. Open Chrome and go to `chrome://extensions/`
3. Enable **Developer mode** (toggle in the top-right corner)
4. Click **Load unpacked** and select the cloned project folder
5. The extension icon should now appear in your browser toolbar

## Team

This project was built as part of the **BU Cyber Fortress Challenge**, where it placed 1st.

- Fatematus Shaheba
- Worakamon Srireangmas
- Areeya Buranthai
- Phatchara Thaiyanant

## License

This project was built for educational and competition purposes.
