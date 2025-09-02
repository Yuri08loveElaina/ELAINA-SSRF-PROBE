<div align="center">
  <a href="https://github.com/yuri08loveelaina">
    <img src="https://img.shields.io/badge/Maintained%20by-yuri08loveelaina-6a5acd?style=for-the-badge&logo=github" alt="Maintained by yuri08loveelaina">
  </a>
  <br>
  <br>
  <img src="https://pin.it/2RsHXYt8p" alt="Elaina-SSRF-Probe Banner" width="800">
  <h1>Elaina-SSRF-Probe</h1>
  <p><i>An Advanced, Multi-Dimensional Framework for SSRF Vulnerability Discovery and Exploitation</i></p>
  
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=FFD43B)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-red.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg?style=for-the-badge&logo=codefactor&logoColor=white)](https://github.com/psf/black)
[![Last Commit](https://img.shields.io/github/last-commit/yuri08loveelaina/SSRF-Probe?style=for-the-badge&logo=git&logoColor=white)](https://github.com/yuri08loveelaina/SSRF-Probe/commits/main)
[![Issues](https://img.shields.io/github/issues/yuri08loveelaina/Elaina-SSRF-Probe?style=for-the-badge&logo=github)](https://github.com/yuri08loveelaina/SSRF-Probe/issues)
[![Forks](https://img.shields.io/github/forks/yuri08loveelaina/Elaina-SSRF-Probe?style=for-the-badge&logo=github)](https://github.com/yuri08loveelaina/SSRF-Probe/network/members)
[![Stars](https://img.shields.io/github/stars/yuri08loveelaina/Elaina-SSRF-Probe?style=for-the-badge&logo=github)](https://github.com/yuri08loveelaina/SSRF-Probe/stargazers)

<h4>
  <a href="#-key-features">Features</a> |
  <a href="#-installation">Installation</a> |
  <a href="#️-usage">Usage</a> |
  <a href="#-technical-deep-dive">Deep Dive</a> |
  <a href="#-disclaimer--ethical-use">Disclaimer</a>
</h4>
</div>

---

## 📜 Abstract

Elaina-SSRF-Probe is not merely a script; it is a sophisticated framework engineered for the systematic identification, analysis, and validation of Server-Side Request Forgery (SSRF) vulnerabilities. Moving beyond simple payload injection, SSRF-Probe employs a synergistic blend of traditional security testing, advanced machine learning for intelligent response analysis, and a comprehensive arsenal of Web Application Firewall (WAF) bypass techniques. The framework is designed to emulate a human expert's thought process, combining rapid discovery with deep, contextual analysis to uncover even the most subtly concealed SSRF flaws in modern web applications and cloud environments.

---

## 🚀 Key Features

### 🔍 Comprehensive Payload Arsenal
- **Cloud Metadata Targets**: Pre-configured payloads for AWS (`169.254.169.254`), GCP (`metadata.google.internal`), Azure (`100.100.100.200`), and AliCloud.
- **Internal Network Services**: Probes for common internal services (Redis, Elasticsearch, databases, etc.).
- **Local File Access**: `file://` protocol payloads for potential Local File Inclusion (LFI) via SSRF.
- **IPv6 & Obfuscation**: Support for IPv6 addresses and various IP format obfuscations (decimal, octal, hexadecimal).

### 🛡️ Advanced WAF Evasion
- **Multi-Layered Bypass**: Over 20 distinct obfuscation techniques, including URL encoding, null byte injection, comment insertion, and header manipulation.
- **Intelligent Profiling**: Automatically profiles target WAFs (Cloudflare, Akamai, ModSecurity) and selects the most effective bypass strategies.
- **Traffic Shaping**: Implements human-like request patterns, random delays, and User-Agent rotation to evade behavioral detection.

### 🧠 Intelligent Analysis Engine
- **Machine Learning Integration**: Utilizes an ensemble of models (Naive Bayes, Random Forest, MLP, SVM, etc.) to analyze server responses, significantly reducing false positives.
- **Behavioral Analysis**: Establishes baseline response metrics (time, size) and flags anomalies that might indicate a successful SSRF, even without explicit fingerprints.
- **Contextual Awareness**: Employs a headless browser (via Playwright) for deep contextual analysis, understanding application flow to identify high-value input vectors.

### 🌐 Blind SSRF Detection
- **Integrated Callback Servers**: Features built-in DNS and HTTP servers to reliably detect out-of-band (blind) SSRF vulnerabilities.
- **Unique Identifiers**: Generates unique, non-colliding callback URLs for each test, ensuring accurate correlation.

### 🎯 Reinforcement Learning (Optional)
- **Adaptive Agent**: An optional Proximal Policy Optimization (PPO) agent can be trained to learn the optimal sequence of payloads and bypass techniques for a specific target.
- **Fine-Tuning**: The agent can be fine-tuned for specific environments, improving its success rate over time.

### 📈 Professional Reporting & Integration
- **Interactive HTML Reports**: Generates visually rich, interactive reports with charts, graphs, and sortable tables using Plotly and Jinja2.
- **Multi-Format Export**: Supports exporting results to JSON, CSV, XML, and plain text for seamless integration into various workflows.
- **Platform Integration**: Native support for pushing findings to JIRA, DefectDojo, and sending notifications to Slack.

---

## 📋 Table of Contents

- [📜 Abstract](#-abstract)
- [🚀 Key Features](#-key-features)
- [📋 Table of Contents](#-table-of-contents)
- [🎯 Installation](#-installation)
- [⚙️ Configuration](#️-configuration)
- [🛠️ Usage](#️-usage)
  - [Basic Scanning](#basic-scanning)
  - [Advanced Scanning](#advanced-scanning)
  - [Blind SSRF Detection](#blind-ssrf-detection)
  - [Exporting and Reporting](#exporting-and-reporting)
- [📊 Reporting](#-reporting)
- [🧠 Technical Deep Dive](#-technical-deep-dive)
  - [Payload Management & WAF Bypass](#payload-management--waf-bypass)
  - [The Machine Learning Pipeline](#the-machine-learning-pipeline)
  - [Reinforcement Learning Agent](#reinforcement-learning-agent)
- [📝 Payload Customization](#-payload-customization)
- [⚠️ Disclaimer & Ethical Use](#️-disclaimer--ethical-use)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🙏 Acknowledgements](#-acknowledgements)

---

## 🎯 Installation

SSRF-Probe is developed for Python 3.8+ and leverages several powerful libraries. It is highly recommended to operate within a virtual environment to ensure dependency isolation.

# 1. Clone the repository
```
git clone https://github.com/yuri08loveelaina/Elaina-SSRF-Probe.git
cd Elaina-SSRF-Probe
```
# 2. Create and activate a virtual environment
```
python -m venv venv
source venv/bin/activate  
```
# On Windows: 
```
venv\Scripts\activate
```

# 3. Install the required dependencies
```
pip install -r requirements.txt
```
# Optional: For Reinforcement Learning features
```
pip install "stable-baselines3[extra]" torch torchvision torchaudio
```
- Some features, like the headless browser for contextual analysis, may require additional system-level dependencies (e.g., Playwright browsers). Refer to the Playwright documentation for installation instructions.

⚙️ Configuration
Elaina-SSRF-Probe offers flexible configuration through command-line arguments, JSON configuration files, and environment variables.
Configuration File `config.json`
A JSON configuration file allows for complex scan profiles and custom payload definitions.
```
{
  "scan_settings": {
    "default_timeout": 15,
    "threads": 5,
    "rate_limit": 10
  },
  "evasion": {
    "user_agents": [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ..."
    ],
    "random_delay_base": 1.0,
    "random_delay_std_dev": 0.5
  },
  "payloads": {
    "custom_ssrf_payloads": [
      "http://internal.vault.company.com/secrets",
      "gopher://localhost:3306/_SELECT%20*%20FROM%20users"
    ],
    "custom_waf_bypasses": [
      "add_random_param",
      "dangling_markup"
    ]
  },
  "integrations": {
    "jira": {
      "server": "https://your-company.atlassian.net",
      "username": "security_user",
      "api_token": "${JIRA_API_TOKEN}",
      "project_key": "VULN",
      "issue_type": "Bug"
    },
    "slack": {
      "webhook_url": "${SLACK_WEBHOOK_URL}"
    }
  }
}
```

Environment Variables
For sensitive data like API keys, it's recommended to use environment variables.
```
export JIRA_API_TOKEN="your_jira_api_token_here"
export SLACK_WEBHOOK_URL="your_slack_webhook_url_here"
```

🛠️ Usage
- The primary entry point is elaina.py. The scan command initiates the vulnerability assessment process.
- Basic Scanning
- Perform a standard scan against a target URL. This is the most common use case.
```
python elaina.py scan -u https://app.example.com/user/profile
```

***What happens:***
- 1.The target URL is fetched and parsed for HTML forms and URL parameters.
- 2.Each identified parameter is tested against the comprehensive built-in payload list.
- 3.WAF bypass techniques are systematically applied.
- 4.Responses are analyzed using behavioral heuristics and the ML model.
- 5.Findings are printed to the console in a structured format.
### Advanced Scanning 
- Enable more powerful, time-intensive features for a deeper assessment.

- # Use Reinforcement Learning to optimize the attack sequence
```
python elaina.py scan -u https://secure-app.example.com/api --rl
```
- # Perform a deep contextual crawl to understand the application
```
python elaina.py scan -u https://portal.example.com --contextual-mode deep --force-recrawl
```
- # Use aggressive evasion techniques
```
python elaina.py scan -u https://waf-protected.example.com --evasion-mode aggressive
```
- Blind SSRF Detection
- Focus specifically on identifying blind SSRF vulnerabilities using the out-of-band method.

- # The framework automatically starts callback servers for this
```
python elaina.py scan -u https://api.example.com/forward?url=
```
- Exporting and Reporting
- Save your findings in a professional format for reporting and integration.
- # Generate an interactive HTML report and a CSV for data analysis
```
python elaina.py scan -u https://example.com --export html --export csv
```
# Push findings to JIRA and send a summary to Slack
```
python elaina.py scan -u https://example.com --integration config.json
```
- Full Command-Line Interface
```
usage: elaina.py scan [-h] -u URL [--timeout TIMEOUT] [--threads THREADS]
                   [--rate RATE] [--export {json,csv,xml,txt,html}]
                   [--payloads PAYLOADS] [--integration INTEGRATION]
                   [--rl] [--contextual-mode {fast,deep}]
                   [--force-recrawl] [--evasion-mode {basic,aggressive}]
options:
  -h, --help            show this help message and exit
  -u URL, --url URL      The target URL to scan for SSRF vulnerabilities.
  --timeout TIMEOUT      Request timeout in seconds. (default: 15)
  --threads THREADS      Number of concurrent threads for testing. (default: 3)
  --rate RATE            Maximum requests per second. (default: 5)
  --export {json,csv,xml,txt,html}
                        Export results format. Can be specified multiple times.
  --payloads PAYLOADS   Path to a custom JSON file defining payloads and bypasses.
  --integration INTEGRATION
                        Path to a JSON configuration file for platform integrations.
  --rl                  Enable the Reinforcement Learning agent for attack optimization.
  --contextual-mode {fast,deep}
                        Set the contextual analysis mode. 'fast' uses static analysis,
                        'deep' uses a headless browser. (default: fast)
  --force-recrawl       Force a re-crawl of the target, ignoring any cached data.
  --evasion-mode {basic,aggressive}
                        Set the evasion and anti-detection strategy. 'aggressive' enables
                        more advanced techniques. (default: basic)
```

### 📊 Reporting
- The true power of SSRF-Probe lies in its ability to communicate findings effectively. The interactive HTML report is a cornerstone of this capability.
Interactive HTML Report

<p align="center">
<img src="https://pin.it/2RsHXYt8p" alt="banner" width="800">
</p>

## The report provides:
- Executive Dashboard: High-level metrics including total vulnerabilities, confidence distribution, and detected OS.
- Detailed Findings Table: A sortable, filterable table listing each vulnerability with its URL, parameter, payload, and confidence score.
- Visual Analytics: Interactive charts (using Plotly) showing vulnerability distribution by endpoint, payload type, and detected operating system.
- Evidence & PoC: For each finding, the report provides clear evidence snippets from the server response and a reproducible curl command for validation.
- Risk Assessment: Each vulnerability is assigned a risk level (Critical, High, Medium, Low) based on the type of data accessed and exploitation potential.
## 🧠 Technical Deep Dive
- Payload Management & WAF Bypass
- The PayloadManager class is the heart of the attack vector generation. It doesn't just store a list of payloads; it manages a dynamic ecosystem of attack techniques.
- Core Payloads: A comprehensive list targeting known-sensitive resources.
- Bypass Techniques: A collection of lambda functions, each representing a unique obfuscation method. For example:
- url_encode: Standard URL encoding.
- add_null_byte: Appends a %00 to terminate strings prematurely.
- ipv6_bypass: Converts IPv4 addresses to their IPv6 equivalent (::ffff:169.254.169.254).
- override_headers: Attempts to inject headers like X-Forwarded-Host.
- Dynamic Generation: The generate_waf_bypass_payloads method applies all relevant bypass techniques to a base payload, creating a large set of variations to test against a WAF.
- # The Machine Learning Pipeline
- The framework's intelligence comes from its ML pipeline, orchestrated by the MLModelManager.
- Vectorization: The TfidfVectorizer converts raw response text into a matrix of TF-IDF features.
- Label Encoding: Categorical labels (e.g., 'normal', 'ssrf', 'error') are converted into numerical form.
- Model Ensemble: Multiple scikit-learn models are trained on a labeled dataset of normal, SSRF, and error responses. This ensemble approach provides robustness.
- Prediction: When a new response is received, it's transformed by the same vectorizer and fed to all trained models. The probabilities from each model are -- - - averaged to produce a final confidence score for each class.
- Persistence: Trained models, vectorizers, and encoders are serialized using pickle and can be saved/loaded, allowing the framework to learn from new data over time.
- # Reinforcement Learning Agent
- For advanced users and hardened targets, the RLAgent provides a way to optimize the attack process.
- Environment (RLEnvironment): Models the SSRF problem as a Markov Decision Process.
- State Space (observation_space): A 10-dimensional vector representing features of the last response (status code, time, size, content indicators).
- Action Space (action_space): A discrete space representing the choice of a specific payload and bypass technique combination.
- Reward Function: A carefully crafted function that rewards actions leading to high-confidence SSRF discoveries (e.g., finding cloud metadata) and penalizes - # failures or WAF blocks.
- Agent (PPO): Uses the Proximal Policy Optimization algorithm from stable-baselines3. It learns a policy that maps states (observations) to actions (payload choices) to maximize the cumulative reward.
- Training: The agent can be trained from scratch or, more effectively, fine-tuned from a pre-trained base model on a specific target to adapt to its unique defenses.
### 📝 Payload Customization

While SSRF-Probe comes with a comprehensive set of payloads, you can easily extend it.
Create a custom JSON file (e.g., my_payloads.json):

```
{
  "ssrf_payloads": [
    "http://internal-dashboard.company.com/admin",
    "https://metadata.internal.company.com/v1/instance"
  ],
  "waf_bypass_techniques": [
    "custom_technique_1",
    "custom_technique_2"
  ]
}
```

Then, reference it during the scan:
```
python elaina.py scan -u https://target.com --payloads my_payloads.json
```
- Note: For custom WAF bypass techniques, you must also implement the corresponding lambda function within the PayloadManager class in the source code.
### ⚠️ Disclaimer & Ethical Use
Elaina-SSRF-Probe is a powerful security tool intended for educational purposes, research, and authorized security testing only. Misuse of this tool to attack systems without explicit permission is illegal and unethical.
By using this software, you agree to the following terms:
Authorization: You will only use SSRF-Probe on systems for which you have obtained explicit, written permission.
Responsibility: You are solely responsible for any damage caused by the misuse of this tool. The developers and contributors of SSRF-Probe assume no liability.
Compliance: You will comply with all applicable local, state, national, and international laws and regulations.
This tool is provided "as is" without warranty of any kind. The entire risk as to the quality and performance of the program is with you.
### 🤝 Contributing
Contributions to Elaina-SSRF-Probe are welcome! Whether it's a new feature, a bug fix, or improved documentation, your help is appreciated.
Guidelines
Fork the Repository: Create your own fork of the project on GitHub.
Create a Feature Branch: git checkout -b feature/amazing-new-feature
Follow Code Style: Please ensure your code adheres to the PEP 8 standard. The project uses black for formatting.
Write Tests: If you are adding new functionality, please include appropriate tests.
Commit Changes: git commit -m 'Add some amazing feature'
Push to Branch: git push origin feature/amazing-new-feature
Open a Pull Request: Submit a pull request to the main branch of the original repository.
Please read our Contributing Guidelines for more details.
### 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
### 🙏 Acknowledgements
Elaina-SSRF-Probe stands on the shoulders of giants. I would like to express my gratitude to:
The open-source community for the incredible libraries that make this project possible, including requests, scikit-learn, stable-baselines3, plotly, and many more.
The security research community for their continuous work in identifying and documenting SSRF vulnerabilities and bypass techniques.


<div align="center">
<p>Made with ❤️ by <a href="https://github.com/yuri08loveelaina">yuri08loveelaina</a></p>
</div>
