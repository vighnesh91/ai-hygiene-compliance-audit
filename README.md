# AI Hygiene & Compliance Audit Tool

A lightweight, high-performance security tool designed for internal compliance scanning and credential hygiene of local AI deployments. It scans the filesystem for exposed LLM API tokens (OpenAI, Anthropic, Gemini, DeepSeek, etc.) and audits local networks for exposed, unauthenticated inference service endpoints.

## Features

- **Secret & Token Detection:** Scans text files up to an 8,192 character line limit for explicit token patterns and high-entropy strings using Shannon Entropy.
- **Service Endpoint Probing:** Async network mapping across standard AI deployment ports (Ollama, vLLM, Qdrant, Milvus, Gradio, Streamlit).
- **Compliance Validation:** Sends a bounded, malformed fallback probe to `/v1/chat/completions` if a metadata endpoint requires authentication or throws a client error, checking for exposed generation pipelines without reading response bodies.
- **Alert Integrations:** Dispatches structural critical exposure payloads directly to Slack, Microsoft Teams, or Discord webhooks.
- **Self-Contained Execution:** Dynamically installs minimal external dependencies (`httpx`, `rich`) inside the active Python ecosystem at runtime if absent.

## Supported Providers & Ports

### Detected Token Patterns
- OpenAI & OpenAI-compatible Hex Keys (DeepSeek, self-hosted)
- Anthropic, Google Gemini, Hugging Face, Groq, Together AI, Perplexity AI, Cohere, and Mistral AI

### Audited Target Ports
- `11434` (Ollama)
- `8000`, `8080` (vLLM / FastAPI integrations)
- `7860` (Gradio)
- `8501` (Streamlit)
- `6333` (Qdrant)
- `19530` (Milvus)
- `8888` (Jupyter / Generic Notebook services)

## Installation & Requirements

- **Python 3.11+**
- No manual dependency installation required (automatically fetches `httpx` and `rich` on first execution).

```bash
git clone https://github.com
cd ai-hygiene-compliance-audit
chmod +x audit.py
```

## Usage

### Basic Local Scan
Scan the current directory for high-entropy secrets and exposed API tokens:
```bash
python3 audit.py
```

### Complete Network Audit
Audit a single internal service target host or IP for open AI service endpoints:
```bash
python3 audit.py internal-ai-server.local --concurrency 8
```

### Bounded Range Compliance Check
Audit an automated target text file populated with internal addresses and CIDRs, setting an entropy baseline of 4.5 bits:
```bash
python3 audit.py --target-file targets.txt --entropy-threshold 4.5 --report business_compliance_report.json
```

### Real-time Alerts via Webhooks
Configure critical exposure warnings to alert your incident response endpoint:
```bash
export AI_AUDIT_WEBHOOK_URL="https://slack.com..."
python3 audit.py --target-file secure_hosts.txt --notify slack
```

## Security & Privacy Guardrails
1. **No Data Ingestion:** Response bodies from audited target containers are never retrieved or read.
2. **Token Masking:** Discovered secrets are completely redacted (`sk-pro…-4f1b`) before being parsed into report artifacts.
3. **Environment Security:** Webhook endpoint URLs are treated as volatile variables and are omitted from all exported configuration outputs.
