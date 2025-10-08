[![Build](https://github.com/hackerman-jpeg/macos-audit-suite/actions/workflows/python-lint-test.yml/badge.svg)](https://github.com/YOURORG/YOURREPO/actions/workflows/python-lint-test.yml)
[![Release Bundle](https://github.com/hackerman-jpeg/macos-audit-suite/actions/workflows/release.yml/badge.svg)](https://github.com/YOURORG/YOURREPO/actions/workflows/release.yml)

[![macOS 12 plus](https://img.shields.io/badge/macOS-12%2B-0b72ff?style=for-the-badge&logo=apple&logoColor=white)](#requirements)
[![Python 3.10 plus](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](#requirements)

[![STIG XCCDF](https://img.shields.io/badge/STIG-XCCDF-6c63ff?style=for-the-badge)](#stig-runner)
[![NIST and CMMC](https://img.shields.io/badge/NIST%20800%2053%20%7C%20800%20171%20%7C%20CMMC-Support-ffb300?style=for-the-badge)](#compliance-posture)
[![Llama 3.1](https://img.shields.io/badge/AI-Llama%203.1%208B-8e8dff?style=for-the-badge&logo=meta&logoColor=white)](#ai-behavior)
[![Apple Silicon](https://img.shields.io/badge/Apple%20Silicon-Optimized-bd10e0?style=for-the-badge&logo=apple&logoColor=white)](#requirements)

# MacAudit²
## An on-prem macOS AI audit suite designed for those who need to NIST audit...but offline

This lightweight python script runs fully locally on macOS, no network calls, with an on device LLM for context. It then spits out a  nice HTML report (customizable) and a .txt. The point of this was to create a NIST audit script and create something that others can **build upon and expand** (so please do). This isn't an end all be all...but rather a stepping stone for doing more. 

### What you get
* `ai_audit_agent.py` scans logs and key settings over a time window, then adds inline AI verdicts
* `stig_runner.py` parses a DISA XCCDF macOS STIG and executes checks in a safe way by default
* `report_theme.py` a shared HTML theme, same look for both reports
* Optional, your XCCDF file next to the scripts for the STIG run

---
### Features
- Identical HTML for both tools, single theme and dashboard at the top
- Inline AI analysis near each finding, not a detached summary
- Plain text report and rich HTML, both timestamped to the minute
- Safe by default for STIG checks, with a single switch to allow commands that modify state
- Evidence preserved verbatim for every rule or category

---

### Requirements
- macOS 12 or newer
- Python 3.10 or newer
- Built in tools available on a standard Mac environment, for example log, awk, xmllint, csrutil, spctl
- Ollama for the on device LLM  
  ```bash
  brew install ollama
  brew services start ollama
  ollama pull llama3.1
  ```
**NOTE**: Model weights are not bundled. You pull them locally once with the line above.

---

### Quick start

#### Download the Llama Model
Legally, we can't build Metas Llama model in our code. So I wrote a script to make it easy. Or just get it at [HuggingFace](https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct). But to use the script:
```
curl -fsSL https://raw.githubusercontent.com/hackerman-jpeg/macos-audit-suite/main/install_llama_local.sh -o install_llama_local.sh
chmod +x install_llama_local.sh
./install_llama_local.sh
```

- What this does
  - Detects macOS and CPU
  - Installs Homebrew if missing
  - Installs and starts Ollama (the local LLM runtime)
  - Downloads the Llama 3.1 (8B Instruct) model
  - Verifies the model locally
  - Creates helper scripts in your folder:
    - `test_llm.sh` – Quick test to check the AI
    - `run_audit.sh` – Runs the AI audit agent
    - `run_stig.sh` – Runs the STIG checks

After it finishes
`./test_llm.sh`
should respond with a short “READY” message.
Then you can run:
`./run_audit.sh`
or
`./run_stig.sh`

#### NEXT...Clone, create a virtual environment.
```bash
git clone https://github.com/hackerman-jpeg/macos-audit-suite.git
cd macos-audit-suite
python3 -m venv .venv
source .venv/bin/activate
```
#### Prepare the model once.

``ollama list | grep -q llama3.1 || ollama pull llama3.1``

#### To run the normal audit.
```bash
export OLLAMA_MODEL=llama3.1
export OLLAMA_NUM_CTX=8192
sudo python3 ai_audit_agent.py --stream
```
#### To just run the STIG runner. Place your XCCDF XML in the same folder
```bash
sudo python3 stig_runner.py --stream
```

---

### Menu, `audit_agent`
1. Quick last hour
2. Last 24 hours
3. Last 48 hours
4. Last 7 days
5. Custom range
6. Run STIGs if the runner script is present

---

### Running `STIG_runner`
- Select an XCCDF file
- Run all rules, or choose rules by id list, or filter by keyword in a future menu extension
- Safe mode is the default. To allow non safe commands:
```bash
sudo python3 stig_runner.py --allow-unsafe
```
- Per command timeout, default eight seconds:
```bash
sudo python3 stig_runner.py --timeout 20
```

---

### Outputs
Text report with minute stamp, example
``audit_YYYY-MM-DD_HHMM.txt``
``stig_YYYY-MM-DD_HHMM.txt``
HTML report with the same theme and dashboard for both tools, example
``audit_YYYY-MM-DD_HHMM.html``
``stig_YYYY-MM-DD_HHMM.html``
The tool opens the HTML in your default browser

---

### Dashboard at the top
`Fail`, `Pass`, `Error`, Manual counts, severity counts, and an AI risk index on a zero to one hundred scale

---

### Inside each section
- Commands that were executed, shown exactly as run
- Exit code and raw evidence, standard output and standard error
- AI verdict next to the evidence with a short rationale and tags

---

### AI behavior
- Local only through Ollama on http://127.0.0.1:11434
- Model defaults to Meta Llama 3.1 eight B Instruct
- Deterministic system prompts that ask for strict JSON
- Verdict values
  - Benign likely false positive
  - Risk needs review
  - Fail confirmed
  - Inconclusive

---

### Switching models
Set the variable and ensure the model is present in Ollama
```bash
export OLLAMA_MODEL=qwen2.5:7b-instruct
export OLLAMA_NUM_CTX=8192
```

---

### Compliance posture
The audit agent and the STIG runner support evidence gathering for controls that map to NIST 800-53, NIST 800-171, and CMMC. The STIG runner executes the actual XCCDF checks you provide. For any control that is not testable via command line, the runner marks it manual and preserves the text for review. Use your program specific control mapping to produce the final control by control artifact.

---

### Security posture
- No network calls by the Python scripts other than the local Ollama port
- STIG runner defaults to safe commands that do not change state
- Every command has a timeout to avoid hangs
- Ctrl-C skips the current rule cleanly and continues

---

### Troubleshooting

#### ⛔ Ollama port already in use.

``lsof -iTCP:11434 -sTCP:LISTEN -n -P``

Check the Ollama API.

``curl -s http://127.0.0.1:11434/ | python3 -m json.tool``

#### ⛔ Model not present.

``ollama pull llama3.1``

Stream everything to the console for live debugging.

``sudo python3 ai_audit_agent.py --stream``
``sudo python3 stig_runner.py --stream``

---

### Notes.
- You can tune the context window with OLLAMA_NUM_CTX
- You can disable auto open of the browser by adding ``--no-open``
- You can run both tools without the stream flag if you want a minimal console

