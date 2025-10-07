#!/usr/bin/env bash
# install_llama_local.sh
# Sets up a local LLM (Llama 3.1 via Ollama) on macOS, starts the service, pulls the model,
# and verifies everything end to end. Safe to rerun.

set -euo pipefail

BOLD="$(tput bold 2>/dev/null || true)"; NORM="$(tput sgr0 2>/dev/null || true)"
say() { printf "%s%s%s\n" "$BOLD" "$*" "$NORM"; }
ok()  { printf "✅  %s\n" "$*"; }
warn(){ printf "⚠️  %s\n" "$*"; }
die() { printf "❌  %s\n" "$*"; exit 1; }

REQUIRED_MODEL="${OLLAMA_MODEL:-llama3.1}"
HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}"
PORT="$(printf "%s" "$HOST" | awk -F: '{print $NF}')"
TEST_PROMPT='Return the string READY only.'

require() {
  command -v "$1" >/dev/null 2>&1 || return 1
}

mac_check() {
  [[ "$(uname -s)" == "Darwin" ]] || die "This script is for macOS."
  ok "macOS detected"
  say "CPU check"
  arch="$(uname -m)"
  ok "Architecture: $arch"
}

ensure_brew() {
  if require brew; then
    ok "Homebrew present"
  else
    say "Installing Homebrew"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || die "Homebrew install failed"
    if [[ -x /opt/homebrew/bin/brew ]]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -x /usr/local/bin/brew ]]; then
      eval "$(/usr/local/bin/brew shellenv)"
    fi
    ok "Homebrew installed"
  fi
}

ensure_ollama() {
  if require ollama; then
    ok "Ollama present: $(ollama --version 2>/dev/null || echo unknown)"
  else
    say "Installing Ollama"
    brew install ollama || die "brew install ollama failed"
    ok "Ollama installed"
  fi
}

start_ollama() {
  say "Starting Ollama service"
  if require brew; then
    brew services start ollama >/dev/null 2>&1 || true
  fi
  # If brew services not used or already running, ensure a server is live
  if ! curl -fsS -m 1 "$HOST" >/dev/null 2>&1; then
    warn "Background service not responding, launching a foreground daemon in background"
    nohup ollama serve >/tmp/ollama_serve.log 2>&1 &
    sleep 1
  fi
  # Wait for readiness
  say "Waiting for API on $HOST"
  for i in {1..30}; do
    if curl -fsS -m 1 "$HOST" >/dev/null 2>&1; then ok "Ollama API is up"; return; fi
    sleep 1
  done
  die "Ollama did not start on $HOST"
}

pull_model() {
  say "Ensuring model: $REQUIRED_MODEL"
  if ollama list 2>/dev/null | awk '{print $1}' | grep -Fxq "$REQUIRED_MODEL"; then
    ok "Model already present: $REQUIRED_MODEL"
  else
    ollama pull "$REQUIRED_MODEL" || die "Model pull failed"
    ok "Model pulled: $REQUIRED_MODEL"
  fi
}

smoke_test() {
  say "Running a tiny generate test"
  out="$(curl -fsS -m 60 -H "Content-Type: application/json" \
    -d "{\"model\":\"$REQUIRED_MODEL\",\"prompt\":\"$TEST_PROMPT\",\"stream\":false}" \
    "$HOST/api/generate" | python - <<'PY'
import sys, json
try:
    print(json.load(sys.stdin).get("response","").strip())
except Exception as e:
    print("ERR:"+str(e))
PY
)"
  if [[ "$out" == "READY" ]]; then
    ok "Model responded correctly"
  else
    warn "Unexpected model response:"
    printf "%s\n" "$out"
  fi
}

drop_env_and_helper() {
  say "Writing helper files"
  cat > .ollama.env <<EOF
# Sourced by helper scripts
export OLLAMA_HOST="$HOST"
export OLLAMA_MODEL="$REQUIRED_MODEL"
export OLLAMA_NUM_CTX="${OLLAMA_NUM_CTX:-8192}"
EOF
  ok "Created .ollama.env"

  cat > test_llm.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -f ".ollama.env" ]]; then source .ollama.env; fi
PROMPT="${1:-Summarize: macOS audit ready.}"
curl -fsS -H "Content-Type: application/json" \
  -d "{\"model\":\"${OLLAMA_MODEL:-llama3.1}\",\"prompt\":\"$PROMPT\",\"stream\":false}" \
  "${OLLAMA_HOST:-http://127.0.0.1:11434}/api/generate" \
  | python - <<'PY'
import sys,json
try:
  j=json.load(sys.stdin); print(j.get("response","").strip())
except Exception as e:
  print("LLM error:", e)
PY
EOF
  chmod +x test_llm.sh
  ok "Created test_llm.sh"

  # Optional runner for your audit scripts if present
  if [[ -f "ai_audit_agent.py" ]]; then
    cat > run_audit.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -f ".ollama.env" ]]; then source .ollama.env; fi
exec python3 ai_audit_agent.py --stream
EOF
    chmod +x run_audit.sh
    ok "Created run_audit.sh"
  fi

  if [[ -f "stig_runner.py" ]]; then
    cat > run_stig.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -f ".ollama.env" ]]; then source .ollama.env; fi
exec sudo -E python3 stig_runner.py --stream
EOF
    chmod +x run_stig.sh
    ok "Created run_stig.sh"
  fi
}

port_conflict_hint() {
  if lsof -iTCP:"${PORT}" -sTCP:LISTEN -n -P >/dev/null 2>&1; then
    ok "Port ${PORT} is listening"
  else
    warn "Port ${PORT} not visible yet, but API replied earlier. If issues persist:"
    printf "  lsof -iTCP:%s -sTCP:LISTEN -n -P\n" "$PORT"
  fi
}

main() {
  mac_check
  ensure_brew
  ensure_ollama
  start_ollama
  pull_model
  smoke_test
  drop_env_and_helper
  port_conflict_hint

  echo
  say "Done"
  echo "Try a quick call:"
  echo "  ./test_llm.sh"
  if [[ -f run_audit.sh ]]; then echo "  ./run_audit.sh"; fi
  if [[ -f run_stig.sh ]]; then echo "  ./run_stig.sh"; fi
}

main "$@"
