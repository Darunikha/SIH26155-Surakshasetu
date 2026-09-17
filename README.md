# SurakshaSetu

### AI-Driven Multi-Vendor Network Security Compliance Auditor

**Smart India Hackathon 2026 — Problem Statement SIH26155**

SurakshaSetu (*"bridge of security"*) ingests a network device configuration — Cisco,
Fortinet, or Palo Alto — and turns it into an auditable, evidence-backed compliance
report: a vendor-neutral model of the device, a deterministic pass/fail against
CIS / NIST 800-53 / ISO 27001 controls, a quantified risk score, a graph of exploitable
attack paths, an optimizer-sequenced remediation plan, tamper-evident provenance on a
real blockchain ledger, and — where a local LLM is available — a plain-language
explanation of what was found and why it matters.

---

## Project resources

| Resource | Link |
|---|---|
| Demo video | [Watch](https://drive.google.com/file/d/1C070-BgAATTnWCAKf00GUV4SnNwmcnC2/view?usp=sharing) |
| Document | [Open](https://docs.google.com/document/d/1pygOHMMGcEjCaPtpBdrTg1wARnpOXrVa/edit?usp=sharing&ouid=105585471477634809410&rtpof=true&sd=true) |
| Technical PPT | [Open](https://docs.google.com/presentation/d/1RwWajljQHObk0cefRGYoqWAsN7SxQCri/edit?usp=sharing&ouid=105585471477634809410&rtpof=true&sd=true) |

## The problem

Enterprises and government networks run a mix of vendor equipment, each with its own
configuration syntax and its own idea of what "secure" means. Auditing that mix today
is manual, slow, and inconsistent — an analyst reads raw CLI output, cross-references
it against a compliance framework by hand, and writes up findings. SurakshaSetu
automates every deterministic step of that pipeline and keeps a human in the loop for
every step that carries real consequence.

## What makes this submission different

Most hackathon security tools generate their headline numbers with an LLM prompt and
hope for the best. SurakshaSetu doesn't. Every score, mapping, and graph in this system
is the output of **auditable, deterministic code** — the AI layer is opt-in, and it is
never load-bearing for correctness:

- **The compliance, risk, attack-path, and remediation-sequencing engines are plain
  Python** — rule evaluation and graph algorithms, not model inference. The same input
  always produces the same output, and a judge can read the source and verify the logic.
- **When the optional local LLM isn't running, the system says so.** Every AI-backed
  endpoint returns an explicit `AI_UNAVAILABLE` rather than a plausible-sounding guess.
  There is no fallback path that quietly fabricates an explanation.
- **The blockchain is real, not a demo prop.** `blockchain/` stands up an actual
  Hyperledger Fabric network (orderer, peer, channel, Go chaincode) — not a hash stored
  in a SQL column labeled "ledger." `tests/test_blockchain_tamper.py` proves tamper
  detection end-to-end: it writes evidence, commits it to the ledger, edits MongoDB
  directly to simulate tampering, and asserts the mismatch is caught against the live
  chain.
- **Every AI-assisted remediation is a suggestion, never an action.** Drafted commands
  are syntax-checked and marked `SIMULATED`; nothing in this system pushes
  configuration to a real device without an explicit human approval step.

## End-to-end pipeline

```
 Upload config          Normalize             Evaluate                Act
┌───────────────┐   ┌────────────────┐   ┌───────────────────┐   ┌──────────────────┐
│ Cisco IOS      │   │ Vendor-neutral │   │ Compliance engine  │   │ ACO remediation   │
│ FortiGate      │──▶│ Security IR    │──▶│ (CIS/NIST/ISO)     │──▶│ sequencing        │
│ Palo Alto      │   │ (parsed model) │   │ Risk scoring       │   │ Blockchain record │
└───────────────┘   └────────────────┘   │ Attack-path graph  │   │ PDF report        │
                                          └─────────┬──────────┘   └──────────────────┘
                                                    │
                                       optional, human-gated
                                                    ▼
                                     ┌───────────────────────────┐
                                     │ Local LLM (Ollama)         │
                                     │ explanation + remediation  │
                                     │ drafts, RAG-grounded       │
                                     │ against an authored        │
                                     │ security-knowledge corpus  │
                                     └───────────────────────────┘
```

## Architecture

```
┌─────────────┐      ┌──────────────────┐      ┌───────────────────────┐
│  Next.js UI │◄────►│  FastAPI backend │◄────►│  MongoDB (evidence)   │
│  (frontend) │      │    (backend)     │      │  Pinecone (RAG, opt.) │
└─────────────┘      └────────┬─────────┘      └───────────────────────┘
                               │
                 ┌─────────────┼──────────────┐
                 ▼             ▼              ▼
          ┌────────────┐ ┌──────────┐  ┌─────────────────┐
          │ Ollama LLM │ │ Fabric   │  │ Compliance/Risk/ │
          │ (optional, │ │ gateway  │  │ Attack-Graph/ACO │
          │  local)    │ │ sidecar  │  │ engines (pure    │
          └────────────┘ │ (Node)   │  │ Python, no AI)   │
                          └────┬─────┘  └──────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Hyperledger Fabric   │
                    │ (orderer, peer,      │
                    │  chaincode, ledger)  │
                    └─────────────────────┘
```

| Component | What it does |
|---|---|
| **backend/** | FastAPI app: auth/RBAC, project & device management, configuration upload → vendor detection → normalization into a Security IR, the compliance/risk/attack-graph/ACO engines, blockchain recording & verification, PDF reporting, the AI service (Ollama) and RAG retrieval (Pinecone), and the agent tool registry. |
| **blockchain/** | A real local Hyperledger Fabric network (one orderer, one peer, one org), Go chaincode (`security-audit-chaincode`), and a Node.js gateway sidecar that exposes it over HTTP to the Python backend. |
| **frontend/** | Next.js 15 (App Router) + TypeScript + Tailwind dashboard. Every page reads live data from the backend — nothing in the UI is mocked. |
| **rag/** | The authored security-knowledge corpus embedded into Pinecone to ground AI explanations and remediation drafts in real source material. |
| **dataset/**, **ml/**, **training/** | A 5,000-row instruction-tuning dataset and a QLoRA fine-tuning pipeline that trains a small model specifically on network/security configuration semantics — see [Fine-tuned security model](#fine-tuned-security-model) below. |
| **tests/**, **frontend/e2e/** | pytest unit + live-integration tests, and a real Playwright end-to-end test that drives the whole stack — register → upload → scan → compliance/risk/attack-graph → ACO → blockchain verify → PDF report — through an actual browser against the live backend and blockchain. |

## Fine-tuned security model

Generic LLMs are fluent but not specialists in network configuration syntax. To close
that gap, this project built and ran a full fine-tuning pipeline rather than only
documenting one:

1. **Dataset** — 5,000 synthetic instruction-tuning examples (`dataset/`) covering
   vendor CLI parsing, risk classification, remediation proposals, cross-vendor
   translation, and ambiguous-input handling, grounded in real sourced reference
   material (NIST SP 800-53 Rev 5 control text, DISA STIG rules, NCIIPC controls,
   CIS/ISO mappings — see `dataset/README.md` for full provenance).
2. **Base model** — Qwen2.5-3B-Instruct, loaded in 4-bit NF4 quantization
   (`bitsandbytes`) to fit a 6GB-class consumer GPU.
3. **QLoRA fine-tuning** — LoRA adapters (rank 16) over all attention and MLP
   projections, gradient checkpointing, 3 epochs over the training split
   (`training/train_qlora.py`).
4. **Result** — training converged cleanly: eval loss fell from **0.137 → 0.074** and
   final held-out **token accuracy reached 96.9%**. The resulting adapter
   (`training/qwen2.5-3b-secconf-adapter/`) is a small, local, domain-specialized
   supplement to the general-purpose Ollama model already wired into the backend.

This keeps the core compliance pipeline fully deterministic and AI-independent, while
demonstrating a real, executed path to a domain-specific model rather than a diagram of
one.

## Prerequisites

- Python 3.12, Node.js 20+
- A MongoDB connection string (the free Atlas tier works — this is the only hard
  requirement to run anything)
- Optional, for the full stack: Docker Desktop (with WSL2 backend on Windows) for the
  blockchain network, and [Ollama](https://ollama.com) for AI explanations/remediation
  (`ollama pull qwen2.5:3b-instruct`)
- Optional: a Pinecone API key for RAG-grounded AI answers (falls back to a local
  keyword lookup against `rag/knowledge/` if omitted)

## Easy setup

The absolute minimum to get the app running, with no explanation — see
[Quick start](#quick-start-5-minutes-judges-start-here) below for what each step does.

```bash
# Terminal 1
cd backend
python -m venv venv && ./venv/Scripts/activate
pip install -r requirements.txt
cp .env.example .env   # set MONGODB_URI
uvicorn app.main:app --port 8000
```

```bash
# Terminal 2
cd frontend
npm install
cp .env.local.example .env.local
npm run dev
```

Open **http://localhost:3000** and register an account. That's it — AI and blockchain
are optional add-ons, not required to use the app.

## Quick start (~5 minutes, judges start here)

This gets the dashboard running with real compliance/risk/attack-graph/ACO/reporting —
everything except AI explanations and blockchain provenance, which are additive layers
(see [Full setup](#full-setup) below to add them). Two terminals, no Docker required.

**Terminal 1 — backend**

```bash
cd backend
python -m venv venv
./venv/Scripts/activate            # Windows; use `source venv/bin/activate` on Linux/Mac
pip install -r requirements.txt
cp .env.example .env               # paste your MongoDB URI into MONGODB_URI
uvicorn app.main:app --port 8000
```

**Terminal 2 — frontend**

```bash
cd frontend
npm install
cp .env.local.example .env.local   # already points at http://localhost:8000, no edit needed
npm run dev
```

Open **http://localhost:3000**, register an account, create a project, and upload one of
the sample configs in `configs/synthetic/` — that alone exercises vendor detection,
normalization, compliance scoring, risk scoring, attack-path derivation, and ACO
remediation sequencing end to end, all deterministic, none of it mocked.

## Full setup

Adds the two optional layers on top of the quick start above.

### AI explanations & remediation (Ollama)

```bash
# Install Ollama from https://ollama.com, then:
ollama pull qwen2.5:3b-instruct
```

Nothing else to configure — `backend/.env`'s `OLLAMA_URL`/`OLLAMA_MODEL` already point at
this by default. Restart the backend if it was already running. Until this is done,
every AI-backed action (finding explanations, remediation drafts, the adaptive-learning
suggestion, the AI assistant) returns an explicit `AI_UNAVAILABLE` — the UI shows
"AI not connected," never a fabricated answer, so there's no silent degraded mode to be
surprised by.

### Blockchain provenance (Hyperledger Fabric)

```bash
cd blockchain/scripts
./blockchain-up.sh      # generates crypto material, brings up orderer+peer,
                         # creates/joins the channel, deploys chaincode,
                         # starts the gateway sidecar on :4001
```

On Windows without a POSIX shell, use `blockchain-up.ps1` instead. Tear down with
`blockchain-down.sh`/`.ps1`; wipe and rebuild from scratch with
`blockchain-reset.sh`/`.ps1`. The first run pulls several Docker images and takes a few
minutes. Without this running, `/api/blockchain/verify` correctly reports the ledger as
unreachable rather than fabricating a verified result — everything else in the app works
normally regardless.

### Running the tests

```bash
cd backend
pytest                          # unit tests only, run without extra setup
pytest -m integration           # also exercises the live MongoDB + Fabric ledger
                                 # (requires blockchain-up.sh to have been run)
```

```bash
cd frontend
npx playwright install chromium   # first time only
npm run test:e2e                  # drives a real browser through the full user
                                   # journey against the live backend and blockchain
```

## Design principles

- **Nothing is fabricated.** The compliance engine is deterministic rule evaluation,
  not an LLM guess. Risk scores follow a documented weighted formula. When the AI
  service can't reach Ollama, every endpoint that would use it returns
  `AI_UNAVAILABLE` explicitly — the UI shows "AI not connected," never a hallucinated
  answer.
- **Human-in-the-loop for anything consequential.** Starting a scan, approving a
  remediation plan, and confirming an adaptive-learning mapping all require an explicit
  authenticated action; AI-drafted remediation commands are syntax-validated and
  require human approval before being marked `SIMULATED` — this prototype never pushes
  configuration to a real device.
- **Real blockchain, not a database with extra steps.** `blockchain/` runs an actual
  Hyperledger Fabric network with real chaincode; `POST /api/blockchain/verify`
  recomputes hashes from MongoDB right now and compares them against what's actually on
  the ledger.
- **Every uploaded configuration is versioned, never overwritten**, and secrets
  (passwords, community strings, private keys) are redacted before anything is sent to
  the AI service.

## Known limitations

- The ACO optimizer, compliance engine, and risk engine cover the control set
  documented in `app/compliance/controls/` — a representative baseline, not the full
  CIS/NIST/ISO catalogs (those run to hundreds/thousands of controls).
- AI remediation commands are syntax-checked against known vendor command prefixes, not
  validated against a full vendor grammar — always review before applying.
- The fine-tuned QLoRA adapter (see above) is trained and evaluated but not yet wired
  into the backend's AI service as the default model — the system currently serves AI
  features through a general-purpose Ollama model; swapping in the adapter is a
  configuration change, not further research.

## Team

Built for Smart India Hackathon 2026, Problem Statement SIH26155.
