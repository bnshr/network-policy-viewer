# Network Policy Viewer

Tools to retrieve and display all network policies from an OpenShift/Kubernetes cluster in a tabular format showing ingress and egress traffic flows.

## Files in this Directory

- **`network-policy-viewer.py`** - Python script (recommended)
- **`network-policy-viewer.sh`** - Bash script alternative
- **`requirements-network-policy-viewer.txt`** - Python dependencies
- **`README-network-policy-viewer.md`** - Detailed usage guide

## Quick Start

### Python Script (Recommended)

```bash
# Install dependencies
pip install -r requirements-network-policy-viewer.txt

# View all network policies
python3 network-policy-viewer.py

# View policies in a specific namespace
python3 network-policy-viewer.py -n my-namespace

# Export to CSV
python3 network-policy-viewer.py --csv > policies.csv

# Filter by policy type (ingress only)
python3 network-policy-viewer.py --type ingress

# Filter by policy type (egress only) and export to CSV
python3 network-policy-viewer.py --type egress --csv > egress-policies.csv
```

### Bash Script

```bash
# Make executable (if not already)
chmod +x network-policy-viewer.sh

# View all network policies
./network-policy-viewer.sh

# View policies in a specific namespace
./network-policy-viewer.sh -n my-namespace

# Filter by policy type (ingress only)
./network-policy-viewer.sh --type ingress

# Filter by policy type (egress only) and export to CSV
./network-policy-viewer.sh --type egress --csv > egress-policies.csv
```

## Documentation

- **`README-network-policy-viewer.md`** - Detailed usage instructions, examples, and troubleshooting
- **`POD_SELECTOR_EXPLAINED.md`** - Understanding "Pod Selector: All pods" and how pod selectors work
- **`NETWORK_POLICY_VIEWER_IDEAS.md`** - Implementation ideas and advanced features

## Prerequisites

### Python Script
- Python 3.6+
- `oc` or `kubectl` CLI tool
- `tabulate` Python package

### Bash Script
- Bash 4.0+
- `jq` command-line JSON processor
- `oc` or `kubectl` CLI tool
