# Network Policy Viewer

Tools to retrieve and display all network policies from an OpenShift/Kubernetes cluster in a tabular format showing ingress and egress traffic flows.

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

# Export to JSON
python3 network-policy-viewer.py --json > policies.json

# Use kubectl instead of oc
python3 network-policy-viewer.py --kubectl
```

### Bash Script

```bash
# Make executable (if not already)
chmod +x network-policy-viewer.sh

# View all network policies
./network-policy-viewer.sh

# View policies in a specific namespace
./network-policy-viewer.sh -n my-namespace

# Export to CSV
./network-policy-viewer.sh --csv > policies.csv

# Export to JSON
./network-policy-viewer.sh --json > policies.json

# Use kubectl instead of oc
./network-policy-viewer.sh --kubectl
```

## Prerequisites

### Python Script
- Python 3.6+
- `oc` or `kubectl` CLI tool
- `tabulate` Python package

### Bash Script
- Bash 4.0+
- `jq` command-line JSON processor
- `oc` or `kubectl` CLI tool

## Output Format

The tools display network policies in a table with the following columns:

1. **Namespace** - The namespace where the policy is applied
2. **Policy Name** - The name of the network policy
3. **Pod Selector** - Labels that identify which pods the policy applies to
4. **Types** - Whether the policy controls Ingress, Egress, or both
5. **Ingress Rules** - What traffic is allowed INTO the selected pods
6. **Egress Rules** - What traffic is allowed OUT OF the selected pods

### Example Output

```
==========================================================================================================
NETWORK POLICIES OVERVIEW
==========================================================================================================

Namespace          Policy Name                    Pod Selector              Types          Ingress Rules                                    Egress Rules
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
default            allow-all                      All pods                  Ingress, Egress  • From: All sources | Ports: TCP:443, TCP:80     • To: All destinations | Ports: TCP:443
production         web-app-policy                 app=web                   Ingress         • From: Pods: app=nginx | Ports: TCP:8080         N/A
production         db-policy                      app=database              Egress          N/A                                              • To: IPs: 10.0.0.0/8 | Ports: TCP:5432
```

## Understanding the Output

### Ingress Rules
Shows what traffic is **allowed INTO** the pods selected by the policy:
- **From:** Sources can be:
  - Pods matching specific labels
  - Namespaces matching specific labels
  - IP addresses/CIDR blocks
- **Ports:** Allowed ports and protocols (e.g., TCP:443, UDP:53)

### Egress Rules
Shows what traffic is **allowed OUT OF** the pods selected by the policy:
- **To:** Destinations can be:
  - Pods matching specific labels
  - Namespaces matching specific labels
  - IP addresses/CIDR blocks
- **Ports:** Allowed ports and protocols

### Special Cases
- **"Deny all"** - No rules specified, all traffic is denied
- **"N/A"** - Policy type not applicable (e.g., egress rules for ingress-only policy)
- **"All pods"** - Empty selector, applies to all pods in namespace
- **"All sources/destinations"** - No restrictions specified

## Use Cases

1. **Audit Network Policies** - Review all policies across the cluster
2. **Troubleshoot Connectivity** - Understand why pods can't communicate
3. **Documentation** - Export policies to CSV/JSON for documentation
4. **Compliance** - Verify network security policies are in place
5. **Migration** - Compare policies before/after cluster migration

## Advanced Usage

### Filter by Namespace
```bash
python3 network-policy-viewer.py -n production
```

### Export for Analysis
```bash
# CSV for Excel/Google Sheets
python3 network-policy-viewer.py --csv > policies.csv

# JSON for programmatic processing
python3 network-policy-viewer.py --json > policies.json
```

### Combine with Other Tools
```bash
# Get policies and filter by name
python3 network-policy-viewer.py --json | jq '.items[] | select(.metadata.name | contains("web"))'

# Count policies per namespace
python3 network-policy-viewer.py --json | jq '[.items[].metadata.namespace] | group_by(.) | map({namespace: .[0], count: length})'
```

## Troubleshooting

### Error: `oc` not found
- Ensure OpenShift CLI is installed and in your PATH
- Or use `--kubectl` flag to use kubectl instead

### Error: `jq` not found (bash script)
- Install jq: `brew install jq` (macOS) or `apt-get install jq` (Linux)

### Error: `tabulate` not found (Python script)
- Install: `pip install tabulate`

### No policies shown
- Check if you have access to the cluster: `oc get networkpolicy --all-namespaces`
- Verify you're connected to the correct cluster: `oc cluster-info`

## Related Files

- `NETWORK_POLICY_VIEWER_IDEAS.md` - Detailed ideas and approaches
- `requirements-network-policy-viewer.txt` - Python dependencies

## Examples

### Example 1: Quick Overview
```bash
python3 network-policy-viewer.py
```

### Example 2: Production Namespace Only
```bash
python3 network-policy-viewer.py -n production
```

### Example 3: Export and Analyze
```bash
# Export to CSV
python3 network-policy-viewer.py --csv > all-policies.csv

# Open in Excel/Google Sheets for analysis
```

### Example 4: Find Policies with Specific Selector
```bash
python3 network-policy-viewer.py --json | \
  jq '.items[] | select(.spec.podSelector.matchLabels.app == "web")'
```

## Notes

- Network policies are additive - multiple policies can apply to the same pod
- If no policy applies to a pod, default behavior depends on cluster configuration
- Policies with empty ingress/egress rules deny all traffic in that direction
- The tools show what's **allowed**, not what's **blocked**
