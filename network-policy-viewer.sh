#!/bin/bash
#
# Network Policy Viewer for OpenShift/Kubernetes (Bash version)
# Retrieves all network policies and displays traffic flows
# in a flat CSV format (one row per allowed traffic flow).
#
# Column order:
#   Namespace, Policy Name, Source → Destination, then Port info.
#   "Direction" column only appears when showing both egress and ingress.
#

set -euo pipefail

# ──────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────
NAMESPACE=""
USE_KUBECTL=false
OUTPUT_FORMAT="csv"          # csv (default) | json | table
DIRECTION_FILTER=""          # "" = both | ingress | egress

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ──────────────────────────────────────────────
# Usage
# ──────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Retrieve all NetworkPolicies from an OpenShift/Kubernetes cluster and display
allowed traffic flows in a flat, per-row format.

OUTPUT COLUMNS (when -d egress):
  Namespace          Namespace where the policy lives
  Policy Name        Name of the NetworkPolicy
  Pod Selector       Pods the policy applies to (source of egress traffic)
  Destination Type   ipBlock / podSelector / namespaceSelector / All
  Destination        CIDR, label selector, or "All"
  Dest Namespace     Target namespace (if determinable)
  Protocol           TCP / UDP / SCTP / All
  Port               Destination port number (or "All" if unrestricted)

When showing both directions (no -d flag), a "Direction" column is prepended.

OPTIONS:
    -n, --namespace NS     Filter by namespace (default: all namespaces)
    -d, --direction DIR    Show only 'egress' or 'ingress' rows (default: both)
    -k, --kubectl          Use kubectl instead of oc
    -j, --json             Output raw JSON from the API
    -t, --table            Pretty-print as an aligned table instead of CSV
    -h, --help             Show this help message

EXAMPLES:
    # Show all egress flows as CSV
    $0 -d egress

    # Show egress flows for a specific namespace
    $0 -d egress -n openshift-monitoring

    # Show both directions in a pretty table
    $0 -t

    # Save egress to file
    $0 -d egress > egress-flows.csv
EOF
}

# ──────────────────────────────────────────────
# Parse arguments
# ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)   NAMESPACE="$2";          shift 2 ;;
        -d|--direction)
            DIRECTION_FILTER="$2"
            if [[ "$DIRECTION_FILTER" != "ingress" ]] && [[ "$DIRECTION_FILTER" != "egress" ]]; then
                echo -e "${RED}Error: --direction must be 'ingress' or 'egress'${NC}" >&2; exit 1
            fi
            shift 2 ;;
        -k|--kubectl)     USE_KUBECTL=true;        shift   ;;
        -j|--json)        OUTPUT_FORMAT="json";    shift   ;;
        -t|--table)       OUTPUT_FORMAT="table";   shift   ;;
        -h|--help)        usage; exit 0            ;;
        *)                echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# ──────────────────────────────────────────────
# CLI tool selection
# ──────────────────────────────────────────────
CMD="oc"
[[ "$USE_KUBECTL" == "true" ]] && CMD="kubectl"

if ! command -v "$CMD" &>/dev/null; then
    echo -e "${RED}Error: $CMD not found. Install it or use --kubectl / default oc.${NC}" >&2
    exit 1
fi
if ! command -v jq &>/dev/null; then
    echo -e "${RED}Error: jq is required. Install it first.${NC}" >&2
    exit 1
fi

# ──────────────────────────────────────────────
# Fetch network policies
# ──────────────────────────────────────────────
GET_CMD=("$CMD" "get" "networkpolicy" "-o" "json")
if [[ -n "$NAMESPACE" ]]; then
    GET_CMD+=("-n" "$NAMESPACE")
else
    GET_CMD+=("--all-namespaces")
fi

if ! POLICIES=$("${GET_CMD[@]}" 2>/dev/null); then
    echo -e "${RED}Error: Failed to retrieve network policies${NC}" >&2
    exit 1
fi

POLICY_COUNT=$(echo "$POLICIES" | jq '.items | length')
if [[ "$POLICY_COUNT" -eq 0 ]]; then
    echo "No network policies found."
    exit 0
fi

# ──────────────────────────────────────────────
# JSON output shortcut
# ──────────────────────────────────────────────
if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    echo "$POLICIES" | jq '.'
    exit 0
fi

# ──────────────────────────────────────────────
# Helper: format matchLabels object → string
# ──────────────────────────────────────────────
format_labels() {
    local json_obj="$1"
    if [[ -z "$json_obj" ]] || [[ "$json_obj" == "null" ]] || [[ "$json_obj" == "{}" ]]; then
        echo "All"
    else
        echo "$json_obj" | jq -r 'to_entries | map("\(.key)=\(.value)") | join("; ")'
    fi
}

# ──────────────────────────────────────────────
# Named-port resolution
#
# Kubernetes NetworkPolicies can reference ports by name (e.g. "dns-tcp").
# These names map to containerPort entries in pod specs.
# We query pods in the target namespace to resolve the name → number.
#
# A simple file-based cache avoids repeated API calls for the same namespace.
# ──────────────────────────────────────────────
PORT_CACHE_DIR=$(mktemp -d)
trap 'rm -rf "$PORT_CACHE_DIR"' EXIT

# Fetch and cache all pods for a namespace (JSON).
cache_pods_for_ns() {
    local target_ns="$1"
    local cache_file="${PORT_CACHE_DIR}/${target_ns}.json"

    if [[ -f "$cache_file" ]]; then
        cat "$cache_file"
        return
    fi

    local pods_json
    if pods_json=$("$CMD" get pods -n "$target_ns" -o json 2>/dev/null); then
        echo "$pods_json" > "$cache_file"
        echo "$pods_json"
    else
        echo '{"items":[]}' > "$cache_file"
        echo '{"items":[]}'
    fi
}

# Resolve a named port to its numeric value.
# Usage: resolve_port <port_name_or_number> <protocol> <target_namespace>
# Returns: the numeric port, or "name (unresolved)" if lookup fails.
resolve_port() {
    local port_val="$1"
    local protocol="$2"
    local target_ns="$3"

    # Already numeric — return as-is
    if [[ "$port_val" =~ ^[0-9]+$ ]]; then
        echo "$port_val"
        return
    fi

    # Special values
    if [[ "$port_val" == "All" ]] || [[ -z "$port_val" ]]; then
        echo "$port_val"
        return
    fi

    # No namespace to query
    if [[ -z "$target_ns" ]]; then
        echo "$port_val"
        return
    fi

    # Query pods
    local pods_json
    pods_json=$(cache_pods_for_ns "$target_ns")

    # Search all containers for a matching named port
    local resolved
    resolved=$(echo "$pods_json" | jq -r \
        --arg pname "$port_val" \
        --arg proto "$protocol" '
        [ .items[]?.spec.containers[]?.ports[]?
          | select(.name == $pname and (.protocol // "TCP") == $proto)
          | .containerPort
        ] | unique | first // empty
    ')

    if [[ -n "$resolved" ]] && [[ "$resolved" != "null" ]]; then
        echo "$resolved"
    else
        echo "$port_val"
    fi
}

# ──────────────────────────────────────────────
# Emit a single row.
# When a direction filter is set, Direction is omitted.
# ──────────────────────────────────────────────
emit_row() {
    local direction="$1"
    local namespace="$2"
    local policy_name="$3"
    local pod_selector="$4"
    local dest_type="$5"
    local dest_value="$6"
    local dest_ns="$7"
    local protocol="$8"
    local port="$9"

    if [[ -n "$DIRECTION_FILTER" ]]; then
        # Direction already known — omit from output
        echo "${namespace},${policy_name},${pod_selector},${dest_type},${dest_value},${dest_ns},${protocol},${port}"
    else
        echo "${direction},${namespace},${policy_name},${pod_selector},${dest_type},${dest_value},${dest_ns},${protocol},${port}"
    fi
}

# ──────────────────────────────────────────────
# Build port tuples from a rule's .ports array
#   Args: <ports_json_array> <target_namespace>
#   Returns lines of "protocol|port"
#   Named ports are resolved to numbers via pod lookup.
# ──────────────────────────────────────────────
build_port_tuples() {
    local ports_arr="$1"
    local target_ns="${2:-}"
    local ports_len
    ports_len=$(echo "$ports_arr" | jq 'length')

    if [[ "$ports_len" -eq 0 ]]; then
        echo "All|All"
        return
    fi

    for ((pi=0; pi<ports_len; pi++)); do
        p_proto=$(echo "$ports_arr" | jq -r ".[$pi].protocol // \"TCP\"")
        p_port=$(echo "$ports_arr"  | jq -r ".[$pi].port // \"All\"")
        p_end=$(echo "$ports_arr"   | jq -r ".[$pi].endPort // empty")

        # Resolve named port to numeric
        p_port=$(resolve_port "$p_port" "$p_proto" "$target_ns")

        if [[ -n "$p_end" ]]; then
            echo "${p_proto}|${p_port}-${p_end}"
        else
            echo "${p_proto}|${p_port}"
        fi
    done
}

# ──────────────────────────────────────────────
# Build destination tuples from a rule's .to array
#   Returns lines of "type|value|dest_ns"
# ──────────────────────────────────────────────
build_dest_tuples() {
    local to_arr="$1"
    local source_ns="$2"
    local to_len
    to_len=$(echo "$to_arr" | jq 'length')

    if [[ "$to_len" -eq 0 ]]; then
        echo "All|All destinations||"
        return
    fi

    for ((di=0; di<to_len; di++)); do
        dest=$(echo "$to_arr" | jq -c ".[$di]")

        if echo "$dest" | jq -e '.ipBlock' &>/dev/null; then
            cidr=$(echo "$dest" | jq -r '.ipBlock.cidr')
            except=$(echo "$dest" | jq -r '.ipBlock.except // [] | join("; ")')
            dest_val="$cidr"
            [[ -n "$except" ]] && dest_val="$cidr (except $except)"
            echo "ipBlock|${dest_val}|"
        fi

        if echo "$dest" | jq -e '.namespaceSelector' &>/dev/null; then
            ns_labels=$(echo "$dest" | jq -c '.namespaceSelector.matchLabels // {}')
            ns_str=$(format_labels "$ns_labels")
            # Try to extract a concrete namespace name
            dest_ns=""
            if echo "$ns_labels" | jq -e '.["kubernetes.io/metadata.name"]' &>/dev/null; then
                dest_ns=$(echo "$ns_labels" | jq -r '.["kubernetes.io/metadata.name"]')
            elif echo "$ns_labels" | jq -e '.name' &>/dev/null; then
                dest_ns=$(echo "$ns_labels" | jq -r '.name')
            fi

            # Combined namespaceSelector + podSelector in same entry
            if echo "$dest" | jq -e '.podSelector' &>/dev/null; then
                ps_labels=$(echo "$dest" | jq -c '.podSelector.matchLabels // {}')
                ps_str=$(format_labels "$ps_labels")
                echo "namespaceSelector+podSelector|NS(${ns_str}) Pods(${ps_str})|${dest_ns}"
            else
                echo "namespaceSelector|${ns_str}|${dest_ns}"
            fi
        elif echo "$dest" | jq -e '.podSelector' &>/dev/null; then
            # podSelector only → same namespace
            ps_labels=$(echo "$dest" | jq -c '.podSelector.matchLabels // {}')
            ps_str=$(format_labels "$ps_labels")
            echo "podSelector|${ps_str}|${source_ns}"
        fi
    done
}

# ──────────────────────────────────────────────
# Build source tuples from a rule's .from array
#   Returns lines of "type|value|src_ns"
# ──────────────────────────────────────────────
build_src_tuples() {
    local from_arr="$1"
    local policy_ns="$2"
    local from_len
    from_len=$(echo "$from_arr" | jq 'length')

    if [[ "$from_len" -eq 0 ]]; then
        echo "All|All sources|"
        return
    fi

    for ((si=0; si<from_len; si++)); do
        src=$(echo "$from_arr" | jq -c ".[$si]")

        if echo "$src" | jq -e '.ipBlock' &>/dev/null; then
            cidr=$(echo "$src" | jq -r '.ipBlock.cidr')
            except=$(echo "$src" | jq -r '.ipBlock.except // [] | join("; ")')
            src_val="$cidr"
            [[ -n "$except" ]] && src_val="$cidr (except $except)"
            echo "ipBlock|${src_val}|"
        fi

        if echo "$src" | jq -e '.namespaceSelector' &>/dev/null; then
            ns_labels=$(echo "$src" | jq -c '.namespaceSelector.matchLabels // {}')
            ns_str=$(format_labels "$ns_labels")
            src_ns=""
            if echo "$ns_labels" | jq -e '.["kubernetes.io/metadata.name"]' &>/dev/null; then
                src_ns=$(echo "$ns_labels" | jq -r '.["kubernetes.io/metadata.name"]')
            elif echo "$ns_labels" | jq -e '.name' &>/dev/null; then
                src_ns=$(echo "$ns_labels" | jq -r '.name')
            fi

            if echo "$src" | jq -e '.podSelector' &>/dev/null; then
                ps_labels=$(echo "$src" | jq -c '.podSelector.matchLabels // {}')
                ps_str=$(format_labels "$ps_labels")
                echo "namespaceSelector+podSelector|NS(${ns_str}) Pods(${ps_str})|${src_ns}"
            else
                echo "namespaceSelector|${ns_str}|${src_ns}"
            fi
        elif echo "$src" | jq -e '.podSelector' &>/dev/null; then
            ps_labels=$(echo "$src" | jq -c '.podSelector.matchLabels // {}')
            ps_str=$(format_labels "$ps_labels")
            echo "podSelector|${ps_str}|${policy_ns}"
        fi
    done
}

# ──────────────────────────────────────────────
# Core: expand every policy into flat rows
# ──────────────────────────────────────────────
generate_rows() {
    echo "$POLICIES" | jq -c '.items[]' | while IFS= read -r policy; do

        ns=$(echo "$policy"  | jq -r '.metadata.namespace // "default"')
        name=$(echo "$policy" | jq -r '.metadata.name')
        pod_sel_json=$(echo "$policy" | jq -c '.spec.podSelector.matchLabels // {}')
        pod_sel=$(format_labels "$pod_sel_json")

        spec=$(echo "$policy" | jq -c '.spec')
        policy_types_arr=$(echo "$spec" | jq -r '.policyTypes // [] | .[]' 2>/dev/null)

        # Determine active directions
        has_ingress="false"; has_egress="false"
        if [[ -z "$policy_types_arr" ]]; then
            [[ $(echo "$spec" | jq '.ingress // [] | length') -gt 0 ]] && has_ingress="true"
            [[ $(echo "$spec" | jq '.egress  // [] | length') -gt 0 ]] && has_egress="true"
        else
            echo "$policy_types_arr" | grep -q "Ingress" && has_ingress="true"
            echo "$policy_types_arr" | grep -q "Egress"  && has_egress="true"
        fi

        # ── EGRESS rows ──────────────────────
        if [[ "$has_egress" == "true" ]] && [[ "$DIRECTION_FILTER" != "ingress" ]]; then
            egress_rules=$(echo "$spec" | jq -c '.egress // []')
            egress_len=$(echo "$egress_rules" | jq 'length')

            if [[ "$egress_len" -eq 0 ]]; then
                # Deny-all egress — single summary row
                emit_row "Egress" "$ns" "$name" "$pod_sel" "DENY ALL" "All traffic denied" "" "ALL" "ALL"
            else
                for ((ri=0; ri<egress_len; ri++)); do
                    rule=$(echo "$egress_rules" | jq -c ".[$ri]")

                    ports_arr=$(echo "$rule" | jq -c '.ports // []')
                    to_arr=$(echo "$rule" | jq -c '.to // []')

                    # Cross-product: one row per (destination × port)
                    # For egress, resolve named ports against the DESTINATION namespace
                    build_dest_tuples "$to_arr" "$ns" | while IFS='|' read -r d_type d_val d_ns; do
                        # Use destination namespace for port resolution; fall back to policy namespace
                        resolve_ns="${d_ns:-$ns}"
                        build_port_tuples "$ports_arr" "$resolve_ns" | while IFS='|' read -r proto port_val; do
                            emit_row "Egress" "$ns" "$name" "$pod_sel" "$d_type" "$d_val" "$d_ns" "$proto" "$port_val"
                        done
                    done
                done
            fi
        fi

        # ── INGRESS rows ─────────────────────
        if [[ "$has_ingress" == "true" ]] && [[ "$DIRECTION_FILTER" != "egress" ]]; then
            ingress_rules=$(echo "$spec" | jq -c '.ingress // []')
            ingress_len=$(echo "$ingress_rules" | jq 'length')

            if [[ "$ingress_len" -eq 0 ]]; then
                emit_row "Ingress" "$ns" "$name" "$pod_sel" "DENY ALL" "All traffic denied" "" "ALL" "ALL"
            else
                for ((ri=0; ri<ingress_len; ri++)); do
                    rule=$(echo "$ingress_rules" | jq -c ".[$ri]")

                    ports_arr=$(echo "$rule" | jq -c '.ports // []')
                    from_arr=$(echo "$rule" | jq -c '.from // []')

                    # For ingress, resolve named ports against the POLICY namespace
                    # (the policy's podSelector targets pods in this namespace)
                    build_src_tuples "$from_arr" "$ns" | while IFS='|' read -r s_type s_val s_ns; do
                        build_port_tuples "$ports_arr" "$ns" | while IFS='|' read -r proto port_val; do
                            emit_row "Ingress" "$ns" "$name" "$pod_sel" "$s_type" "$s_val" "$s_ns" "$proto" "$port_val"
                        done
                    done
                done
            fi
        fi

    done
}

# ──────────────────────────────────────────────
# Build header based on direction filter
# ──────────────────────────────────────────────
if [[ -n "$DIRECTION_FILTER" ]]; then
    # Direction is implied — omit from header
    HEADER="Namespace,Policy Name,Pod Selector,Destination Type,Destination,Dest Namespace,Protocol,Port"
else
    HEADER="Direction,Namespace,Policy Name,Pod Selector,Destination Type,Destination,Dest Namespace,Protocol,Port"
fi

# ──────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────
if [[ "$OUTPUT_FORMAT" == "table" ]]; then
    echo ""
    echo -e "${BOLD}=========================================================================================================${NC}"
    echo -e "${BOLD}NETWORK POLICY TRAFFIC FLOWS${NC}"
    echo -e "${BOLD}=========================================================================================================${NC}"
    if [[ -n "$NAMESPACE" ]]; then
        echo -e "  Filtered by namespace: ${CYAN}${NAMESPACE}${NC}"
    fi
    if [[ -n "$DIRECTION_FILTER" ]]; then
        echo -e "  Direction: ${CYAN}${DIRECTION_FILTER}${NC}"
    fi
    echo ""
    echo -e "${YELLOW}NOTE: NetworkPolicies enforce 'deny all' by default.${NC}"
    echo -e "${YELLOW}      Only traffic matching the rows below is explicitly allowed.${NC}"
    echo ""

    ROWS=$(generate_rows)
    TOTAL=$(echo "$ROWS" | grep -c . || true)

    if [[ "$TOTAL" -eq 0 ]]; then
        echo "No traffic flow rows generated."
        exit 0
    fi

    {
        echo "$HEADER"
        echo "$ROWS"
    } | column -t -s ','

    echo ""
    echo -e "Total allowed flows: ${GREEN}${TOTAL}${NC}  |  Policies scanned: ${POLICY_COUNT}"
    echo ""
    echo "Legend:"
    echo "  DENY ALL                       – All traffic is blocked (no allow rules)"
    echo "  ipBlock                         – Target is an IP/CIDR range"
    echo "  podSelector                     – Target is pods matching labels (same namespace)"
    echo "  namespaceSelector               – Target is pods in namespaces matching labels"
    echo "  namespaceSelector+podSelector   – Target is specific pods in specific namespaces"
else
    # CSV output (default)
    echo "$HEADER"
    generate_rows
fi
