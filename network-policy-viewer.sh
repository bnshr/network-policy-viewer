#!/bin/bash
#
# Network Policy Viewer for OpenShift/Kubernetes (Bash version)
# Retrieves all network policies and displays them in a tabular format
#

set -euo pipefail

# Defaults
NAMESPACE=""
USE_KUBECTL=false
OUTPUT_FORMAT="table"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

View all network policies in OpenShift/Kubernetes cluster

OPTIONS:
    -n, --namespace NAMESPACE    Filter by namespace (default: all namespaces)
    -k, --kubectl                Use kubectl instead of oc
    -j, --json                   Output in JSON format
    -c, --csv                    Output in CSV format
    -h, --help                   Show this help message

EXAMPLES:
    # View all network policies
    $0

    # View policies in specific namespace
    $0 -n my-namespace

    # Use kubectl
    $0 --kubectl

    # Export to CSV
    $0 --csv > policies.csv
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -k|--kubectl)
            USE_KUBECTL=true
            shift
            ;;
        -j|--json)
            OUTPUT_FORMAT="json"
            shift
            ;;
        -c|--csv)
            OUTPUT_FORMAT="csv"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Determine command
if [[ "$USE_KUBECTL" == "true" ]]; then
    CMD="kubectl"
else
    CMD="oc"
fi

# Check if command exists
if ! command -v "$CMD" &> /dev/null; then
    echo -e "${RED}Error: $CMD not found${NC}" >&2
    exit 1
fi

# Build command
GET_CMD=("$CMD" "get" "networkpolicy" "-o" "json")
if [[ -n "$NAMESPACE" ]]; then
    GET_CMD+=("-n" "$NAMESPACE")
else
    GET_CMD+=("--all-namespaces")
fi

# Get network policies
if ! POLICIES=$("${GET_CMD[@]}"); then
    echo -e "${RED}Error: Failed to retrieve network policies${NC}" >&2
    exit 1
fi

# Check if jq is available for JSON parsing
if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}Warning: jq not found. JSON output will be raw.${NC}" >&2
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        echo "$POLICIES"
        exit 0
    else
        echo -e "${RED}Error: jq is required for table/CSV output${NC}" >&2
        exit 1
    fi
fi

# Count policies
POLICY_COUNT=$(echo "$POLICIES" | jq '.items | length')

if [[ "$POLICY_COUNT" -eq 0 ]]; then
    echo "No network policies found."
    exit 0
fi

# Output based on format
if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    echo "$POLICIES" | jq '.'
    exit 0
fi

# Function to format selectors
format_selector() {
    local selector="$1"
    if [[ -z "$selector" ]] || [[ "$selector" == "null" ]]; then
        echo "All pods"
    else
        echo "$selector" | jq -r 'to_entries | map("\(.key)=\(.value)") | join(", ")'
    fi
}

# Function to format ingress/egress rules
# In OpenShift/K8s: If policy exists, default is DENY ALL
# Only explicitly allowed rules in the rules array are permitted
format_rules() {
    local rules="$1"
    local rule_type="$2"  # "ingress" or "egress"
    local has_type="$3"    # "true" if this policy type is active
    
    # If policy type is not applicable
    if [[ "$has_type" != "true" ]]; then
        echo "N/A (not applicable)"
        return
    fi
    
    # If no rules specified, it's deny all by default
    if [[ -z "$rules" ]] || [[ "$rules" == "null" ]] || [[ "$rules" == "[]" ]]; then
        echo "[DENY ALL] Default - no rules specified"
        return
    fi
    
    local count=$(echo "$rules" | jq 'length')
    local result=""
    
    for ((i=0; i<count; i++)); do
        local rule=$(echo "$rules" | jq ".[$i]")
        local parts=()
        
        if [[ "$rule_type" == "ingress" ]]; then
            local from=$(echo "$rule" | jq -r '.from // []')
            if [[ -n "$from" ]] && [[ "$from" != "[]" ]]; then
                local from_count=$(echo "$from" | jq 'length')
                local from_parts=()
                
                for ((j=0; j<from_count; j++)); do
                    local source=$(echo "$from" | jq ".[$j]")
                    
                    if echo "$source" | jq -e '.podSelector' > /dev/null 2>&1; then
                        local pod_sel=$(echo "$source" | jq -r '.podSelector.matchLabels // {}')
                        local formatted=$(format_selector "$pod_sel")
                        from_parts+=("Pods: $formatted")
                    fi
                    
                    if echo "$source" | jq -e '.namespaceSelector' > /dev/null 2>&1; then
                        local ns_sel=$(echo "$source" | jq -r '.namespaceSelector.matchLabels // {}')
                        local formatted=$(format_selector "$ns_sel")
                        from_parts+=("Namespaces: $formatted")
                    fi
                    
                    if echo "$source" | jq -e '.ipBlock' > /dev/null 2>&1; then
                        local cidr=$(echo "$source" | jq -r '.ipBlock.cidr')
                        from_parts+=("IPs: $cidr")
                    fi
                done
                
                if [[ ${#from_parts[@]} -gt 0 ]]; then
                    parts+=("From: $(IFS=' | '; echo "${from_parts[*]}")")
                fi
            fi
        else
            local to=$(echo "$rule" | jq -r '.to // []')
            if [[ -n "$to" ]] && [[ "$to" != "[]" ]]; then
                local to_count=$(echo "$to" | jq 'length')
                local to_parts=()
                
                for ((j=0; j<to_count; j++)); do
                    local dest=$(echo "$to" | jq ".[$j]")
                    
                    if echo "$dest" | jq -e '.podSelector' > /dev/null 2>&1; then
                        local pod_sel=$(echo "$dest" | jq -r '.podSelector.matchLabels // {}')
                        local formatted=$(format_selector "$pod_sel")
                        to_parts+=("Pods: $formatted")
                    fi
                    
                    if echo "$dest" | jq -e '.namespaceSelector' > /dev/null 2>&1; then
                        local ns_sel=$(echo "$dest" | jq -r '.namespaceSelector.matchLabels // {}')
                        local formatted=$(format_selector "$ns_sel")
                        to_parts+=("Namespaces: $formatted")
                    fi
                    
                    if echo "$dest" | jq -e '.ipBlock' > /dev/null 2>&1; then
                        local cidr=$(echo "$dest" | jq -r '.ipBlock.cidr')
                        to_parts+=("IPs: $cidr")
                    fi
                done
                
                if [[ ${#to_parts[@]} -gt 0 ]]; then
                    parts+=("To: $(IFS=' | '; echo "${to_parts[*]}")")
                fi
            fi
        fi
        
        # Ports
        local ports=$(echo "$rule" | jq -r '.ports // []')
        if [[ -n "$ports" ]] && [[ "$ports" != "[]" ]]; then
            local port_str=$(echo "$ports" | jq -r '.[] | "\(.protocol // "TCP"):\(.port // "all")"' | tr '\n' ',' | sed 's/,$//')
            parts+=("Ports: $port_str")
        fi
        
        if [[ ${#parts[@]} -gt 0 ]]; then
            result+="  [ALLOWED] $(IFS=' | '; echo "${parts[*]}")\n"
        fi
    done
    
    # Prepend default deny message if there are allowed rules
    if [[ -n "$result" ]]; then
        echo -e "[DENY ALL] Default\n$result" | sed 's/[[:space:]]*$//'
    else
        echo "[DENY ALL] Default - no rules specified"
    fi
}

# Generate table data
if [[ "$OUTPUT_FORMAT" == "csv" ]]; then
    # CSV header
    echo "Namespace,Policy Name,Pod Selector,Types,Ingress Rules,Egress Rules"
    
    # CSV rows - show deny all default, then allowed rules
    echo "$POLICIES" | jq -r '.items[] | 
        "\(.metadata.namespace // "default")|\(.metadata.name)|\(.spec.podSelector.matchLabels // {} | to_entries | map("\(.key)=\(.value)") | join(",") // "All pods")|\(.spec.policyTypes // [] | join(";"))|\(.spec.ingress // [] | length)|\(.spec.egress // [] | length)"' | \
    while IFS='|' read -r ns name selector types ingress_count egress_count; do
        policy_json=$(echo "$POLICIES" | jq --arg name "$name" --arg ns "$ns" '.items[] | select(.metadata.name == $name and .metadata.namespace == $ns)')
        spec=$(echo "$policy_json" | jq '.spec')
        policy_types=$(echo "$spec" | jq -r '.policyTypes // []')
        ingress_rules=$(echo "$spec" | jq -c '.ingress // []')
        egress_rules=$(echo "$spec" | jq -c '.egress // []')
        
        # Determine policy types
        has_ingress_type="false"
        has_egress_type="false"
        if [[ -z "$policy_types" ]] || [[ "$policy_types" == "[]" ]]; then
            has_ingress_type=$(echo "$ingress_rules" | jq -r 'if length > 0 then "true" else "false" end')
            has_egress_type=$(echo "$egress_rules" | jq -r 'if length > 0 then "true" else "false" end')
        else
            has_ingress_type=$(echo "$policy_types" | jq -r 'if index("Ingress") != null then "true" else "false" end')
            has_egress_type=$(echo "$policy_types" | jq -r 'if index("Egress") != null then "true" else "false" end')
        fi
        
        # Format for CSV - simpler format
        ingress_str=""
        if [[ "$has_ingress_type" == "false" ]]; then
            ingress_str="N/A"
        elif [[ "$ingress_count" == "0" ]]; then
            ingress_str="Deny all (default - no rules)"
        else
            ingress_str="Deny all (default); Allowed: $(echo "$ingress_rules" | jq -r '[.[] | "From: \(.from // [] | map(if .podSelector then "Pods:\(.podSelector.matchLabels // {})" elif .namespaceSelector then "NS:\(.namespaceSelector.matchLabels // {})" elif .ipBlock then "IP:\(.ipBlock.cidr)" else "" end) | join(",")) | Ports: \(.ports // [] | map("\(.protocol // "TCP"):\(.port // "all")") | join(","))"] | join("; ")')"
        fi
        
        egress_str=""
        if [[ "$has_egress_type" == "false" ]]; then
            egress_str="N/A"
        elif [[ "$egress_count" == "0" ]]; then
            egress_str="Deny all (default - no rules)"
        else
            egress_str="Deny all (default); Allowed: $(echo "$egress_rules" | jq -r '[.[] | "To: \(.to // [] | map(if .podSelector then "Pods:\(.podSelector.matchLabels // {})" elif .namespaceSelector then "NS:\(.namespaceSelector.matchLabels // {})" elif .ipBlock then "IP:\(.ipBlock.cidr)" else "" end) | join(",")) | Ports: \(.ports // [] | map("\(.protocol // "TCP"):\(.port // "all")") | join(","))"] | join("; ")')"
        fi
        
        echo "$ns,$name,\"$selector\",$types,\"$ingress_str\",\"$egress_str\""
    done
else
    # Table output
    echo ""
    echo "=========================================================================================================="
    echo "NETWORK POLICIES OVERVIEW"
    echo "=========================================================================================================="
    echo ""
    echo "NOTE: In OpenShift/Kubernetes, NetworkPolicies enforce 'deny all' by default."
    echo "      Only traffic matching the explicitly allowed rules below is permitted."
    echo ""
    echo "=========================================================================================================="
    echo ""
    
    printf "%-20s %-30s %-30s %-15s %-50s %-50s\n" \
        "NAMESPACE" "POLICY NAME" "POD SELECTOR" "TYPES" "INGRESS RULES" "EGRESS RULES"
    echo "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    
    echo "$POLICIES" | jq -r '.items[] | 
        "\(.metadata.namespace // "default")|\(.metadata.name)|\(.spec.podSelector.matchLabels // {} | to_entries | map("\(.key)=\(.value)") | join(", ") // "All pods")|\(.spec.policyTypes // [] | join(", "))|\(.spec.ingress // [] | length > 0)|\(.spec.egress // [] | length > 0)"' | \
    while IFS='|' read -r ns name selector types has_ingress_rules has_egress_rules; do
        # Get full policy for this item to extract rules
        policy_json=$(echo "$POLICIES" | jq --arg name "$name" --arg ns "$ns" '.items[] | select(.metadata.name == $name and .metadata.namespace == $ns)')
        
        # Determine if policy types are active
        spec=$(echo "$policy_json" | jq '.spec')
        policy_types=$(echo "$spec" | jq -r '.policyTypes // []')
        ingress_rules=$(echo "$spec" | jq -c '.ingress // []')
        egress_rules=$(echo "$spec" | jq -c '.egress // []')
        
        # If policyTypes not specified, infer from rules
        has_ingress_type="false"
        has_egress_type="false"
        if [[ -z "$policy_types" ]] || [[ "$policy_types" == "[]" ]]; then
            has_ingress_type=$(echo "$ingress_rules" | jq -r 'if length > 0 then "true" else "false" end')
            has_egress_type=$(echo "$egress_rules" | jq -r 'if length > 0 then "true" else "false" end')
        else
            has_ingress_type=$(echo "$policy_types" | jq -r 'if index("Ingress") != null then "true" else "false" end')
            has_egress_type=$(echo "$policy_types" | jq -r 'if index("Egress") != null then "true" else "false" end')
        fi
        
        ingress_str=$(format_rules "$ingress_rules" "ingress" "$has_ingress_type")
        egress_str=$(format_rules "$egress_rules" "egress" "$has_egress_type")
        
        # Truncate long strings for display (but preserve first line)
        ingress_str=$(echo "$ingress_str" | head -n 3 | tr '\n' ' ' | sed 's/ $//')
        egress_str=$(echo "$egress_str" | head -n 3 | tr '\n' ' ' | sed 's/ $//')
        
        printf "%-20s %-30s %-30s %-15s %-50s %-50s\n" \
            "$ns" "$name" "$selector" "$types" "$ingress_str" "$egress_str"
    done
    
    echo ""
    echo "Total policies: $POLICY_COUNT"
    echo ""
    echo "Legend:"
    echo "  [DENY ALL] Default - All traffic is blocked by default"
    echo "  [ALLOWED] - Only these explicitly allowed rules permit traffic"
fi
