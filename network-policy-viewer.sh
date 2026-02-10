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
POLICY_TYPE_FILTER=""
RESOLVE_PORTS=true

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
    -t, --type TYPE              Filter by policy type: 'ingress' or 'egress' (default: show both)
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
        -t|--type)
            POLICY_TYPE_FILTER="$2"
            if [[ "$POLICY_TYPE_FILTER" != "ingress" ]] && [[ "$POLICY_TYPE_FILTER" != "egress" ]]; then
                echo -e "${RED}Error: --type must be 'ingress' or 'egress'${NC}" >&2
                exit 1
            fi
            shift 2
            ;;
        --no-resolve-ports)
            RESOLVE_PORTS=false
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

# Cache for pod queries per namespace (to avoid multiple API calls)
# Using a simple approach compatible with bash 3.2 (no associative arrays)
# Cache format: POD_CACHE_<namespace> variable
POD_CACHE_NAMESPACES=""

# Function to get pods for a namespace (with caching)
get_pods_for_namespace() {
    local namespace="$1"
    local use_kubectl="$2"
    
    # Sanitize namespace for variable name (replace special chars with _)
    local cache_var_name=$(echo "POD_CACHE_${namespace}" | tr -cd '[:alnum:]_')
    
    # Check cache first using eval (bash 3.2 compatible)
    local cached_value
    eval "cached_value=\${${cache_var_name}:-}"
    if [[ -n "$cached_value" ]]; then
        echo "$cached_value"
        return
    fi
    
    # Query pods
    local cmd="$CMD"
    if [[ "$use_kubectl" == "true" ]]; then
        cmd="kubectl"
    else
        cmd="oc"
    fi
    
    local pods_json
    if pods_json=$("$cmd" get pods -n "$namespace" -o json 2>/dev/null); then
        # Cache the result using eval (bash 3.2 compatible)
        eval "${cache_var_name}=\"\$pods_json\""
        # Track this namespace in our list
        if [[ "$POD_CACHE_NAMESPACES" != *"$cache_var_name"* ]]; then
            POD_CACHE_NAMESPACES="$POD_CACHE_NAMESPACES $cache_var_name"
        fi
        echo "$pods_json"
    else
        # Cache empty result to avoid retrying
        eval "${cache_var_name}=\"{}\""
        echo "{}"
    fi
}

# Function to resolve a named port to its numeric value
resolve_named_port() {
    local port_name="$1"
    local protocol="$2"
    local namespace="$3"
    local pod_selector="$4"  # JSON object with matchLabels
    local use_kubectl="$5"
    
    # If port_name is not a string (it's already a number), return as-is
    if [[ "$port_name" =~ ^[0-9]+$ ]]; then
        echo "$port_name"
        return
    fi
    
    # If no namespace, can't resolve
    if [[ -z "$namespace" ]]; then
        echo "$port_name"
        return
    fi
    
    # Get pods (using cache)
    local pods_json
    pods_json=$(get_pods_for_namespace "$namespace" "$use_kubectl")
    
    if [[ -z "$pods_json" ]] || [[ "$pods_json" == "{}" ]]; then
        echo "$port_name"
        return
    fi
    
    # Filter pods by selector if provided
    local filtered_pods="$pods_json"
    if [[ -n "$pod_selector" ]] && [[ "$pod_selector" != "null" ]] && [[ "$pod_selector" != "{}" ]]; then
        # Extract matchLabels from selector
        local match_labels=$(echo "$pod_selector" | jq -r '.matchLabels // {}')
        if [[ -n "$match_labels" ]] && [[ "$match_labels" != "null" ]] && [[ "$match_labels" != "{}" ]]; then
            # Filter pods that match all labels
            filtered_pods=$(echo "$pods_json" | jq --argjson labels "$match_labels" '
                .items[] | 
                select(
                    (.metadata.labels // {}) as $pod_labels |
                    ($labels | to_entries | all(. as $label | $pod_labels[$label.key] == $label.value))
                )
            ' | jq -s '{items: .}')
        fi
    fi
    
    # Search for the named port in all matching pods
    local resolved_port
    resolved_port=$(echo "$filtered_pods" | jq -r --arg port_name "$port_name" --arg protocol "$protocol" '
        .items[]? |
        .spec.containers[]? |
        .ports[]? |
        select(.name == $port_name and (.protocol // "TCP") == $protocol) |
        .containerPort
    ' | head -n 1)
    
    if [[ -n "$resolved_port" ]] && [[ "$resolved_port" != "null" ]] && [[ "$resolved_port" =~ ^[0-9]+$ ]]; then
        echo "$resolved_port"
    else
        echo "$port_name"
    fi
}

# Function to format a port with resolution
format_port() {
    local port_obj="$1"  # JSON object with protocol and port
    local namespace="$2"
    local pod_selector="$3"
    local use_kubectl="$4"
    
    local protocol=$(echo "$port_obj" | jq -r '.protocol // "TCP"')
    local port=$(echo "$port_obj" | jq -r '.port // empty')
    local end_port=$(echo "$port_obj" | jq -r '.endPort // empty')
    
    if [[ -z "$port" ]]; then
        echo "$protocol"
        return
    fi
    
    # Try to resolve if port is a string (named port)
    local resolved_port="$port"
    if [[ ! "$port" =~ ^[0-9]+$ ]] && [[ -n "$namespace" ]] && [[ "$RESOLVE_PORTS" == "true" ]]; then
        resolved_port=$(resolve_named_port "$port" "$protocol" "$namespace" "$pod_selector" "$use_kubectl")
    fi
    
    # Format output: show resolved port and original name if different
    if [[ "$resolved_port" != "$port" ]] && [[ "$resolved_port" =~ ^[0-9]+$ ]]; then
        if [[ -n "$end_port" ]]; then
            echo "${protocol}:${resolved_port}-${end_port} (${port})"
        else
            echo "${protocol}:${resolved_port} (${port})"
        fi
    else
        if [[ -n "$end_port" ]]; then
            echo "${protocol}:${port}-${end_port}"
        else
            echo "${protocol}:${port}"
        fi
    fi
}

# Function to format ingress/egress rules
# In OpenShift/K8s: If policy exists, default is DENY ALL
# Only explicitly allowed rules in the rules array are permitted
format_rules() {
    local rules="$1"
    local rule_type="$2"  # "ingress" or "egress"
    local has_type="$3"    # "true" if this policy type is active
    local namespace="$4"    # Namespace for port resolution
    local pod_selector="$5" # Pod selector for port resolution (JSON)
    local use_kubectl="$6"  # Whether to use kubectl
    
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
            
            # Ports - for ingress, use policy's pod selector
            local ports=$(echo "$rule" | jq -r '.ports // []')
            if [[ -n "$ports" ]] && [[ "$ports" != "[]" ]]; then
                local port_parts=()
                local port_count=$(echo "$ports" | jq 'length')
                
                for ((k=0; k<port_count; k++)); do
                    local port_obj=$(echo "$ports" | jq ".[$k]")
                    local formatted_port=$(format_port "$port_obj" "$namespace" "$pod_selector" "$use_kubectl")
                    port_parts+=("$formatted_port")
                done
                
                if [[ ${#port_parts[@]} -gt 0 ]]; then
                    parts+=("Ports: $(IFS=', '; echo "${port_parts[*]}")")
                fi
            fi
        else
            local to=$(echo "$rule" | jq -r '.to // []')
            local dest_pod_selector="$pod_selector"
            local dest_namespace="$namespace"
            
            if [[ -n "$to" ]] && [[ "$to" != "[]" ]]; then
                local to_count=$(echo "$to" | jq 'length')
                local to_parts=()
                
                for ((j=0; j<to_count; j++)); do
                    local dest=$(echo "$to" | jq ".[$j]")
                    
                    if echo "$dest" | jq -e '.podSelector' > /dev/null 2>&1; then
                        local pod_sel=$(echo "$dest" | jq -r '.podSelector.matchLabels // {}')
                        local formatted=$(format_selector "$pod_sel")
                        to_parts+=("Pods: $formatted")
                        # Use the first podSelector found for port resolution
                        if [[ -z "$dest_pod_selector" ]] || [[ "$dest_pod_selector" == "null" ]] || [[ "$dest_pod_selector" == "{}" ]]; then
                            dest_pod_selector=$(echo "$dest" | jq -c '.podSelector // {}')
                        fi
                    fi
                    
                    if echo "$dest" | jq -e '.namespaceSelector' > /dev/null 2>&1; then
                        local ns_sel=$(echo "$dest" | jq -r '.namespaceSelector.matchLabels // {}')
                        local formatted=$(format_selector "$ns_sel")
                        to_parts+=("Namespaces: $formatted")
                        # Try to extract namespace from namespaceSelector
                        local ns_selector_obj=$(echo "$dest" | jq -c '.namespaceSelector // {}')
                        local match_labels=$(echo "$ns_selector_obj" | jq -r '.matchLabels // {}')
                        # Check if namespace is specified via kubernetes.io/metadata.name
                        if echo "$match_labels" | jq -e '.["kubernetes.io/metadata.name"]' > /dev/null 2>&1; then
                            dest_namespace=$(echo "$match_labels" | jq -r '.["kubernetes.io/metadata.name"]')
                        elif echo "$match_labels" | jq -e '.name' > /dev/null 2>&1; then
                            dest_namespace=$(echo "$match_labels" | jq -r '.name')
                        else
                            # Can't determine specific namespace
                            dest_namespace=""
                        fi
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
            
            # Ports - for egress, use destination pod selector and namespace
            local ports=$(echo "$rule" | jq -r '.ports // []')
            if [[ -n "$ports" ]] && [[ "$ports" != "[]" ]]; then
                local port_parts=()
                local port_count=$(echo "$ports" | jq 'length')
                
                for ((k=0; k<port_count; k++)); do
                    local port_obj=$(echo "$ports" | jq ".[$k]")
                    local formatted_port=$(format_port "$port_obj" "$dest_namespace" "$dest_pod_selector" "$use_kubectl")
                    port_parts+=("$formatted_port")
                done
                
                if [[ ${#port_parts[@]} -gt 0 ]]; then
                    parts+=("Ports: $(IFS=', '; echo "${port_parts[*]}")")
                fi
            fi
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

# Determine which columns to show
SHOW_INGRESS=true
SHOW_EGRESS=true
if [[ -n "$POLICY_TYPE_FILTER" ]]; then
    if [[ "$POLICY_TYPE_FILTER" == "ingress" ]]; then
        SHOW_EGRESS=false
    else
        SHOW_INGRESS=false
    fi
fi

# Generate table data
if [[ "$OUTPUT_FORMAT" == "csv" ]]; then
    # CSV header
    HEADER="Namespace,Policy Name,Pod Selector,Types"
    if [[ "$SHOW_INGRESS" == "true" ]]; then
        HEADER+=",Ingress Rules"
    fi
    if [[ "$SHOW_EGRESS" == "true" ]]; then
        HEADER+=",Egress Rules"
    fi
    echo "$HEADER"
    
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
        
        # Filter policies based on policy_type_filter
        if [[ -n "$POLICY_TYPE_FILTER" ]]; then
            if [[ "$POLICY_TYPE_FILTER" == "ingress" ]] && [[ "$has_ingress_type" != "true" ]]; then
                continue  # Skip policies without ingress
            fi
            if [[ "$POLICY_TYPE_FILTER" == "egress" ]] && [[ "$has_egress_type" != "true" ]]; then
                continue  # Skip policies without egress
            fi
        fi
        
        # Update types string based on filter - if filtering, only show the filtered type
        if [[ -n "$POLICY_TYPE_FILTER" ]]; then
            if [[ "$POLICY_TYPE_FILTER" == "ingress" ]] && [[ "$has_ingress_type" == "true" ]]; then
                types="Ingress"
            elif [[ "$POLICY_TYPE_FILTER" == "egress" ]] && [[ "$has_egress_type" == "true" ]]; then
                types="Egress"
            else
                types="None"
            fi
        fi
        
        # Get pod selector for port resolution
        policy_pod_selector=$(echo "$spec" | jq -c '.podSelector // {}')
        
        # Build CSV row
        ROW="$ns,$name,\"$selector\",$types"
        
        # Format for CSV - simpler format
        if [[ "$SHOW_INGRESS" == "true" ]]; then
            ingress_str=""
            if [[ "$has_ingress_type" == "false" ]]; then
                ingress_str="N/A"
            elif [[ "$ingress_count" == "0" ]]; then
                ingress_str="Deny all (default - no rules)"
            else
                # Format ingress rules with port resolution
                ingress_formatted=""
                ingress_rule_count=$(echo "$ingress_rules" | jq 'length')
                for ((ir=0; ir<ingress_rule_count; ir++)); do
                    ingress_rule=$(echo "$ingress_rules" | jq ".[$ir]")
                    from_part=$(echo "$ingress_rule" | jq -r '.from // [] | map(if .podSelector then "Pods:\(.podSelector.matchLabels // {})" elif .namespaceSelector then "NS:\(.namespaceSelector.matchLabels // {})" elif .ipBlock then "IP:\(.ipBlock.cidr)" else "" end) | join(",")')
                    ports_part=$(echo "$ingress_rule" | jq -r '.ports // []')
                    port_strs=()
                    if [[ -n "$ports_part" ]] && [[ "$ports_part" != "[]" ]]; then
                        port_count=$(echo "$ports_part" | jq 'length')
                        for ((p=0; p<port_count; p++)); do
                            port_obj=$(echo "$ports_part" | jq ".[$p]")
                            formatted_port=$(format_port "$port_obj" "$ns" "$policy_pod_selector" "$USE_KUBECTL")
                            port_strs+=("$formatted_port")
                        done
                    fi
                    if [[ ${#port_strs[@]} -gt 0 ]]; then
                        ports_str=$(IFS=','; echo "${port_strs[*]}")
                    else
                        ports_str=""
                    fi
                    if [[ -n "$ingress_formatted" ]]; then
                        ingress_formatted+="; "
                    fi
                    ingress_formatted+="From: $from_part"
                    if [[ -n "$ports_str" ]]; then
                        ingress_formatted+=" | Ports: $ports_str"
                    fi
                done
                ingress_str="Deny all (default); Allowed: $ingress_formatted"
            fi
            ROW+=",\"$ingress_str\""
        fi
        
        if [[ "$SHOW_EGRESS" == "true" ]]; then
            egress_str=""
            if [[ "$has_egress_type" == "false" ]]; then
                egress_str="N/A"
            elif [[ "$egress_count" == "0" ]]; then
                egress_str="Deny all (default - no rules)"
            else
                # Format egress rules with port resolution
                egress_formatted=""
                egress_rule_count=$(echo "$egress_rules" | jq 'length')
                for ((er=0; er<egress_rule_count; er++)); do
                    egress_rule=$(echo "$egress_rules" | jq ".[$er]")
                    to_part=$(echo "$egress_rule" | jq -r '.to // [] | map(if .podSelector then "Pods:\(.podSelector.matchLabels // {})" elif .namespaceSelector then "NS:\(.namespaceSelector.matchLabels // {})" elif .ipBlock then "IP:\(.ipBlock.cidr)" else "" end) | join(",")')
                    ports_part=$(echo "$egress_rule" | jq -r '.ports // []')
                    
                    # Extract destination pod selector and namespace for port resolution
                    dest_pod_sel=""
                    dest_ns="$ns"
                    to_list=$(echo "$egress_rule" | jq -r '.to // []')
                    if [[ -n "$to_list" ]] && [[ "$to_list" != "[]" ]]; then
                        to_count=$(echo "$to_list" | jq 'length')
                        for ((t=0; t<to_count; t++)); do
                            dest=$(echo "$to_list" | jq ".[$t]")
                            if echo "$dest" | jq -e '.podSelector' > /dev/null 2>&1; then
                                if [[ -z "$dest_pod_sel" ]] || [[ "$dest_pod_sel" == "null" ]]; then
                                    dest_pod_sel=$(echo "$dest" | jq -c '.podSelector // {}')
                                fi
                            fi
                            if echo "$dest" | jq -e '.namespaceSelector' > /dev/null 2>&1; then
                                ns_sel_obj=$(echo "$dest" | jq -c '.namespaceSelector // {}')
                                match_labels=$(echo "$ns_sel_obj" | jq -r '.matchLabels // {}')
                                if echo "$match_labels" | jq -e '.["kubernetes.io/metadata.name"]' > /dev/null 2>&1; then
                                    dest_ns=$(echo "$match_labels" | jq -r '.["kubernetes.io/metadata.name"]')
                                elif echo "$match_labels" | jq -e '.name' > /dev/null 2>&1; then
                                    dest_ns=$(echo "$match_labels" | jq -r '.name')
                                fi
                            fi
                        done
                    fi
                    
                    port_strs=()
                    if [[ -n "$ports_part" ]] && [[ "$ports_part" != "[]" ]]; then
                        port_count=$(echo "$ports_part" | jq 'length')
                        for ((p=0; p<port_count; p++)); do
                            port_obj=$(echo "$ports_part" | jq ".[$p]")
                            formatted_port=$(format_port "$port_obj" "$dest_ns" "$dest_pod_sel" "$USE_KUBECTL")
                            port_strs+=("$formatted_port")
                        done
                    fi
                    if [[ ${#port_strs[@]} -gt 0 ]]; then
                        ports_str=$(IFS=','; echo "${port_strs[*]}")
                    else
                        ports_str=""
                    fi
                    if [[ -n "$egress_formatted" ]]; then
                        egress_formatted+="; "
                    fi
                    egress_formatted+="To: $to_part"
                    if [[ -n "$ports_str" ]]; then
                        egress_formatted+=" | Ports: $ports_str"
                    fi
                done
                egress_str="Deny all (default); Allowed: $egress_formatted"
            fi
            ROW+=",\"$egress_str\""
        fi
        
        echo "$ROW"
    done
else
    # Table output
    echo ""
    echo "=========================================================================================================="
    echo "NETWORK POLICIES OVERVIEW"
    echo "=========================================================================================================="
    
    # Show filter info if namespace or policy type specified
    FILTER_PARTS=()
    if [[ -n "$NAMESPACE" ]]; then
        FILTER_PARTS+=("namespace: $NAMESPACE")
    fi
    if [[ -n "$POLICY_TYPE_FILTER" ]]; then
        FILTER_PARTS+=("policy type: $POLICY_TYPE_FILTER")
    fi
    if [[ ${#FILTER_PARTS[@]} -gt 0 ]]; then
        echo ""
        echo "Filtered by: $(IFS=', '; echo "${FILTER_PARTS[*]}")"
    fi
    
    echo ""
    echo "NOTE: In OpenShift/Kubernetes, NetworkPolicies enforce 'deny all' by default."
    echo "      Only traffic matching the explicitly allowed rules below is permitted."
    echo ""
    echo "=========================================================================================================="
    echo ""
    
    # Build header row
    HEADER_ROW="%-20s %-30s %-30s %-15s"
    HEADER_VALUES=("NAMESPACE" "POLICY NAME" "POD SELECTOR" "TYPES")
    if [[ "$SHOW_INGRESS" == "true" ]]; then
        HEADER_ROW+=" %-50s"
        HEADER_VALUES+=("INGRESS RULES")
    fi
    if [[ "$SHOW_EGRESS" == "true" ]]; then
        HEADER_ROW+=" %-50s"
        HEADER_VALUES+=("EGRESS RULES")
    fi
    HEADER_ROW+="\n"
    
    printf "$HEADER_ROW" "${HEADER_VALUES[@]}"
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
        
        # Filter policies based on policy_type_filter
        if [[ -n "$POLICY_TYPE_FILTER" ]]; then
            if [[ "$POLICY_TYPE_FILTER" == "ingress" ]] && [[ "$has_ingress_type" != "true" ]]; then
                continue  # Skip policies without ingress
            fi
            if [[ "$POLICY_TYPE_FILTER" == "egress" ]] && [[ "$has_egress_type" != "true" ]]; then
                continue  # Skip policies without egress
            fi
        fi
        
        # Update types string based on filter - if filtering, only show the filtered type
        if [[ -n "$POLICY_TYPE_FILTER" ]]; then
            if [[ "$POLICY_TYPE_FILTER" == "ingress" ]] && [[ "$has_ingress_type" == "true" ]]; then
                types="Ingress"
            elif [[ "$POLICY_TYPE_FILTER" == "egress" ]] && [[ "$has_egress_type" == "true" ]]; then
                types="Egress"
            else
                types="None"
            fi
        fi
        
        # Get pod selector for port resolution (for ingress, use policy's podSelector)
        policy_pod_selector=$(echo "$spec" | jq -c '.podSelector // {}')
        
        # Build format string and values
        FORMAT_ROW="%-20s %-30s %-30s %-15s"
        ROW_VALUES=("$ns" "$name" "$selector" "$types")
        
        if [[ "$SHOW_INGRESS" == "true" ]]; then
            # For ingress, ports apply to pods selected by the policy's podSelector
            ingress_str=$(format_rules "$ingress_rules" "ingress" "$has_ingress_type" "$ns" "$policy_pod_selector" "$USE_KUBECTL")
            # Truncate long strings for display (but preserve first line)
            ingress_str=$(echo "$ingress_str" | head -n 3 | tr '\n' ' ' | sed 's/ $//')
            FORMAT_ROW+=" %-50s"
            ROW_VALUES+=("$ingress_str")
        fi
        
        if [[ "$SHOW_EGRESS" == "true" ]]; then
            # For egress, ports apply to destination pods (from "to" section)
            # We'll extract podSelector from each rule in format_rules
            egress_str=$(format_rules "$egress_rules" "egress" "$has_egress_type" "$ns" "" "$USE_KUBECTL")
            # Truncate long strings for display (but preserve first line)
            egress_str=$(echo "$egress_str" | head -n 3 | tr '\n' ' ' | sed 's/ $//')
            FORMAT_ROW+=" %-50s"
            ROW_VALUES+=("$egress_str")
        fi
        
        FORMAT_ROW+="\n"
        printf "$FORMAT_ROW" "${ROW_VALUES[@]}"
    done
    
    echo ""
    echo "Total policies: $POLICY_COUNT"
    echo ""
    echo "Legend:"
    echo "  [DENY ALL] Default - All traffic is blocked by default"
    echo "  [ALLOWED] - Only these explicitly allowed rules permit traffic"
fi
