#!/usr/bin/env python3
"""
Network Policy Viewer for OpenShift/Kubernetes
Retrieves all network policies and displays them in a tabular format
showing ingress and egress traffic flows.
"""

import json
import subprocess
import sys
from typing import Dict, List, Any, Optional, Tuple
from tabulate import tabulate
import argparse


def run_oc_command(cmd: List[str]) -> Dict[str, Any]:
    """Execute oc/kubectl command and return JSON output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {' '.join(cmd)}", file=sys.stderr)
        print(f"Error: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
        sys.exit(1)


def format_selector(selector: Dict[str, str]) -> str:
    """Format a label selector into a readable string."""
    if not selector:
        return "All pods"
    labels = [f"{k}={v}" for k, v in selector.items()]
    return ", ".join(labels)


def format_namespace_selector(selector: Dict[str, Any]) -> str:
    """Format a namespace selector into a readable string."""
    if not selector:
        return "All namespaces"
    
    match_labels = selector.get("matchLabels", {})
    match_expressions = selector.get("matchExpressions", [])
    
    parts = []
    if match_labels:
        labels = [f"{k}={v}" for k, v in match_labels.items()]
        parts.extend(labels)
    
    if match_expressions:
        for expr in match_expressions:
            key = expr.get("key", "")
            operator = expr.get("operator", "")
            values = expr.get("values", [])
            if operator == "In":
                parts.append(f"{key} in ({', '.join(values)})")
            elif operator == "NotIn":
                parts.append(f"{key} not in ({', '.join(values)})")
            elif operator == "Exists":
                parts.append(f"{key} exists")
            elif operator == "DoesNotExist":
                parts.append(f"{key} !exists")
    
    return ", ".join(parts) if parts else "All namespaces"


def format_ip_block(ip_block: Dict[str, Any]) -> str:
    """Format an IP block into a readable string."""
    cidr = ip_block.get("cidr", "")
    except_list = ip_block.get("except", [])
    
    if except_list:
        return f"{cidr} (except: {', '.join(except_list)})"
    return cidr


def resolve_named_port(port_name: str, protocol: str, namespace: str, pod_selector: Optional[Dict[str, Any]] = None, use_kubectl: bool = False) -> Optional[int]:
    """Resolve a named port to its numeric value by querying pods.
    
    Args:
        port_name: Name of the port to resolve
        protocol: Protocol (TCP, UDP, SCTP)
        namespace: Namespace to search in
        pod_selector: Pod selector to filter pods
        use_kubectl: Whether to use kubectl instead of oc
    
    Returns:
        Port number if found, None otherwise
    """
    try:
        cmd = ["kubectl"] if use_kubectl else ["oc"]
        cmd.extend(["get", "pods", "-n", namespace, "-o", "json"])
        
        result = run_oc_command(cmd)
        pods = result.get("items", [])
        
        # Filter pods by selector if provided
        if pod_selector:
            match_labels = pod_selector.get("matchLabels", {})
            if match_labels:
                filtered_pods = []
                for pod in pods:
                    pod_labels = pod.get("metadata", {}).get("labels", {})
                    # Check if all selector labels match
                    if all(pod_labels.get(k) == v for k, v in match_labels.items()):
                        filtered_pods.append(pod)
                pods = filtered_pods
        
        # Search for the named port in all matching pods
        for pod in pods:
            containers = pod.get("spec", {}).get("containers", [])
            for container in containers:
                container_ports = container.get("ports", [])
                for cp in container_ports:
                    if cp.get("name") == port_name and cp.get("protocol", "TCP") == protocol:
                        return int(cp.get("containerPort", 0))
        
        return None
    except Exception:
        # If we can't resolve, return None
        return None


def format_port(port: Dict[str, Any], namespace: Optional[str] = None, pod_selector: Optional[Dict[str, Any]] = None, use_kubectl: bool = False) -> str:
    """Format a port specification into a readable string.
    
    Args:
        port: Port specification dictionary
        namespace: Namespace for resolving named ports
        pod_selector: Pod selector for resolving named ports
        use_kubectl: Whether to use kubectl instead of oc
    
    Returns:
        Formatted port string with resolved port numbers if named port was resolved
    """
    protocol = port.get("protocol", "TCP")
    port_num = port.get("port")
    end_port = port.get("endPort")
    
    # If port_num is a string (named port), try to resolve it
    if isinstance(port_num, str) and namespace:
        resolved_port = resolve_named_port(port_num, protocol, namespace, pod_selector, use_kubectl)
        if resolved_port:
            port_num = resolved_port
            # Format as "TCP:53 (dns)" to show both the resolved port and the name
            if end_port:
                return f"{protocol}:{port_num}-{end_port} ({port.get('port')})"
            return f"{protocol}:{port_num} ({port.get('port')})"
        else:
            # Couldn't resolve, show the name
            if end_port:
                return f"{protocol}:{port_num}-{end_port}"
            return f"{protocol}:{port_num}"
    
    if port_num:
        if end_port:
            return f"{protocol}:{port_num}-{end_port}"
        return f"{protocol}:{port_num}"
    return protocol


def format_ingress_rule(rule: Dict[str, Any], namespace: Optional[str] = None, policy_pod_selector: Optional[Dict[str, Any]] = None, use_kubectl: bool = False) -> str:
    """Format an ingress rule into a readable string.
    
    Args:
        rule: Ingress rule dictionary
        namespace: Namespace for resolving named ports (uses policy's namespace)
        policy_pod_selector: Policy's pod selector (for resolving named ports on target pods)
        use_kubectl: Whether to use kubectl instead of oc
    """
    parts = []
    
    # From (sources)
    from_list = rule.get("from", [])
    if not from_list:
        parts.append("All sources")
    else:
        source_parts = []
        for source in from_list:
            if "podSelector" in source:
                selector = format_selector(source["podSelector"].get("matchLabels", {}))
                source_parts.append(f"Pods: {selector}")
            if "namespaceSelector" in source:
                selector = format_namespace_selector(source["namespaceSelector"])
                source_parts.append(f"Namespaces: {selector}")
            if "ipBlock" in source:
                ip_block = format_ip_block(source["ipBlock"])
                source_parts.append(f"IPs: {ip_block}")
        parts.append(" | ".join(source_parts) if source_parts else "All sources")
    
    # Ports
    # For ingress, ports apply to the pods selected by the policy's podSelector
    ports = rule.get("ports", [])
    if ports:
        port_strs = [format_port(p, namespace, policy_pod_selector, use_kubectl) for p in ports]
        parts.append(f"Ports: {', '.join(port_strs)}")
    
    return " | ".join(parts)


def format_egress_rule(rule: Dict[str, Any], namespace: Optional[str] = None, policy_namespace: Optional[str] = None, use_kubectl: bool = False) -> str:
    """Format an egress rule into a readable string.
    
    Args:
        rule: Egress rule dictionary
        namespace: Destination namespace for resolving named ports (if known)
        policy_namespace: Policy's namespace (used as fallback for port resolution)
        use_kubectl: Whether to use kubectl instead of oc
    """
    parts = []
    
    # Initialize variables for port resolution
    dest_pod_selector = None
    dest_namespace = namespace or policy_namespace
    
    # To (destinations)
    to_list = rule.get("to", [])
    if not to_list:
        parts.append("All destinations")
    else:
        dest_parts = []
        
        for dest in to_list:
            if "podSelector" in dest:
                selector = format_selector(dest["podSelector"].get("matchLabels", {}))
                dest_parts.append(f"Pods: {selector}")
                # Use the first podSelector found for port resolution
                if dest_pod_selector is None:
                    dest_pod_selector = dest["podSelector"]
            if "namespaceSelector" in dest:
                selector = format_namespace_selector(dest["namespaceSelector"])
                dest_parts.append(f"Namespaces: {selector}")
                # Try to extract namespace from namespaceSelector if it uses matchLabels
                ns_selector = dest.get("namespaceSelector", {})
                match_labels = ns_selector.get("matchLabels", {})
                # Check if namespace is specified via kubernetes.io/metadata.name
                if "kubernetes.io/metadata.name" in match_labels:
                    dest_namespace = match_labels["kubernetes.io/metadata.name"]
                elif "name" in match_labels:
                    dest_namespace = match_labels["name"]
                else:
                    # Can't determine specific namespace, set to None
                    dest_namespace = None
            if "ipBlock" in dest:
                ip_block = format_ip_block(dest["ipBlock"])
                dest_parts.append(f"IPs: {ip_block}")
        parts.append(" | ".join(dest_parts) if dest_parts else "All destinations")
    
    # Ports
    # For egress, ports apply to the destination pods (from "to" section)
    ports = rule.get("ports", [])
    if ports:
        # Only try to resolve if we have a podSelector and a namespace
        port_strs = [format_port(p, dest_namespace, dest_pod_selector, use_kubectl) for p in ports]
        parts.append(f"Ports: {', '.join(port_strs)}")
    
    return " | ".join(parts)


def get_network_policies(namespaces: Optional[List[str]] = None, use_kubectl: bool = False) -> List[Dict[str, Any]]:
    """Retrieve all network policies from the cluster.
    
    Args:
        namespaces: List of namespaces to filter. If None or empty, gets all namespaces.
        use_kubectl: Whether to use kubectl instead of oc.
    
    Returns:
        List of network policy objects.
    """
    cmd = ["kubectl"] if use_kubectl else ["oc"]
    cmd.extend(["get", "networkpolicy", "-o", "json"])
    
    if namespaces and len(namespaces) == 1:
        # Single namespace - use -n flag
        cmd.extend(["-n", namespaces[0]])
    elif namespaces and len(namespaces) > 1:
        # Multiple namespaces - get all and filter
        cmd.append("--all-namespaces")
    else:
        # No namespace specified - get all
        cmd.append("--all-namespaces")
    
    result = run_oc_command(cmd)
    policies = result.get("items", [])
    
    # Filter by namespaces if multiple specified
    if namespaces and len(namespaces) > 1:
        namespace_set = set(namespaces)
        policies = [p for p in policies if p.get("metadata", {}).get("namespace") in namespace_set]
    
    return policies


def get_policy_types(policy: Dict[str, Any]) -> tuple:
    """Extract policy types (Ingress, Egress, or both).
    
    In Kubernetes/OpenShift, if a NetworkPolicy exists, it defaults to deny all
    for the specified policy types. Only explicitly allowed rules are permitted.
    """
    spec = policy.get("spec", {})
    types = spec.get("policyTypes", [])
    ingress_rules = spec.get("ingress", [])
    egress_rules = spec.get("egress", [])
    
    # If policyTypes is not specified, infer from existing rules
    if not types:
        has_ingress = len(ingress_rules) > 0
        has_egress = len(egress_rules) > 0
    else:
        has_ingress = "Ingress" in types
        has_egress = "Egress" in types
    
    return has_ingress, has_egress


def analyze_network_policies(namespaces: Optional[List[str]] = None, use_kubectl: bool = False, policy_type_filter: Optional[str] = None) -> Tuple[List[List[str]], List[str]]:
    """Analyze network policies and return tabular data.
    
    Args:
        namespaces: List of namespaces to filter. If None or empty, gets all namespaces.
        use_kubectl: Whether to use kubectl instead of oc.
        policy_type_filter: Filter by policy type - "ingress", "egress", or None for both.
    
    Returns:
        Tuple of (table_data, headers) where table_data is list of rows and headers is list of column names.
    """
    policies = get_network_policies(namespaces, use_kubectl)
    
    table_data = []
    
    # Determine which columns to include based on filter
    show_ingress = policy_type_filter is None or policy_type_filter.lower() == "ingress"
    show_egress = policy_type_filter is None or policy_type_filter.lower() == "egress"
    
    for policy in policies:
        metadata = policy.get("metadata", {})
        spec = policy.get("spec", {})
        
        name = metadata.get("name", "N/A")
        ns = metadata.get("namespace", "N/A")
        
        # Pod selector
        pod_selector = spec.get("podSelector", {})
        pod_labels = format_selector(pod_selector.get("matchLabels", {}))
        
        # Policy types
        has_ingress, has_egress = get_policy_types(policy)
        
        # Filter policies based on policy_type_filter
        if policy_type_filter:
            filter_lower = policy_type_filter.lower()
            if filter_lower == "ingress" and not has_ingress:
                continue  # Skip policies without ingress
            if filter_lower == "egress" and not has_egress:
                continue  # Skip policies without egress
        
        # Build policy types string - if filtering, only show the filtered type
        policy_types = []
        if policy_type_filter:
            # When filtering, only show the filtered type
            filter_lower = policy_type_filter.lower()
            if filter_lower == "ingress" and has_ingress:
                policy_types.append("Ingress")
            elif filter_lower == "egress" and has_egress:
                policy_types.append("Egress")
        else:
            # No filter - show all types the policy has
            if has_ingress:
                policy_types.append("Ingress")
            if has_egress:
                policy_types.append("Egress")
        types_str = ", ".join(policy_types) if policy_types else "None"
        
        row = [ns, name, pod_labels, types_str]
        
        # Ingress rules
        if show_ingress:
            ingress_rules = spec.get("ingress", [])
            if not has_ingress:
                ingress_str = "N/A (not applicable)"
            elif not ingress_rules:
                ingress_str = "🚫 Deny all (default - no rules specified)"
            else:
                # Show default deny, then list allowed rules
                # For ingress, ports apply to pods selected by the policy's podSelector
                ingress_parts = [format_ingress_rule(rule, ns, pod_selector, use_kubectl) for rule in ingress_rules]
                allowed_rules = "\n".join([f"  ✓ {part}" for part in ingress_parts])
                ingress_str = f"🚫 Deny all (default)\n✅ Allowed:\n{allowed_rules}"
            row.append(ingress_str)
        
        # Egress rules
        if show_egress:
            egress_rules = spec.get("egress", [])
            if not has_egress:
                egress_str = "N/A (not applicable)"
            elif not egress_rules:
                egress_str = "🚫 Deny all (default - no rules specified)"
            else:
                # Show default deny, then list allowed rules
                # For egress, ports apply to destination pods (from "to" section)
                egress_parts = [format_egress_rule(rule, None, ns, use_kubectl) for rule in egress_rules]
                allowed_rules = "\n".join([f"  ✓ {part}" for part in egress_parts])
                egress_str = f"🚫 Deny all (default)\n✅ Allowed:\n{allowed_rules}"
            row.append(egress_str)
        
        table_data.append(row)
    
    # Build headers based on what we're showing
    headers = ["Namespace", "Policy Name", "Pod Selector", "Types"]
    if show_ingress:
        headers.append("Ingress Rules")
    if show_egress:
        headers.append("Egress Rules")
    
    return table_data, headers


def main():
    parser = argparse.ArgumentParser(
        description="View all network policies in OpenShift/Kubernetes cluster",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # View all network policies in all namespaces
  %(prog)s

  # View network policies in a specific namespace
  %(prog)s -n my-namespace
  %(prog)s --namespace production

  # View policies in multiple namespaces (specify -n multiple times)
  %(prog)s -n production -n staging -n development

  # Use kubectl instead of oc
  %(prog)s --kubectl

  # Export to CSV
  %(prog)s --csv > policies.csv

  # Filter by namespace and export to CSV
  %(prog)s -n production --csv > production-policies.csv

  # Filter by policy type (ingress only)
  %(prog)s --type ingress

  # Filter by policy type (egress only) and export to CSV
  %(prog)s --type egress --csv > egress-policies.csv
        """
    )
    parser.add_argument(
        "-n", "--namespace",
        dest="namespace",
        metavar="NAMESPACE",
        help="Filter policies by namespace (default: all namespaces). Can be specified multiple times for multiple namespaces.",
        action="append"
    )
    parser.add_argument(
        "--kubectl",
        action="store_true",
        help="Use kubectl instead of oc"
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Output in CSV format"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )
    parser.add_argument(
        "--type",
        dest="policy_type",
        choices=["ingress", "egress"],
        metavar="TYPE",
        help="Filter by policy type: 'ingress' or 'egress' (default: show both)"
    )
    
    args = parser.parse_args()
    
    # Check if oc/kubectl is available
    cmd = "kubectl" if args.kubectl else "oc"
    try:
        subprocess.run([cmd, "version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"Error: {cmd} not found or not configured. Please ensure {cmd} is installed and configured.", file=sys.stderr)
        sys.exit(1)
    
    # Process namespace argument (can be list if specified multiple times)
    # If namespace was specified, args.namespace will be a list (even if single item)
    namespaces = args.namespace if args.namespace else None
    
    # Get network policies
    table_data, headers = analyze_network_policies(namespaces, args.kubectl, args.policy_type)
    
    if not table_data:
        if namespaces:
            ns_str = ", ".join(namespaces)
            type_str = f" with type '{args.policy_type}'" if args.policy_type else ""
            print(f"No network policies found in namespace(s): {ns_str}{type_str}")
        else:
            type_str = f" with type '{args.policy_type}'" if args.policy_type else ""
            print(f"No network policies found{type_str}.")
        return
    
    # Determine which columns to show (for tabulate maxcolwidths)
    show_ingress = args.policy_type is None or args.policy_type.lower() == "ingress"
    show_egress = args.policy_type is None or args.policy_type.lower() == "egress"
    
    # Show filter info if namespace or policy type specified
    filter_info = ""
    filter_parts = []
    if namespaces:
        # args.namespace is always a list when using action="append"
        ns_str = ", ".join(namespaces)
        if len(namespaces) == 1:
            filter_parts.append(f"namespace: {ns_str}")
        else:
            filter_parts.append(f"namespaces: {ns_str}")
    if args.policy_type:
        filter_parts.append(f"policy type: {args.policy_type}")
    if filter_parts:
        filter_info = f"\nFiltered by {', '.join(filter_parts)}\n"
    
    if args.json:
        # Output as JSON
        policies = get_network_policies(namespaces, args.kubectl)
        print(json.dumps(policies, indent=2))
    elif args.csv:
        # Output as CSV
        import csv
        writer = csv.writer(sys.stdout)
        writer.writerow(headers)
        writer.writerows(table_data)
    else:
        # Output as formatted table
        print("\n" + "="*120)
        print("NETWORK POLICIES OVERVIEW")
        print("="*120)
        if filter_info:
            print(filter_info)
        print("NOTE: In OpenShift/Kubernetes, NetworkPolicies enforce 'deny all' by default.")
        print("      Only traffic matching the explicitly allowed rules below is permitted.\n")
        print("="*120 + "\n")
        # Adjust maxcolwidths based on number of columns
        col_widths = [20, 25, 25, 10]
        if show_ingress:
            col_widths.append(50)
        if show_egress:
            col_widths.append(50)
        
        print(tabulate(
            table_data,
            headers=headers,
            tablefmt="grid",
            maxcolwidths=col_widths
        ))
        print(f"\nTotal policies: {len(table_data)}")
        print("\nLegend:")
        print("  🚫 Deny all (default) - All traffic is blocked by default")
        print("  ✅ Allowed - Only these explicitly allowed rules permit traffic")


if __name__ == "__main__":
    main()
