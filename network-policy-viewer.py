#!/usr/bin/env python3
"""
Network Policy Viewer for OpenShift/Kubernetes
Retrieves all network policies and displays them in a tabular format
showing ingress and egress traffic flows.
"""

import json
import subprocess
import sys
from typing import Dict, List, Any, Optional
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


def format_port(port: Dict[str, Any]) -> str:
    """Format a port specification into a readable string."""
    protocol = port.get("protocol", "TCP")
    port_num = port.get("port")
    end_port = port.get("endPort")
    
    if port_num:
        if end_port:
            return f"{protocol}:{port_num}-{end_port}"
        return f"{protocol}:{port_num}"
    return protocol


def format_ingress_rule(rule: Dict[str, Any]) -> str:
    """Format an ingress rule into a readable string."""
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
    ports = rule.get("ports", [])
    if ports:
        port_strs = [format_port(p) for p in ports]
        parts.append(f"Ports: {', '.join(port_strs)}")
    
    return " | ".join(parts)


def format_egress_rule(rule: Dict[str, Any]) -> str:
    """Format an egress rule into a readable string."""
    parts = []
    
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
            if "namespaceSelector" in dest:
                selector = format_namespace_selector(dest["namespaceSelector"])
                dest_parts.append(f"Namespaces: {selector}")
            if "ipBlock" in dest:
                ip_block = format_ip_block(dest["ipBlock"])
                dest_parts.append(f"IPs: {ip_block}")
        parts.append(" | ".join(dest_parts) if dest_parts else "All destinations")
    
    # Ports
    ports = rule.get("ports", [])
    if ports:
        port_strs = [format_port(p) for p in ports]
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


def analyze_network_policies(namespaces: Optional[List[str]] = None, use_kubectl: bool = False) -> List[List[str]]:
    """Analyze network policies and return tabular data."""
    policies = get_network_policies(namespaces, use_kubectl)
    
    table_data = []
    
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
        policy_types = []
        if has_ingress:
            policy_types.append("Ingress")
        if has_egress:
            policy_types.append("Egress")
        types_str = ", ".join(policy_types) if policy_types else "None"
        
        # Ingress rules
        # In OpenShift/K8s: If policy exists with Ingress type, default is DENY ALL
        # Only explicitly allowed rules in the ingress array are permitted
        ingress_rules = spec.get("ingress", [])
        if not has_ingress:
            ingress_str = "N/A (not applicable)"
        elif not ingress_rules:
            ingress_str = "🚫 Deny all (default - no rules specified)"
        else:
            # Show default deny, then list allowed rules
            ingress_parts = [format_ingress_rule(rule) for rule in ingress_rules]
            allowed_rules = "\n".join([f"  ✓ {part}" for part in ingress_parts])
            ingress_str = f"🚫 Deny all (default)\n✅ Allowed:\n{allowed_rules}"
        
        # Egress rules
        # In OpenShift/K8s: If policy exists with Egress type, default is DENY ALL
        # Only explicitly allowed rules in the egress array are permitted
        egress_rules = spec.get("egress", [])
        if not has_egress:
            egress_str = "N/A (not applicable)"
        elif not egress_rules:
            egress_str = "🚫 Deny all (default - no rules specified)"
        else:
            # Show default deny, then list allowed rules
            egress_parts = [format_egress_rule(rule) for rule in egress_rules]
            allowed_rules = "\n".join([f"  ✓ {part}" for part in egress_parts])
            egress_str = f"🚫 Deny all (default)\n✅ Allowed:\n{allowed_rules}"
        
        table_data.append([
            ns,
            name,
            pod_labels,
            types_str,
            ingress_str,
            egress_str
        ])
    
    return table_data


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
    table_data = analyze_network_policies(namespaces, args.kubectl)
    
    if not table_data:
        if namespaces:
            ns_str = ", ".join(namespaces)
            print(f"No network policies found in namespace(s): {ns_str}")
        else:
            print("No network policies found.")
        return
    
    headers = ["Namespace", "Policy Name", "Pod Selector", "Types", "Ingress Rules", "Egress Rules"]
    
    # Show filter info if namespace specified
    filter_info = ""
    if namespaces:
        # args.namespace is always a list when using action="append"
        ns_str = ", ".join(namespaces)
        if len(namespaces) == 1:
            filter_info = f"\nFiltered by namespace: {ns_str}\n"
        else:
            filter_info = f"\nFiltered by namespaces: {ns_str}\n"
    
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
        print(tabulate(
            table_data,
            headers=headers,
            tablefmt="grid",
            maxcolwidths=[20, 25, 25, 10, 50, 50]
        ))
        print(f"\nTotal policies: {len(table_data)}")
        print("\nLegend:")
        print("  🚫 Deny all (default) - All traffic is blocked by default")
        print("  ✅ Allowed - Only these explicitly allowed rules permit traffic")


if __name__ == "__main__":
    main()
