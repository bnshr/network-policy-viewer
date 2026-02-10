#!/usr/bin/env python3
"""
Analyze Network Policies for External Egress Communication
Identifies egress policies that allow communication outside the cluster.
"""

import json
import subprocess
import sys
import ipaddress
from typing import Dict, List, Any, Optional
from tabulate import tabulate
import argparse


def is_cluster_internal_cidr(cidr: str) -> bool:
    """Check if a CIDR is likely cluster-internal.
    
    Common cluster-internal ranges:
    - 10.0.0.0/8 (often used for pods/services)
    - 172.16.0.0/12 (often used for pods/services)
    - 192.168.0.0/16 (often used for pods/services)
    - 100.64.0.0/10 (often used for services)
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # Check if it's in common private/internal ranges
        private_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('100.64.0.0/10'),
        ]
        
        for private_range in private_ranges:
            if network.overlaps(private_range):
                return True
        
        # If it's a link-local or loopback, it's internal
        if network.is_link_local or network.is_loopback:
            return True
            
        return False
    except ValueError:
        return False


def has_external_egress(policy: Dict[str, Any]) -> tuple[bool, List[str]]:
    """Check if a policy has egress rules that allow external communication.
    
    Returns:
        (has_external, reasons) - Boolean and list of reasons why it's external
    """
    spec = policy.get("spec", {})
    egress_rules = spec.get("egress", [])
    policy_types = spec.get("policyTypes", [])
    
    # Check if egress is even applicable
    has_egress_type = "Egress" in policy_types or len(egress_rules) > 0
    
    if not has_egress_type:
        return False, []
    
    # If no egress rules, it's deny all (not external)
    if not egress_rules:
        return False, []
    
    reasons = []
    has_external = False
    
    for rule in egress_rules:
        to_list = rule.get("to", [])
        
        # If "to" is empty, it allows all destinations (external!)
        if not to_list:
            has_external = True
            reasons.append("Empty 'to' list - allows ALL destinations (including external)")
            continue
        
        for dest in to_list:
            # Check for IP blocks
            if "ipBlock" in dest:
                ip_block = dest.get("ipBlock", {})
                cidr = ip_block.get("cidr", "")
                
                if cidr:
                    if not is_cluster_internal_cidr(cidr):
                        has_external = True
                        reasons.append(f"External IP block: {cidr}")
                    else:
                        # Check exceptions - they might be external
                        except_list = ip_block.get("except", [])
                        for exc in except_list:
                            if not is_cluster_internal_cidr(exc):
                                has_external = True
                                reasons.append(f"IP block exception (external): {exc}")
            
            # If it's a podSelector or namespaceSelector, it's cluster-internal
            # (unless it's empty, which would be all pods/namespaces - still internal)
            if "podSelector" in dest or "namespaceSelector" in dest:
                # These are cluster-internal, but note them
                pass
    
    return has_external, reasons


def analyze_policies_for_external_egress(namespace: Optional[str] = None, use_kubectl: bool = False) -> List[Dict[str, Any]]:
    """Analyze network policies and identify those with external egress."""
    cmd = ["kubectl"] if use_kubectl else ["oc"]
    cmd.extend(["get", "networkpolicy", "-o", "json"])
    
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        policies_data = json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {' '.join(cmd)}", file=sys.stderr)
        print(f"Error: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
        sys.exit(1)
    
    policies = policies_data.get("items", [])
    external_egress_policies = []
    
    for policy in policies:
        has_external, reasons = has_external_egress(policy)
        
        if has_external:
            metadata = policy.get("metadata", {})
            spec = policy.get("spec", {})
            
            external_egress_policies.append({
                "namespace": metadata.get("namespace", "N/A"),
                "name": metadata.get("name", "N/A"),
                "pod_selector": spec.get("podSelector", {}).get("matchLabels", {}),
                "reasons": reasons,
                "egress_rules": spec.get("egress", [])
            })
    
    return external_egress_policies


def format_pod_selector(selector: Dict[str, str]) -> str:
    """Format pod selector labels."""
    if not selector:
        return "All pods"
    labels = [f"{k}={v}" for k, v in selector.items()]
    return ", ".join(labels)


def format_reasons(reasons: List[str]) -> str:
    """Format reasons for external egress."""
    if not reasons:
        return "N/A"
    return "\n".join([f"  • {r}" for r in reasons])


def main():
    parser = argparse.ArgumentParser(
        description="Analyze network policies for external egress communication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Find all policies with external egress
  %(prog)s

  # Filter by namespace
  %(prog)s -n production

  # Use kubectl instead of oc
  %(prog)s --kubectl

  # Export to JSON
  %(prog)s --json > external-egress.json
        """
    )
    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to filter policies (default: all namespaces)"
    )
    parser.add_argument(
        "--kubectl",
        action="store_true",
        help="Use kubectl instead of oc"
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
        print(f"Error: {cmd} not found or not configured.", file=sys.stderr)
        sys.exit(1)
    
    # Analyze policies
    external_policies = analyze_policies_for_external_egress(args.namespace, args.kubectl)
    
    if args.json:
        print(json.dumps(external_policies, indent=2))
        return
    
    if not external_policies:
        print("\n✅ No network policies found that allow external egress communication.")
        print("   All egress policies are restricted to cluster-internal traffic.\n")
        return
    
    # Format output
    print("\n" + "="*120)
    print("NETWORK POLICIES WITH EXTERNAL EGRESS COMMUNICATION")
    print("="*120)
    print("\n⚠️  WARNING: These policies allow communication outside the cluster!\n")
    
    table_data = []
    for policy in external_policies:
        table_data.append([
            policy["namespace"],
            policy["name"],
            format_pod_selector(policy["pod_selector"]),
            format_reasons(policy["reasons"])
        ])
    
    headers = ["Namespace", "Policy Name", "Pod Selector", "External Egress Reasons"]
    
    print(tabulate(
        table_data,
        headers=headers,
        tablefmt="grid",
        maxcolwidths=[20, 25, 30, 50]
    ))
    
    print(f"\n📊 Total policies with external egress: {len(external_policies)}")
    print("\n💡 Tips:")
    print("   - Review these policies to ensure external access is intentional")
    print("   - Consider restricting to specific external IPs/CIDRs when possible")
    print("   - Use DNS policies for external service access when appropriate\n")


if __name__ == "__main__":
    main()
