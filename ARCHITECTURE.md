# Cilium + Envoy + Coraza Architecture Implementation

This document describes how the implemented architecture follows the sequence diagram provided in the requirements.

## Architecture Overview

The implemented architecture consists of three main components that process traffic in the following order:

1. **Cilium**: Handles L3/L4 filtering using eBPF
2. **Envoy**: Acts as L7 proxy with TLS termination
3. **Coraza**: Provides WAF functionality via WASM filter

## Sequence Diagram Implementation

### 1. Client → Cilium (L3/L4 Filtering)

The Cilium CNI plugin provides L3/L4 filtering using eBPF programs. This layer implements security policies such as:

- DDoS protection
- Port scan detection
- IP-based access controls
- Network policy enforcement

```yaml
# Example Cilium Network Policy
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: waf-ingress-protection
spec:
  endpointSelector:
    matchLabels:
      app: waf-gateway
  ingress:
  - fromEndpoints:
    - matchLabels:
        reserved: world
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
      - port: "443"
        protocol: TCP
```

### 2. Cilium → Envoy (Traffic Forwarding)

If traffic passes L3/L4 filtering, it's forwarded to the Envoy proxy which acts as an L7 gateway:

- Handles HTTP/HTTPS traffic
- Performs TLS termination for HTTPS connections
- Routes traffic to appropriate backends

### 3. Envoy → Coraza (WAF Processing)

The Envoy proxy invokes the Coraza WASM filter to apply WAF rules:

- Parses HTTP requests
- Applies OWASP Core Rule Set (CRS)
- Detects common attack patterns (SQLi, XSS, etc.)

### 4. Coraza → Response Handling

Based on WAF evaluation:

- **Blocked requests**: Return HTTP 403 Forbidden
- **Allowed requests**: Forward to backend application

## Configuration Details

### Envoy Configuration

The Envoy proxy is configured with:

- WASM filter for Coraza integration
- Router filter for traffic forwarding
- TLS termination capabilities
- Structured logging for audit trails

### Coraza Rules

The WAF engine uses:

- OWASP CRS 3.3 ruleset
- Detection-only mode (logs but doesn't block in passive mode)
- JSON-formatted audit logs
- Custom exclusion rules to reduce false positives

### Threat Analysis Component

The threat analyzer monitors:

- Coraza audit logs via Loki
- Identifies high-frequency attack sources
- Automatically creates Cilium network policies to block malicious IPs
- Implements TTL-based blocking with automatic cleanup

## Deployment Components

### 1. WAF Gateway (deploy/waf-gateway-full.yaml)

- Envoy proxy with Coraza WASM filter
- Service to expose the WAF gateway
- ConfigMaps for configuration

### 2. Cilium Policies (deploy/cilium-network-policies.yaml)

- Network policies for WAF infrastructure
- RBAC for policy management
- Default deny policies for enhanced security

### 3. Threat Analyzer (deploy/threat-analyzer.yaml)

- Monitors WAF logs
- Identifies malicious IPs
- Creates blocking policies
- Implements automatic cleanup

## Security Features

### L3/L4 Protection (Cilium)
- DDoS mitigation at network level
- IP reputation filtering
- Connection rate limiting
- Network segmentation

### L7 Protection (Coraza WAF)
- SQL injection detection
- Cross-site scripting (XSS) protection
- Path traversal prevention
- HTTP protocol validation

### Automated Response
- Real-time threat detection
- Automatic IP blocking
- TTL-based policy management
- Self-healing security policies

## Traffic Flow

The complete traffic flow follows the sequence diagram:

1. Client sends HTTP/HTTPS request
2. Cilium performs L3/L4 filtering (eBPF)
3. If allowed, traffic forwarded to Envoy
4. Envoy performs TLS termination (if HTTPS)
5. Envoy invokes Coraza WASM filter
6. Coraza parses HTTP and applies WAF rules
7. If blocked by WAF (SQLi, XSS, etc.), return 403
8. If allowed, forward to backend application
9. Response returned to client

This architecture provides defense in depth with multiple security layers while maintaining performance through eBPF acceleration and WASM-based processing.