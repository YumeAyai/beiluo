# Cilium + Envoy + Coraza WAF Gateway Helm Chart

This Helm chart deploys a complete WAF solution using Cilium, Envoy, and Coraza following the architecture described in the sequence diagram.

## Architecture Overview

The deployed system follows this architecture:

```
Client -> Cilium (L3/L4 Filtering) -> Envoy (L7 Proxy) -> Coraza (WAF) -> Application
```

## Features

- **L3/L4 Filtering**: Cilium provides eBPF-based network filtering
- **L7 Proxy**: Envoy acts as a Layer 7 proxy with TLS termination
- **WAF Protection**: Coraza provides Web Application Firewall functionality via WASM filter
- **Threat Analysis**: Automatic IP blocking based on attack patterns
- **TTL-based Blocking**: Automatic cleanup of expired policies

## Prerequisites

- Kubernetes 1.24+
- Cilium CNI installed and configured
- Loki for log aggregation (optional, if using threat analyzer)
- Helm 3+

## Installation

### Add the Cilium Helm repository:

```bash
helm repo add cilium https://helm.cilium.io/
helm repo update
```

### Install Cilium with Hubble (recommended):

```bash
helm install cilium cilium/cilium --version 1.15.0 \
  --namespace kube-system \
  --set hubble.enabled=true \
  --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}"
```

### Install the WAF Gateway:

```bash
helm install waf-gateway /workspace/charts/waf-gateway --namespace default
```

## Configuration

The following table lists the configurable parameters of the waf-gateway chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `wafGateway.replicaCount` | Number of WAF gateway replicas | `1` |
| `wafGateway.image.repository` | WAF gateway image repository | `envoyproxy/envoy-contrib` |
| `wafGateway.image.tag` | WAF gateway image tag | `v1.28-latest` |
| `wafGateway.service.type` | Type of service to expose WAF gateway | `LoadBalancer` |
| `wafGateway.service.ports.http` | HTTP port | `80` |
| `wafGateway.service.ports.https` | HTTPS port | `443` |
| `coraza.rules.engine` | Coraza rule engine mode (DetectionOnly or On) | `DetectionOnly` |
| `coraza.logLevel` | Coraza logging level | `INFO` |
| `threatAnalyzer.enabled` | Enable/disable threat analyzer | `true` |
| `threatAnalyzer.replicaCount` | Number of threat analyzer replicas | `1` |
| `threatAnalyzer.lokiUrl` | Loki URL for log queries | `http://loki:3100` |
| `threatAnalyzer.attackThreshold` | Number of attacks before blocking IP | `3` |

## Usage

After installation:

1. The WAF gateway will be accessible via the service load balancer
2. All traffic will be filtered through Cilium (L3/L4) then Envoy/Coraza (L7)
3. The threat analyzer will monitor for attack patterns and automatically block malicious IPs
4. Blocked IPs will be added to Cilium network policies with TTL-based cleanup

## Security Model

The system implements defense-in-depth:

- **L3/L4 Layer**: Cilium filters at the network level using eBPF
- **L7 Layer**: Coraza inspects HTTP traffic for application-layer attacks
- **Automatic Response**: Threat analyzer creates blocking policies for malicious IPs
- **TTL Management**: Expired policies are automatically cleaned up

## Monitoring

- WAF logs are aggregated by Loki (if configured)
- Hubble provides network visibility
- Threat analyzer logs can be monitored for blocked IP events

## Uninstallation

To uninstall the chart:

```bash
helm uninstall waf-gateway
```

This will remove all resources associated with the chart.