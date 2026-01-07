# Cilium-based Passive WAF and Threat Detection System

## Overview
This project implements a cloud-native, passive WAF (Web Application Firewall) and threat detection system based on Cilium, Envoy, and Coraza. The system detects web attacks (SQL injection, XSS, etc.) without blocking traffic, but automatically blocks malicious IPs at the network layer using Cilium Network Policies.

## Architecture Components

### 1. Envoy Proxy with Coraza WASM Plugin (`deploy/waf-gateway.yaml`)
- Envoy acts as the ingress gateway
- Coraza WAF integrated as a WASM plugin
- Runs in DetectionOnly mode (logs attacks but doesn't block)
- Processes HTTP/HTTPS traffic and forwards to backend services

### 2. Coraza WAF Configuration (`deploy/coraza-config.yaml`)
- OWASP CRS 3.3 ruleset for comprehensive attack detection
- DetectionOnly mode to avoid impacting legitimate traffic
- Structured logging for audit trail
- JSON-formatted logs sent to stdout for collection

### 3. Log Collection with Loki (`deploy/coraza-config.yaml`)
- Coraza logs forwarded to Loki for aggregation
- Structured JSON logs with attack details
- Timestamps, source IPs, rule IDs, and attack vectors captured

### 4. Threat Analyzer (`deploy/threat-analyzer.yaml`)
- Python-based analyzer that monitors Loki logs
- Identifies high-risk IP addresses based on attack frequency
- Configurable thresholds (default: 3 attacks in 10 minutes)
- Creates Cilium Network Policies to block malicious IPs
- TTL-based blocking (default: 24 hours)

### 5. Cilium Network Policies (`deploy/cilium-network-policies.yaml`)
- Predefined policies for securing the WAF infrastructure
- Network policies that block traffic from identified malicious IPs
- Both ingress and egress blocking to prevent communication
- Proper RBAC configuration for policy creation

### 6. Automatic Cleanup (`deploy/cleanup-controller.yaml`)
- CronJob that periodically removes expired network policies
- Prevents accumulation of stale policies
- Maintains cluster security hygiene

### 7. Grafana Dashboard (`deploy/grafana-dashboard.json`)
- Real-time visualization of attack patterns
- Source IP identification
- Attack type distribution
- Blocked IP monitoring

## Deployment Instructions

### Prerequisites
- Kubernetes cluster (v1.24+)
- kubectl configured
- Helm (optional but recommended)

### Step 1: Install Cilium
```bash
helm repo add cilium https://helm.cilium.io/
helm install cilium cilium/cilium --version 1.15.0 \
  --namespace kube-system \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set operator.replicas=1
```

### Step 2: Install Loki Stack
```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm upgrade --install loki grafana/loki-stack \
  --set promtail.enabled=true \
  --set grafana.enabled=true
```

### Step 3: Deploy the WAF Components
```bash
kubectl apply -f deploy/coraza-config.yaml
kubectl apply -f deploy/waf-gateway.yaml
kubectl apply -f deploy/threat-analyzer.yaml
kubectl apply -f deploy/cleanup-controller.yaml
kubectl apply -f deploy/cilium-network-policies.yaml
```

### Step 4: Import Grafana Dashboard
- Access Grafana UI
- Import the dashboard from `deploy/grafana-dashboard.json`
- Configure Loki as the data source

## Features

### 1. Passive Detection
- All web attacks are logged without affecting legitimate traffic
- Business continuity maintained during security monitoring
- No false positive blocking issues

### 2. Automated Response
- High-frequency attack sources automatically blocked
- Network-level blocking prevents further attacks
- Self-managing security responses

### 3. TTL-Based Blocking
- Malicious IPs blocked for configurable duration (default 24 hours)
- Automatic unblocking prevents permanent lockouts
- Maintains security posture while allowing access restoration

### 4. Comprehensive Monitoring
- Real-time attack visualization
- Source IP reputation tracking
- Attack type analysis
- Blocked IP management

### 5. Scalable Architecture
- Cilium-based network policies scale with cluster size
- Distributed architecture handles high traffic loads
- Modular components for flexible deployment

## Security Considerations

### Network Policy Isolation
- Blocks both ingress and egress traffic from malicious IPs
- Applied at the network layer, bypassing application controls
- Efficient and low-latency enforcement

### RBAC and Least Privilege
- Dedicated service accounts for each component
- Minimal required permissions for policy creation
- Secure by default with no overly permissive access

### Logging and Auditing
- All blocked actions logged for compliance
- Attack vectors preserved for forensic analysis
- Timeline tracking of malicious activities

## Operational Guidelines

### Threshold Tuning
- Adjust `ATTACK_THRESHOLD` based on environment
- Monitor false positive rates and tune accordingly
- Consider traffic patterns during peak hours

### Performance Monitoring
- Monitor resource usage of threat analyzer
- Track policy creation rates
- Watch for any performance degradation

### Incident Response
- Blocked IPs are logged in Grafana dashboard
- Manual override available through kubectl
- Automatic restoration after TTL expiration

## Maintenance

### Policy Cleanup
- CronJob handles expired policy removal
- Regular monitoring ensures clean state
- Backup policies for critical services

### Update Process
- Components can be updated independently
- Backward compatibility maintained between versions
- Rolling updates supported for zero downtime

## Benefits

1. **Zero Business Impact**: Detection-only mode ensures no false positive blocks
2. **Automated Defense**: Self-managing threat response reduces manual overhead
3. **Network-Level Protection**: Cilium policies enforce blocking at kernel level
4. **Scalable Architecture**: Designed for production environments
5. **Comprehensive Coverage**: OWASP CRS ruleset covers known attack vectors
6. **Visual Analytics**: Real-time dashboards for security monitoring
7. **Self-Maintaining**: Automatic cleanup prevents policy bloat

This implementation provides a robust, cloud-native approach to web application security that balances protection with availability.
