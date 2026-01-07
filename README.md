# beiluo

# 🛡️ Cloud-Native WAF & Threat Detection Prototype  
**基于 Cilium + Envoy + Coraza 的 Kubernetes 原生 WAF 原型（被动检测模式）**

> ✨ **2 周可落地 | 零业务侵入 | 自动封禁高危 IP | 开源全栈**

本项目实现了一个轻量级、安全、可观测的 **云原生 WAF 原型**，通过 **被动监听业务流量** 发现 Web 攻击（如 SQLi、XSS），**不拦截请求**（避免影响业务），自动分析威胁并封禁恶意 IP。  
**无需蜜罐，无需修改应用，完全基于 K8s 原生能力构建。**

---

## 🎯 核心能力

- ✅ **被动检测**：记录所有 Web 攻击尝试（SQL 注入、XSS、路径遍历等），**业务无感知**
- ✅ **自动响应**：高频攻击 IP 自动加入 Cilium 黑名单（24 小时）
- ✅ **可视化**：Grafana 实时展示攻击地图、Top 攻击类型、封禁列表
- ✅ **零新增攻击面**：不部署蜜罐，不暴露额外服务
- ✅ **开箱即用**：基于 OWASP CRS 3.3 规则集

---

## 🧱 技术栈

| 组件 | 作用 |
|------|------|
| **Cilium** | CNI + L3/L4 网络策略（自动封禁 IP）
| **Envoy** | L7 代理 + TLS 终止（Ingress Gateway）
| **Coraza** | WAF 引擎（以 WASM 插件运行于 Envoy）
| **Loki + Promtail** | 日志收集（Coraza 审计日志）
| **Grafana** | 威胁可视化仪表盘
| **Python 脚本** | 威胁分析器（自动封禁逻辑）

---

## 🚀 快速开始

### 前置要求
- Kubernetes 集群（v1.24+，推荐 [Kind](https://kind.sigs.k8s.io/) 或 Minikube）
- `kubectl`、`helm`（可选）
- 域名解析（或修改 `/etc/hosts`）

### 1. 安装 Cilium
```bash
helm repo add cilium https://helm.cilium.io/
helm install cilium cilium/cilium --version 1.15.0 \
  --namespace kube-system \
  --set hubble.enabled=true \
  --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}"
```

### 2. 部署 WAF 数据面（Envoy + Coraza）
```bash
kubectl apply -f deploy/waf-gateway.yaml
kubectl apply -f deploy/coraza-config.yaml
kubectl apply -f deploy/waf-deployment.yaml
```

### 3. 部署日志栈（Loki + Grafana）
```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm upgrade --install loki grafana/loki-stack \
  --set promtail.enabled=true \
  --set grafana.enabled=true
```

### 4. 部署威胁分析器
```bash
kubectl apply -f deploy/threat-analyzer.yaml
```

### 5. 配置 Ingress（示例）
```yaml
# 将你的业务指向 WAF Gateway
apiVersion: networking.k8s.io/v1
kind: Ingress
meta
  name: app-ingress
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: your-app-service
            port:
              number: 80
```

> 💡 **注意**：确保 `app.example.com` 解析到 Envoy Service 的 EXTERNAL-IP。

---

## 🔍 验证效果

### 1. 模拟一次 SQL 注入攻击
```bash
curl "https://app.example.com/login?id=1'%20OR%20'1'%3D'1"
```

### 2. 检查日志（应看到 Coraza 记录）
```bash
kubectl logs -l app=waf-gateway | grep "942100"
# 输出示例：{"timestamp":"...","src_ip":"1.2.3.4","rule_id":"942100","msg":"SQL Injection Attack"}
```

### 3. 查看 Grafana 仪表盘
- 访问 `http://<grafana-service>/d/waf-threats`
- 实时看到攻击事件、源 IP、攻击类型

### 4. 触发自动封禁（5 次攻击）
```bash
for i in {1..5}; do curl "https://app.example.com/?q=<script>alert(1)</script>"; done
```
- 检查 Cilium 策略：
  ```bash
  kubectl get cnp | grep deny-attackers
  ```

---

## 📂 目录结构

```
├── deploy/                  # K8s 部署文件
│   ├── waf-gateway.yaml     # Envoy + Coraza WASM 配置
│   ├── coraza-config.yaml   # Coraza 规则（OWASP CRS）
│   ├── threat-analyzer.yaml # 威胁分析器（Python）
│   └── grafana-dashboard.json
├── scripts/
│   └── test-attack.sh       # 攻击测试脚本
├── README.md
└── LICENSE
```

---

## ⚠️ 重要说明

- **默认为 DetectionOnly 模式**：WAF **只记录不拦截**，确保业务安全。
- **封禁策略带 TTL**：恶意 IP 封禁 24 小时后自动释放。
- **生产环境升级建议**：
  - 切换到 `Blocking` 模式（需充分测试）
  - 增加自定义规则（通过 ConfigMap）
  - 集成外部威胁情报（如 AbuseIPDB）

---

## 🤝 贡献与扩展

欢迎提交 Issue 或 PR！  
典型扩展方向：
- 支持 WAF 策略 CRD（`WafPolicy`）
- 集成 Slack/邮件告警
- 支持 Body（JSON/Form）深度检测

---

## 📜 许可证

Apache License 2.0

---

> **构建安全，从看见威胁开始。**  
> 本项目证明：**最好的防御，始于对真实流量的洞察。**