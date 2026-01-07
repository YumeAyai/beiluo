#!/usr/bin/env python3
"""
被动WAF系统威胁分析器

该脚本监控Loki的WAF日志，并使用Cilium网络策略自动阻止高风险IP。
"""

import os
import time
import json
import logging
import requests
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict
import argparse

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    def __init__(self, config_file=None, loki_url=None, cilium_url=None,
                 attack_threshold=None, block_duration_hours=None, time_window_minutes=None):

        # 如果提供了配置文件，则从文件加载配置
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = {}
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"\'')
                        config[key] = value

            self.loki_url = loki_url or config.get('LOKI_URL', 'http://loki:3100')
            self.cilium_url = cilium_url or config.get('CILIUM_URL', 'http://cilium-operator:9963')
            self.attack_threshold = int(attack_threshold or config.get('ATTACK_THRESHOLD', '3'))
            self.block_duration_hours = int(block_duration_hours or config.get('BLOCK_DURATION_HOURS', '24'))
            self.time_window_minutes = int(time_window_minutes or config.get('TIME_WINDOW_MINUTES', '10'))
            self.query = config.get('LOKI_QUERY', '{app="coraza"} | json')
            self.blocked_namespace = config.get('BLOCKED_NAMESPACE', 'default')
            self.ignore_internal_ips = config.get('IGNORE_INTERNAL_IPS', 'True').lower() == 'true'
            self.trusted_ip_ranges = [r.strip() for r in config.get('TRUSTED_IP_RANGES', '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16').split(',')]
            self.debug = config.get('DEBUG', 'False').lower() == 'true'
        else:
            # 使用提供的参数或默认值
            self.loki_url = loki_url or os.getenv('LOKI_URL', 'http://loki:3100')
            self.cilium_url = cilium_url or os.getenv('CILIUM_URL', 'http://cilium-operator:9963')
            self.attack_threshold = int(attack_threshold or os.getenv('ATTACK_THRESHOLD', '3'))
            self.block_duration_hours = int(block_duration_hours or os.getenv('BLOCK_DURATION_HOURS', '24'))
            self.time_window_minutes = int(time_window_minutes or 10)
            self.query = '{app="coraza"} | json'
            self.blocked_namespace = 'default'
            self.ignore_internal_ips = True
            self.trusted_ip_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            self.debug = False

        self.blocked_ips = set()
        self.ip_attack_history = defaultdict(list)  # 存储每个IP的攻击时间戳
        self.last_query_time = datetime.utcnow() - timedelta(minutes=1)

        if self.debug:
            logging.getLogger().setLevel(logging.DEBUG)

    def query_loki(self):
        """查询Loki获取最近的WAF日志"""
        # 格式化查询时间范围
        start_time = self.last_query_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        end_time = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        # Loki查询参数
        params = {
            'query': self.query,
            'start': start_time,
            'end': end_time,
            'direction': 'forward',
            'limit': 1000
        }

        try:
            response = requests.get(f"{self.loki_url}/loki/api/v1/query_range", params=params)
            response.raise_for_status()

            data = response.json()
            logs = []

            if 'data' in data and 'result' in data['data']:
                for result in data['data']['result']:
                    if 'values' in result:
                        for timestamp_ns, log_line in result['values']:
                            try:
                                log_entry = json.loads(log_line)
                                logs.append(log_entry)
                            except json.JSONDecodeError:
                                logger.warning(f"Failed to parse log line: {log_line}")

            # 更新最后查询时间
            self.last_query_time = datetime.utcnow()
            return logs

        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying Loki: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error querying Loki: {e}")
            return []

    def extract_attack_info(self, log_entry):
        """从WAF日志条目中提取相关攻击信息"""
        try:
            # Coraza WAF日志中的常见字段
            client_ip = log_entry.get('client_ip', log_entry.get('src_ip', 'unknown'))
            rule_id = log_entry.get('rule_id', log_entry.get('id', 'unknown'))
            message = log_entry.get('message', log_entry.get('msg', ''))
            uri = log_entry.get('uri', log_entry.get('request_uri', ''))
            method = log_entry.get('method', log_entry.get('request_method', ''))

            return {
                'client_ip': client_ip,
                'rule_id': rule_id,
                'message': message,
                'uri': uri,
                'method': method,
                'timestamp': log_entry.get('timestamp', datetime.utcnow().isoformat())
            }
        except Exception as e:
            logger.error(f"Error extracting attack info: {e}")
            return None

    def is_trusted_ip(self, ip):
        """检查IP是否在信任范围内或是否为内部IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)

            # 检查是否为私有IP且我们应该忽略内部IP
            if self.ignore_internal_ips and ip_obj.is_private:
                return True

            # 检查是否在信任的IP范围内
            for trusted_range in self.trusted_ip_ranges:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(trusted_range, strict=False):
                    return True
        except ValueError:
            # 无效IP地址
            return True  # 将无效IP视为信任IP以避免误报

        return False

    def analyze_attacks(self, logs):
        """分析日志以识别高风险IP"""
        current_time = datetime.utcnow()

        for log in logs:
            attack_info = self.extract_attack_info(log)
            if attack_info and attack_info['client_ip'] != 'unknown':
                ip = attack_info['client_ip']

                # 跳过信任的IP
                if self.is_trusted_ip(ip):
                    if self.debug:
                        logger.debug(f"Skipping trusted IP: {ip}")
                    continue

                # 将时间戳添加到IP的攻击历史中
                self.ip_attack_history[ip].append(current_time)

        # 识别在时间窗口内超过阈值的IP
        high_risk_ips = {}
        time_threshold = datetime.utcnow() - timedelta(minutes=self.time_window_minutes)

        for ip, timestamps in self.ip_attack_history.items():
            # 过滤时间戳，只包含时间窗口内的
            recent_attacks = [t for t in timestamps if t >= time_threshold]

            # 仅使用最近的攻击更新历史
            self.ip_attack_history[ip] = recent_attacks

            # 检查IP是否超过阈值且尚未被阻止
            if len(recent_attacks) >= self.attack_threshold and ip not in self.blocked_ips:
                high_risk_ips[ip] = {
                    'attack_count': len(recent_attacks),
                    'first_seen': min(recent_attacks),
                    'last_seen': max(recent_attacks),
                    'recent_attacks': recent_attacks
                }

        return high_risk_ips

    def create_cilium_network_policy(self, ip):
        """Create a Cilium NetworkPolicy to block an IP"""
        policy_name = f"block-ip-{ip.replace('.', '-').replace(':', '-')}"

        policy = {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {
                "name": policy_name,
                "namespace": "default",  # You may want to make this configurable
                "labels": {
                    "auto-generated": "true",
                    "blocked-by": "threat-analyzer",
                    "blocked-at": datetime.utcnow().isoformat()
                }
            },
            "spec": {
                "description": f"Block IP {ip} due to suspicious activity detected by threat analyzer",
                "endpointSelector": {
                    "matchLabels": {}  # Apply to all endpoints, or make configurable
                },
                "ingress": [],
                "egress": [
                    {
                        "toCIDR": [f"{ip}/32"],
                        "toPorts": []  # Block all ports
                    }
                ],
                "ingressDeny": [
                    {
                        "fromCIDR": f"{ip}/32"
                    }
                ]
            }
        }

        return policy

    def block_ip_with_cilium(self, ip):
        """使用Cilium网络策略阻止IP"""
        try:
            policy = self.create_cilium_network_policy(ip)

            # 使用kubectl或直接通过Cilium API应用策略（如果可用）
            # 现在，我们使用kubectl命令
            import subprocess

            # 将策略写入临时文件
            policy_file = f"/tmp/cilium_policy_{ip.replace('.', '-').replace(':', '-')}.yaml"
            with open(policy_file, 'w') as f:
                json.dump(policy, f, indent=2)

            # 使用kubectl应用策略
            cmd = ['kubectl', 'apply', '-f', policy_file]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"Successfully blocked IP {ip} using Cilium Network Policy")
                self.blocked_ips.add(ip)

                # 清理临时文件
                os.remove(policy_file)

                # 如果可用，也尝试通过Cilium API应用
                try:
                    api_response = requests.put(
                        f"{self.cilium_url}/v2/ciliumnetworkpolicy",
                        json=policy,
                        headers={'Content-Type': 'application/json'}
                    )
                    if api_response.status_code not in [200, 201]:
                        logger.warning(f"Cilium API returned status {api_response.status_code}")
                except Exception as api_e:
                    logger.debug(f"Cilium API call failed (this is OK): {api_e}")

                return True
            else:
                logger.error(f"Failed to apply Cilium policy: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return False

    def run(self):
        """主执行循环"""
        logger.info("Starting threat analyzer...")
        logger.info(f"Monitoring Loki at {self.loki_url}")
        logger.info(f"Blocking via Cilium at {self.cilium_url}")
        logger.info(f"Threshold: {self.attack_threshold} attacks in time window")
        logger.info(f"Block duration: {self.block_duration_hours} hours")

        while True:
            try:
                # 查询Loki获取最近的WAF日志
                logs = self.query_loki()

                if logs:
                    logger.info(f"Found {len(logs)} WAF log entries to analyze")

                    # 分析日志以识别高风险IP
                    high_risk_ips = self.analyze_attacks(logs)

                    if high_risk_ips:
                        logger.info(f"Identified {len(high_risk_ips)} high-risk IPs to block")

                        for ip, details in high_risk_ips.items():
                            logger.info(f"Blocking IP {ip} - {details['attack_count']} attacks detected")
                            logger.info(f"First seen: {details['first_seen']}, Last seen: {details['last_seen']}")

                            if self.block_ip_with_cilium(ip):
                                logger.info(f"Successfully blocked {ip}")
                            else:
                                logger.error(f"Failed to block {ip}")
                    else:
                        logger.debug("No high-risk IPs found in this batch")
                else:
                    logger.debug("No new logs from Loki")

                # 等待下次查询
                time.sleep(30)  # 等待30秒再进行下次检查

            except KeyboardInterrupt:
                logger.info("Received interrupt signal, shutting down...")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(30)  # 等待后重试

def main():
    parser = argparse.ArgumentParser(description='被动WAF系统威胁分析器')
    parser.add_argument('--config',
                       default='threat-analyzer.conf',
                       help='配置文件路径（默认：threat-analyzer.conf）')
    parser.add_argument('--loki-url',
                       help='Loki URL')
    parser.add_argument('--cilium-url',
                       help='Cilium URL')
    parser.add_argument('--threshold',
                       type=int,
                       help='攻击阈值')
    parser.add_argument('--duration',
                       type=int,
                       help='阻止时长（小时）')
    parser.add_argument('--time-window',
                       type=int,
                       help='统计攻击的时间窗口（分钟）')

    args = parser.parse_args()

    analyzer = ThreatAnalyzer(
        config_file=args.config,
        loki_url=args.loki_url,
        cilium_url=args.cilium_url,
        attack_threshold=args.threshold,
        block_duration_hours=args.duration,
        time_window_minutes=args.time_window
    )

    analyzer.run()

if __name__ == "__main__":
    main()