#!/usr/bin/env python3
"""
高级资产探活脚本 - Windows兼容版
支持多种探测方式，提高准确性
"""

import sys
import os
import platform
import time
import socket
import subprocess
import concurrent.futures
from datetime import datetime
import argparse
import ipaddress
import requests
import json
from typing import Dict, List, Tuple, Optional, Any
import re


# 颜色输出
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    END = '\033[0m'


def print_colored(text, color):
    """彩色打印"""
    if platform.system() == 'Windows':
        # Windows终端可能需要启用ANSI转义序列
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass
    print(f"{color}{text}{Colors.END}")


def print_status(host, status, details=""):
    """格式化输出状态"""
    status_map = {
        "alive": (f"[+] {host} 存活", Colors.GREEN),
        "dead": (f"[-] {host} 无响应", Colors.RED),
        "partial": (f"[*] {host} 部分响应", Colors.YELLOW),
        "error": (f"[!] {host} 错误", Colors.RED)
    }

    if status in status_map:
        text, color = status_map[status]
        if details:
            text += f" ({details})"
        print_colored(text, color)


def is_windows():
    """检查是否为Windows系统"""
    return platform.system().lower() == 'windows'


def is_admin():
    """检查是否为管理员权限"""
    try:
        if is_windows():
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False


def get_hostname(ip):
    """尝试获取主机名"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        try:
            hostname = socket.getfqdn(ip)
            if hostname != ip:
                return hostname
        except:
            pass
        return None


def ping_host_os(host, timeout=2, count=2):
    """
    使用系统ping命令
    """
    try:
        if is_windows():
            command = ['ping', '-n', str(count), '-w', str(timeout * 1000), host]
        else:
            command = ['ping', '-c', str(count), '-W', str(timeout), host]

        output = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout * count + 2,
            creationflags=subprocess.CREATE_NO_WINDOW if is_windows() else 0
        )

        output_str = output.stdout.decode('gbk' if is_windows() else 'utf-8', errors='ignore').lower()

        if is_windows():
            success_indicators = ['ttl=', 'bytes=', '来自', 'reply from']
            for indicator in success_indicators:
                if indicator in output_str and '请求超时' not in output_str:
                    return True
            return False
        else:
            return output.returncode == 0 and 'ttl=' in output_str

    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def check_tcp_port_simple(host, port, timeout=2):
    """简单的TCP端口检查"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                try:
                    s.send(b'\r\n\r\n')
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    return {'open': True, 'banner': banner[:200]}
                except:
                    return {'open': True, 'banner': ''}
            return {'open': False}
    except socket.timeout:
        return {'open': False, 'error': 'timeout'}
    except Exception as e:
        return {'open': False, 'error': str(e)}


def check_http_service_advanced(url, timeout=3):
    """
    增强的HTTP服务检测
    """
    result = {
        'alive': False,
        'status_code': None,
        'title': None,
        'server': None,
        'headers': {},
        'redirects': [],
        'technologies': []
    }

    schemes = ['http', 'https']
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Connection': 'close'
    }

    for scheme in schemes:
        try:
            if not url.startswith(('http://', 'https://')):
                test_url = f"{scheme}://{url}"
            else:
                test_url = url.replace('http://', f'{scheme}://') if scheme == 'https' else url

            session = requests.Session()
            session.headers.update(headers)

            response = session.get(
                test_url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                stream=False
            )

            result['alive'] = True
            result['status_code'] = response.status_code
            result['server'] = response.headers.get('Server', '')
            result['headers'] = dict(response.headers)
            result['title'] = extract_title(response.text)

            result['technologies'] = detect_technologies(response)

            if response.history:
                result['redirects'] = [resp.url for resp in response.history]

            result['content_length'] = len(response.content)

            break

        except requests.exceptions.SSLError:
            result['alive'] = True
            result['error'] = 'SSL Error'
            break
        except requests.exceptions.ConnectionError:
            continue
        except Exception:
            continue

    return result


def detect_technologies(response):
    """检测Web技术栈"""
    technologies = []

    server = response.headers.get('Server', '').lower()
    if 'apache' in server:
        technologies.append('Apache')
    elif 'nginx' in server:
        technologies.append('Nginx')
    elif 'iis' in server:
        technologies.append('IIS')

    powered_by = response.headers.get('X-Powered-By', '').lower()
    if 'php' in powered_by:
        technologies.append('PHP')
    elif 'asp.net' in powered_by:
        technologies.append('ASP.NET')

    content = response.text[:5000].lower()
    if '<meta name="generator" content="wordpress' in content:
        technologies.append('WordPress')
    elif 'jquery' in content:
        technologies.append('jQuery')
    elif 'bootstrap' in content:
        technologies.append('Bootstrap')
    elif 'react' in content or 'react-dom' in content:
        technologies.append('React')

    cookies = response.headers.get('Set-Cookie', '').lower()
    if 'laravel_session' in cookies:
        technologies.append('Laravel')
    elif 'django' in cookies:
        technologies.append('Django')

    return list(set(technologies))


def extract_title(html):
    """从HTML中提取标题"""
    try:
        html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)
        html = re.sub(r'<script.*?>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)

        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            title = re.sub(r'\s+', ' ', title)
            title = title.replace('\n', ' ').replace('\r', '')
            if len(title) > 100:
                title = title[:100] + "..."
            return title

        h1_match = re.search(r'<h1[^>]*>(.*?)</h1>', html, re.IGNORECASE | re.DOTALL)
        if h1_match:
            title = h1_match.group(1).strip()
            title = re.sub(r'<[^>]+>', '', title)
            if len(title) > 100:
                title = title[:100] + "..."
            return title

    except:
        pass
    return None


def multi_method_ping(host, timeout=2):
    """
    使用多种方法进行ping检测
    """
    results = {
        'os_ping': False,
        'tcp_ping': False,
        'dns_resolve': False,
        'final': False,
        'confidence': 0
    }

    methods_checked = 0
    methods_success = 0

    # 方法1：系统ping
    try:
        results['os_ping'] = ping_host_os(host, timeout)
        methods_checked += 1
        if results['os_ping']:
            methods_success += 1
    except:
        pass

    # 方法2：TCP端口ping
    common_ports = [80, 443, 22, 3389, 21, 23]
    for port in common_ports[:3]:
        try:
            result = check_tcp_port_simple(host, port, timeout=1)
            if result.get('open'):
                results['tcp_ping'] = True
                methods_checked += 1
                methods_success += 1
                break
        except:
            continue

    # 方法3：DNS解析
    try:
        if not host.replace('.', '').isdigit():
            socket.gethostbyname(host)
            results['dns_resolve'] = True
            methods_checked += 1
            methods_success += 1
    except:
        pass

    # 如果方法检查不足，增加一些检查
    if methods_checked < 2:
        for port in [135, 139, 445]:
            try:
                result = check_tcp_port_simple(host, port, timeout=1)
                if result.get('open'):
                    results['tcp_ping'] = True
                    methods_checked += 1
                    methods_success += 1
                    break
            except:
                continue

    results['final'] = results['os_ping'] or results['tcp_ping'] or results['dns_resolve']

    if methods_checked > 0:
        results['confidence'] = methods_success / methods_checked
    else:
        results['confidence'] = 0

    return results


def port_scan_comprehensive(host, ports, timeout=2):
    """
    综合端口扫描
    """
    results = {
        'tcp': {},
        'common_services': [],
        'top_ports': []
    }

    service_ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        135: 'RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1521: 'Oracle',
        1723: 'PPTP',
        2049: 'NFS',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        9200: 'Elasticsearch',
        27017: 'MongoDB',
        5985: 'WinRM',
        5986: 'WinRM-SSL'
    }

    if not ports:
        ports = list(service_ports.keys())

    for port in ports:
        try:
            result = check_tcp_port_simple(host, port, timeout)
            results['tcp'][port] = result

            if result.get('open'):
                service = service_ports.get(port, f'Unknown({port})')
                banner = result.get('banner', '')

                service_info = {
                    'port': port,
                    'service': service,
                    'banner': banner,
                    'protocol': 'tcp'
                }

                results['common_services'].append(service_info)

                if port in [80, 443, 22, 3389, 21, 23, 25, 53]:
                    results['top_ports'].append(service_info)

        except Exception as e:
            results['tcp'][port] = {'open': False, 'error': str(e)}

    return results


def scan_target(host, config):
    """
    扫描单个目标
    """
    start_time = time.time()

    results = {
        'target': host,
        'hostname': None,
        'ping_results': {},
        'port_scan': {},
        'http_info': {},
        'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'scan_duration': 0,
        'is_alive': False
    }

    try:
        results['hostname'] = get_hostname(host)

        if config.get('ping', True):
            results['ping_results'] = multi_method_ping(host, config.get('timeout', 2))
            results['is_alive'] = results['ping_results'].get('final', False)

        if config.get('ports'):
            port_results = port_scan_comprehensive(
                host,
                config['ports'],
                config.get('timeout', 2)
            )
            results['port_scan'] = port_results

            if port_results.get('common_services'):
                results['is_alive'] = True

        if config.get('http', False):
            http_results = check_http_service_advanced(host, config.get('timeout', 3))
            results['http_info'] = http_results

            if http_results.get('alive'):
                results['is_alive'] = True

        results['scan_duration'] = time.time() - start_time

    except Exception as e:
        results['error'] = str(e)

    return results


def display_scan_results(results, verbose=False):
    """显示扫描结果"""
    host = results['target']
    is_alive = results.get('is_alive', False)

    if is_alive:
        details = []

        ping_results = results.get('ping_results', {})
        if ping_results.get('final'):
            conf = ping_results.get('confidence', 0)
            methods = []
            if ping_results.get('os_ping'):
                methods.append('Ping')
            if ping_results.get('tcp_ping'):
                methods.append('TCP')
            if ping_results.get('dns_resolve'):
                methods.append('DNS')

            if methods:
                details.append(f"检测: {'+'.join(methods)} ({conf:.0%})")

        services = results.get('port_scan', {}).get('common_services', [])
        if services:
            details.append(f"端口: {len(services)}个")

        http_info = results.get('http_info', {})
        if http_info.get('alive'):
            details.append(f"HTTP: {http_info.get('status_code')}")

        print_status(host, "alive", ", ".join(details))

        if verbose:
            if results.get('hostname'):
                print_colored(f"    主机名: {results['hostname']}", Colors.CYAN)

            if services:
                print_colored("    开放端口:", Colors.BLUE)
                for service in services[:8]:
                    port_info = f"{service['port']}/tcp: {service['service']}"
                    if service.get('banner'):
                        banner = service['banner'].replace('\n', ' ').replace('\r', '')
                        if len(banner) > 50:
                            banner = banner[:50] + "..."
                        port_info += f" [{banner}]"
                    print_colored(f"      {port_info}", Colors.BLUE)

                if len(services) > 8:
                    print_colored(f"      ... 还有 {len(services) - 8} 个端口", Colors.BLUE)

            if http_info.get('alive'):
                print_colored("    HTTP服务:", Colors.YELLOW)
                print_colored(f"      状态码: {http_info.get('status_code')}", Colors.YELLOW)
                if http_info.get('title'):
                    print_colored(f"      标题: {http_info['title']}", Colors.YELLOW)
                if http_info.get('server'):
                    print_colored(f"      服务器: {http_info['server']}", Colors.YELLOW)
                if http_info.get('technologies'):
                    print_colored(f"      技术栈: {', '.join(http_info['technologies'])}", Colors.YELLOW)

            duration = results.get('scan_duration', 0)
            if duration > 0:
                print_colored(f"    扫描耗时: {duration:.2f}秒", Colors.MAGENTA)

    else:
        print_status(host, "dead")


def save_results_to_file(results_list, output_file, format='txt'):
    """保存扫描结果到文件"""
    try:
        if format == 'txt':
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write(f"{'资产探活扫描报告':^80}\n")
                f.write("=" * 80 + "\n")
                f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"扫描目标: {len(results_list)} 个\n")
                f.write(f"操作系统: {platform.system()} {platform.release()}\n")
                f.write("=" * 80 + "\n\n")

                alive_hosts = [r for r in results_list if r.get('is_alive', False)]
                f.write(f"[+] 存活主机 ({len(alive_hosts)}个)\n")
                f.write("-" * 80 + "\n")

                for result in alive_hosts:
                    f.write(f"\n目标: {result['target']}\n")

                    if result.get('hostname'):
                        f.write(f"主机名: {result['hostname']}\n")

                    ping = result.get('ping_results', {})
                    if ping.get('final'):
                        methods = []
                        if ping.get('os_ping'):
                            methods.append("系统Ping")
                        if ping.get('tcp_ping'):
                            methods.append("TCP端口")
                        if ping.get('dns_resolve'):
                            methods.append("DNS解析")
                        f.write(f"存活检测: {' + '.join(methods)} (可信度: {ping.get('confidence', 0):.0%})\n")

                    services = result.get('port_scan', {}).get('common_services', [])
                    if services:
                        f.write("开放端口:\n")
                        for service in services:
                            f.write(f"  {service['port']}/tcp: {service['service']}")
                            if service.get('banner'):
                                banner = service['banner'].replace('\n', ' ').replace('\r', '')
                                f.write(f" - {banner[:100]}")
                            f.write("\n")

                    http = result.get('http_info', {})
                    if http.get('alive'):
                        f.write(f"HTTP服务: 状态码 {http.get('status_code')}\n")
                        if http.get('title'):
                            f.write(f"  标题: {http['title']}\n")
                        if http.get('server'):
                            f.write(f"  服务器: {http['server']}\n")
                        if http.get('technologies'):
                            f.write(f"  技术栈: {', '.join(http['technologies'])}\n")

                    f.write(f"扫描耗时: {result.get('scan_duration', 0):.2f}秒\n")
                    f.write("-" * 40 + "\n")

                dead_hosts = [r for r in results_list if not r.get('is_alive', False)]
                if dead_hosts:
                    f.write(f"\n\n[-] 无响应主机 ({len(dead_hosts)}个)\n")
                    f.write("-" * 80 + "\n")
                    for i, result in enumerate(dead_hosts, 1):
                        f.write(f"{result['target']:<20}")
                        if i % 4 == 0:
                            f.write("\n")
                    f.write("\n")

        elif format == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results_list, f, indent=2, ensure_ascii=False)

        elif format == 'csv':
            import csv
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(
                    ['目标', '主机名', '存活状态', '可信度', '开放端口数', 'HTTP状态码', '服务器', '标题', '扫描时间'])

                for result in results_list:
                    ping = result.get('ping_results', {})
                    services = result.get('port_scan', {}).get('common_services', [])
                    http = result.get('http_info', {})

                    ports_count = len(services) if services else 0
                    alive_status = '存活' if result.get('is_alive') else '无响应'

                    writer.writerow([
                        result['target'],
                        result.get('hostname', ''),
                        alive_status,
                        f"{ping.get('confidence', 0):.2f}",
                        ports_count,
                        http.get('status_code', ''),
                        http.get('server', ''),
                        http.get('title', '') or '',
                        result['scan_time']
                    ])

        print_colored(f"\n[✓] 结果已保存到: {output_file}", Colors.GREEN)

    except Exception as e:
        print_colored(f"保存结果失败: {e}", Colors.RED)


def main():
    parser = argparse.ArgumentParser(
        description='高级资产探活扫描脚本 - Windows兼容版',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  python tanhuo.py 192.168.1.1
  python tanhuo.py 192.168.1.0/24 -p 80,443,3389
  python tanhuo.py -i targets.txt --full-scan -o results.json --json
  python tanhuo.py example.com --http -v
        '''
    )

    parser.add_argument('targets', nargs='*', help='目标IP/CIDR/域名')
    parser.add_argument('-i', '--input', help='从文件读取目标列表')
    parser.add_argument('-o', '--output', help='输出结果到文件')
    parser.add_argument('-p', '--ports', help='要扫描的端口 (如: 80,443,3389 或 1-100)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='并发线程数 (默认: 20)')
    parser.add_argument('-T', '--timeout', type=float, default=3, help='超时时间秒 (默认: 3)')
    parser.add_argument('--no-ping', action='store_true', help='禁用Ping检测')
    parser.add_argument('--http', action='store_true', help='启用HTTP检测')
    parser.add_argument('--full-scan', action='store_true', help='完整扫描模式')
    parser.add_argument('--json', action='store_true', help='输出JSON格式')
    parser.add_argument('--csv', action='store_true', help='输出CSV格式')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')

    args = parser.parse_args()

    # 检查权限
    if is_admin():
        print_colored("[*] 以管理员权限运行，可以使用更多探测方法", Colors.YELLOW)

    # 收集目标
    targets = set()

    # 从命令行参数添加目标
    for target in args.targets:
        target = target.strip()
        if not target:
            continue

        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                if network.num_addresses > 65536:
                    print_colored(f"[!] 网段 {target} 太大，将扫描前1024个地址", Colors.YELLOW)
                    for i, ip in enumerate(network.hosts()):
                        if i >= 1024:
                            break
                        targets.add(str(ip))
                else:
                    for ip in network.hosts():
                        targets.add(str(ip))
            except Exception as e:
                print_colored(f"[!] 无效的CIDR格式 {target}: {e}", Colors.YELLOW)
                targets.add(target)

        elif '-' in target and target.count('.') == 3:
            try:
                start_ip, end_part = target.split('-')
                if '.' in end_part:
                    end_ip = end_part
                else:
                    base = '.'.join(start_ip.split('.')[:-1])
                    end_ip = f"{base}.{end_part}"

                start = ipaddress.ip_address(start_ip)
                end = ipaddress.ip_address(end_ip)

                current = int(start)
                end_int = int(end)

                if end_int - current > 1024:
                    print_colored(f"[!] IP范围 {target} 太大，将扫描前1024个地址", Colors.YELLOW)
                    end_int = current + 1024

                while current <= end_int:
                    targets.add(str(ipaddress.ip_address(current)))
                    current += 1
            except Exception as e:
                print_colored(f"[!] 无效的IP范围 {target}: {e}", Colors.YELLOW)
                targets.add(target)
        else:
            targets.add(target)

    # 从文件读取目标
    if args.input:
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.add(line)
        except FileNotFoundError:
            print_colored(f"[!] 文件不存在: {args.input}", Colors.RED)
            return
        except Exception as e:
            print_colored(f"[!] 读取文件错误: {e}", Colors.RED)
            return

    if not targets:
        print_colored("[!] 未指定扫描目标", Colors.RED)
        parser.print_help()
        return

    # 解析端口
    ports = []
    if args.ports:
        try:
            if '-' in args.ports:
                start_port, end_port = map(int, args.ports.split('-'))
                if end_port - start_port > 1000:
                    print_colored(f"[!] 端口范围太大，将扫描前200个端口", Colors.YELLOW)
                    end_port = start_port + 200
                ports = list(range(start_port, end_port + 1))
            else:
                ports = [int(p.strip()) for p in args.ports.split(',')]
                if len(ports) > 200:
                    print_colored(f"[!] 端口数量太多，将扫描前200个端口", Colors.YELLOW)
                    ports = ports[:200]
        except Exception as e:
            print_colored(f"[!] 无效的端口格式: {e}", Colors.RED)
            return

    if args.full_scan and not ports:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 8080,
                 8443, 5985, 5986, 27017, 9200]

    # 配置扫描参数
    config = {
        'ping': not args.no_ping,
        'ports': ports if ports else None,
        'http': args.http or args.full_scan,
        'timeout': args.timeout,
        'full_scan': args.full_scan
    }

    # 显示配置信息
    print_colored("=" * 70, Colors.BLUE)
    print_colored("高级资产探活扫描 (Windows兼容版)", Colors.CYAN)
    print_colored("=" * 70, Colors.BLUE)
    print_colored(f"系统平台: {platform.system()} {platform.release()}", Colors.BLUE)
    print_colored(f"目标数量: {len(targets)}", Colors.BLUE)
    print_colored(f"并发线程: {args.threads}", Colors.BLUE)
    print_colored(f"超时时间: {args.timeout}秒", Colors.BLUE)

    if ports:
        port_count = len(ports)
        print_colored(f"扫描端口: {port_count}个", Colors.BLUE)

    if args.http or args.full_scan:
        print_colored(f"HTTP检测: 启用", Colors.BLUE)

    if args.full_scan:
        print_colored(f"完整扫描: 启用", Colors.GREEN)

    print_colored(f"管理员权限: {'是' if is_admin() else '否'}", Colors.YELLOW)
    print_colored("-" * 70, Colors.BLUE)

    # 扫描执行
    results = []
    start_time = time.time()

    max_threads = min(args.threads, 100)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_target = {
                executor.submit(scan_target, target, config): target
                for target in targets
            }

            completed = 0
            total_targets = len(targets)

            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result(timeout=config['timeout'] * 15)
                    results.append(result)
                    display_scan_results(result, args.verbose)

                    completed += 1

                    if completed % 10 == 0 or completed == total_targets:
                        elapsed = time.time() - start_time
                        progress = (completed / total_targets) * 100
                        remaining_time = (elapsed / completed) * (total_targets - completed) if completed > 0 else 0
                        print_colored(
                            f"进度: {completed}/{total_targets} ({progress:.1f}%) | 用时: {elapsed:.1f}s | 预计剩余: {remaining_time:.1f}s",
                            Colors.CYAN)

                except concurrent.futures.TimeoutError:
                    print_colored(f"[!] 扫描 {target} 超时", Colors.RED)
                    results.append({
                        'target': target,
                        'error': '扫描超时',
                        'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'is_alive': False
                    })
                except Exception as e:
                    print_colored(f"[!] 扫描 {target} 时出错: {e}", Colors.RED)
                    results.append({
                        'target': target,
                        'error': str(e),
                        'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'is_alive': False
                    })

    except KeyboardInterrupt:
        print_colored("\n[!] 扫描被用户中断", Colors.YELLOW)
        if results:
            print_colored(f"[*] 已扫描 {len(results)} 个目标", Colors.YELLOW)

    # 统计信息
    end_time = time.time()
    total_time = end_time - start_time

    alive_count = sum(1 for r in results if r.get('is_alive', False))

    print_colored("\n" + "=" * 70, Colors.GREEN)
    print_colored("扫描完成!", Colors.GREEN)
    print_colored("=" * 70, Colors.GREEN)
    print_colored(f"扫描统计:", Colors.CYAN)
    print_colored(f"  总目标数: {len(targets)}", Colors.CYAN)
    print_colored(f"  成功扫描: {len(results)}", Colors.CYAN)
    print_colored(f"  存活主机: {alive_count}", Colors.GREEN)
    print_colored(f"  无响应数: {len(results) - alive_count}", Colors.RED)
    print_colored(f"  总耗时: {total_time:.2f}秒", Colors.CYAN)
    print_colored(f"  平均时间: {total_time / len(results):.2f}秒/主机" if results else "  平均时间: N/A", Colors.CYAN)

    # 服务统计
    if alive_count > 0:
        service_counts = {}
        for result in results:
            if result.get('is_alive'):
                services = result.get('port_scan', {}).get('common_services', [])
                for service in services:
                    svc_name = service['service']
                    service_counts[svc_name] = service_counts.get(svc_name, 0) + 1

        if service_counts:
            print_colored(f"\n发现的服务分布:", Colors.YELLOW)
            top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            for service, count in top_services:
                print_colored(f"  {service}: {count}台主机", Colors.YELLOW)

    # 保存结果
    if args.output:
        if args.json:
            save_results_to_file(results, args.output, 'json')
        elif args.csv:
            save_results_to_file(results, args.output, 'csv')
        else:
            save_results_to_file(results, args.output, 'txt')
    elif args.json or args.csv:
        ext = 'json' if args.json else 'csv'
        default_file = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
        save_results_to_file(results, default_file, ext)

    print_colored("\n[*] 扫描结束", Colors.MAGENTA)


if __name__ == '__main__':
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        main()
    except KeyboardInterrupt:
        print_colored("\n\n扫描被用户中断", Colors.YELLOW)
        sys.exit(0)
    except Exception as e:
        print_colored(f"\n程序运行错误: {e}", Colors.RED)
        sys.exit(1)