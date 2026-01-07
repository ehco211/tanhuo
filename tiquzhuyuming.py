#!/usr/bin/env python3
"""
增强版域名提取工具 - 保留子域名
支持多种输入格式和高级分析功能
支持IP地址提取和整理
"""

import re
from urllib.parse import urlparse
import sys
import os
from collections import Counter, defaultdict


class FullDomainExtractor:
    """完整域名提取器"""

    def __init__(self, keep_www=True, remove_ports=True,
                 remove_auth=True, normalize_case=False):
        """
        初始化提取器

        Args:
            keep_www: 是否保留www前缀
            remove_ports: 是否移除端口
            remove_auth: 是否移除认证信息(user:pass@)
            normalize_case: 是否将域名转为小写
        """
        self.keep_www = keep_www
        self.remove_ports = remove_ports
        self.remove_auth = remove_auth
        self.normalize_case = normalize_case

        # 域名验证正则
        self.domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
            r'[a-zA-Z]{2,}$'
        )

        # IP地址正则（IPv4）
        self.ipv4_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )

    def extract(self, url):
        """提取完整域名或IP地址"""
        if not url or not isinstance(url, str):
            return None

        url = url.strip()
        if not url:
            return None

        original_url = url

        # 首先检查是否是纯IP地址
        if self.ipv4_pattern.match(url):
            return url

        try:
            # 处理逗号分隔的多个IP地址
            if ',' in url and all(self.ipv4_pattern.match(ip.strip()) for ip in url.split(',')):
                # 如果是逗号分隔的IP地址，返回第一个IP（后续会在process_urls中处理所有）
                return url.split(',')[0].strip()

            # 1. 移除认证信息
            if self.remove_auth and '@' in url:
                url = url.split('@')[-1]

            # 2. 添加协议前缀以便解析
            if not re.match(r'^[a-zA-Z]+://', url):
                url = 'http://' + url

            # 3. 解析URL
            parsed = urlparse(url)
            domain = parsed.netloc

            # 4. 如果解析失败，尝试直接匹配
            if not domain:
                # 尝试从原始字符串中提取域名
                match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', original_url)
                if match:
                    domain = match.group(1)
                else:
                    # 尝试提取IP地址
                    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', original_url)
                    if match:
                        return match.group(1) if self.ipv4_pattern.match(match.group(1)) else None
                    return None

            # 5. 移除端口
            if self.remove_ports and ':' in domain:
                domain = domain.split(':')[0]

            # 6. 移除www前缀（如果需要）
            if not self.keep_www:
                domain = re.sub(r'^www\.', '', domain, flags=re.IGNORECASE)

            # 7. 标准化大小写
            if self.normalize_case:
                domain = domain.lower()

            # 8. 验证域名格式
            if self.domain_pattern.match(domain):
                return domain
            else:
                # 对于IP地址，返回原样
                if self.ipv4_pattern.match(domain):
                    return domain
                # 对于localhost
                if domain.lower() in ['localhost', '127.0.0.1']:
                    return domain

                return None

        except Exception as e:
            # 如果所有方法都失败，尝试简单提取
            match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', original_url)
            if match:
                return match.group(1)
            # 尝试提取IP地址
            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', original_url)
            if match and self.ipv4_pattern.match(match.group(1)):
                return match.group(1)
            return None


def process_urls(urls, extractor, verbose=False):
    """处理URL列表，支持逗号分隔的IP地址"""
    results = []
    errors = []

    for i, url in enumerate(urls, 1):
        if not url.strip():
            continue

        # 检查是否是逗号分隔的IP地址
        if ',' in url:
            ip_list = url.split(',')
            # 验证是否都是IP地址
            if all(extractor.ipv4_pattern.match(ip.strip()) for ip in ip_list):
                # 提取所有IP地址
                for ip in ip_list:
                    ip = ip.strip()
                    if extractor.ipv4_pattern.match(ip):
                        results.append(ip)
                        if verbose and i <= 10:
                            print(f"  [{i}] {url[:50]:<50} → {ip} (从逗号分隔列表)")
                continue

        # 正常处理单个URL
        domain = extractor.extract(url)

        if domain:
            results.append(domain)
            if verbose and i <= 10:
                print(f"  [{i}] {url[:50]:<50} → {domain}")
        else:
            errors.append(url)
            if verbose and i <= 10:
                print(f"  [{i}] {url[:50]:<50} → [无效URL]")

    return results, errors


def generate_report(domains, errors, input_file=None):
    """生成处理报告"""
    print(f"\n{'=' * 70}")
    print("域名和IP地址提取报告")
    print('=' * 70)

    if input_file:
        print(f"输入文件: {input_file}")

    print(f"总输入数: {len(domains) + len(errors)}")
    print(f"成功提取: {len(domains)}")
    print(f"无效URL:  {len(errors)}")

    if domains:
        print(f"\n统计摘要:")
        print("-" * 70)

        # 统计域名和IP
        domains_list = []
        ips_list = []

        for item in domains:
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', item):
                ips_list.append(item)
            else:
                domains_list.append(item)

        print(f"域名数量: {len(domains_list)}")
        print(f"IP地址数量: {len(ips_list)}")

        if domains_list:
            # 按域名部分数量统计
            level_stats = Counter()
            tld_stats = Counter()
            subdomain_stats = defaultdict(Counter)

            for domain in domains_list:
                parts = domain.split('.')
                level = len(parts)
                level_stats[level] += 1

                # 统计顶级域名
                if len(parts) >= 2:
                    tld = parts[-1]
                    tld_stats[tld] += 1

                # 统计常见子域名
                if len(parts) >= 3:
                    sub = parts[0].lower()
                    if sub in ['www', 'mail', 'ftp', 'blog', 'shop',
                               'api', 'mobile', 'test', 'dev', 'staging']:
                        subdomain_stats['common'][sub] += 1

            # 显示域名统计
            if domains_list:
                print(f"\n域名级别分布:")
                for level in sorted(level_stats.keys()):
                    count = level_stats[level]
                    pct = (count / len(domains_list)) * 100
                    print(f"  {level} 级域名: {count:>5} 个 ({pct:>5.1f}%)")

                # 显示顶级域名统计
                if tld_stats:
                    print(f"\n常见顶级域名 (前10):")
                    for tld, count in tld_stats.most_common(10):
                        pct = (count / len(domains_list)) * 100
                        print(f"  .{tld:<8} {count:>5} 个 ({pct:>5.1f}%)")

                # 显示常见子域名统计
                if subdomain_stats.get('common'):
                    print(f"\n常见子域名前缀:")
                    for sub, count in subdomain_stats['common'].most_common(10):
                        pct = (count / len(domains_list)) * 100
                        print(f"  {sub:<10} {count:>5} 个 ({pct:>5.1f}%)")

        if ips_list:
            print(f"\nIP地址统计:")
            # 按IP段统计
            ip_segments = Counter()
            for ip in ips_list:
                segment = '.'.join(ip.split('.')[:3]) + '.*'
                ip_segments[segment] += 1

            if ip_segments:
                print(f"常见IP段 (前10):")
                for segment, count in ip_segments.most_common(10):
                    pct = (count / len(ips_list)) * 100
                    print(f"  {segment:<15} {count:>5} 个 ({pct:>5.1f}%)")

        # 显示示例
        print(f"\n域名示例 (前10个):")
        print("-" * 70)
        domain_count = min(10, len(domains_list))
        for i, domain in enumerate(domains_list[:domain_count], 1):
            level = len(domain.split('.'))
            print(f"  {i:3}. [{level}] {domain}")

        print(f"\nIP地址示例 (前10个):")
        print("-" * 70)
        ip_count = min(10, len(ips_list))
        for i, ip in enumerate(ips_list[:ip_count], 1):
            print(f"  {i:3}. {ip}")

    if errors:
        print(f"\n无效URL示例 (前10个):")
        print("-" * 70)
        for i, error in enumerate(errors[:10], 1):
            print(f"  {i:3}. {error[:80]}")


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(
        description='提取完整域名和IP地址（保留所有子域名）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s urls.txt                      # 基本用法
  %(prog)s urls.txt -o domains.txt       # 保存结果
  %(prog)s urls.txt --no-www             # 移除www前缀
  %(prog)s urls.txt -d -s                # 去重并排序
  %(prog)s urls.txt -v                   # 详细输出
  %(prog)s urls.txt --format csv         # CSV格式输出

支持处理逗号分隔的IP地址，如: 180.169.38.49,192.168.100.66,31.0.6.78
        '''
    )

    parser.add_argument('input', help='输入文件路径')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--no-www', action='store_true', help='移除www前缀')
    parser.add_argument('-d', '--deduplicate', action='store_true',
                        help='去除重复域名/IP')
    parser.add_argument('-s', '--sort', action='store_true',
                        help='对结果排序')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='显示详细处理过程')
    parser.add_argument('--format', choices=['txt', 'csv', 'json'],
                        default='txt', help='输出格式')
    parser.add_argument('--lowercase', action='store_true',
                        help='将域名转为小写')
    parser.add_argument('--separate', action='store_true',
                        help='将域名和IP分别保存到不同文件')

    args = parser.parse_args()

    # 检查文件是否存在
    if not os.path.exists(args.input):
        print(f"错误: 文件 '{args.input}' 不存在")
        sys.exit(1)

    try:
        # 读取文件
        encodings = ['utf-8', 'gbk', 'gb2312', 'latin-1']
        content = None

        for encoding in encodings:
            try:
                with open(args.input, 'r', encoding=encoding) as f:
                    content = f.read()
                print(f"使用编码: {encoding}")
                break
            except UnicodeDecodeError:
                continue

        if content is None:
            print("错误: 无法解码文件")
            sys.exit(1)

        urls = [line.strip() for line in content.splitlines() if line.strip()]

        # 创建提取器
        extractor = FullDomainExtractor(
            keep_www=not args.no_www,
            normalize_case=args.lowercase
        )

        # 处理URL
        print(f"开始处理 {len(urls)} 个URL...")
        domains, errors = process_urls(urls, extractor, args.verbose)

        # 去重
        if args.deduplicate:
            original_count = len(domains)
            domains = list(dict.fromkeys(domains))  # 保持顺序
            print(f"去重: {original_count} → {len(domains)}")

        # 排序
        if args.sort:
            domains.sort()
            print("结果已排序")

        # 生成报告
        generate_report(domains, errors, args.input)

        # 保存结果
        if args.output:
            if args.separate:
                # 分别保存域名和IP
                domains_list = [d for d in domains if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', d)]
                ips_list = [d for d in domains if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', d)]

                # 保存域名
                if domains_list:
                    domain_file = os.path.splitext(args.output)[0] + '_domains.txt'
                    save_results(domains_list, domain_file, args.format)
                    print(f"\n域名已保存到: {domain_file} (共 {len(domains_list)} 个)")

                # 保存IP地址
                if ips_list:
                    ip_file = os.path.splitext(args.output)[0] + '_ips.txt'
                    save_results(ips_list, ip_file, args.format)
                    print(f"IP地址已保存到: {ip_file} (共 {len(ips_list)} 个)")
            else:
                # 保存所有结果
                save_results(domains, args.output, args.format)
                print(f"\n结果已保存到: {args.output} (格式: {args.format})")

        # 如果没有指定输出文件，打印到控制台
        elif domains and args.format == 'txt':
            print(f"\n提取的结果 (共 {len(domains)} 个):")
            print("-" * 70)
            for domain in domains:
                print(domain)

    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()


def save_results(items, output_file, format='txt'):
    """保存结果到文件"""
    try:
        if format == 'txt':
            with open(output_file, 'w', encoding='utf-8') as f:
                for item in items:
                    f.write(item + '\n')

        elif format == 'csv':
            import csv
            with open(output_file, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Type', 'Value'])
                for item in items:
                    item_type = 'IP' if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', item) else 'Domain'
                    writer.writerow([item_type, item])

        elif format == 'json':
            import json
            # 分离域名和IP
            domains = [d for d in items if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', d)]
            ips = [d for d in items if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', d)]

            data = {
                'total': len(items),
                'domains': {
                    'count': len(domains),
                    'list': domains
                },
                'ips': {
                    'count': len(ips),
                    'list': ips
                }
            }
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

    except Exception as e:
        print(f"保存文件时出错: {e}")


def batch_process():
    """批量处理模式"""
    import argparse

    parser = argparse.ArgumentParser(description='批量处理多个文件')
    parser.add_argument('input_dir', help='输入目录')
    parser.add_argument('-o', '--output_dir', help='输出目录')
    parser.add_argument('--pattern', default='*.txt', help='文件模式')

    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"错误: '{args.input_dir}' 不是目录")
        return

    # 查找文件
    import glob
    files = glob.glob(os.path.join(args.input_dir, args.pattern))

    if not files:
        print(f"没有找到匹配 {args.pattern} 的文件")
        return

    print(f"找到 {len(files)} 个文件:")
    for file in files:
        print(f"  {os.path.basename(file)}")

    # 处理每个文件
    extractor = FullDomainExtractor()

    for file in files:
        print(f"\n处理文件: {os.path.basename(file)}")

        try:
            with open(file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]

            domains, errors = process_urls(urls, extractor)
            domains = list(dict.fromkeys(domains))  # 去重

            print(f"  提取到 {len(domains)} 个域名/IP，{len(errors)} 个错误")

            # 保存结果
            if args.output_dir:
                os.makedirs(args.output_dir, exist_ok=True)
                output_file = os.path.join(
                    args.output_dir,
                    f"results_{os.path.basename(file)}"
                )
                with open(output_file, 'w', encoding='utf-8') as f:
                    for domain in domains:
                        f.write(domain + '\n')

        except Exception as e:
            print(f"  处理失败: {e}")


if __name__ == "__main__":
    # 如果没有参数，显示帮助
    if len(sys.argv) == 1:
        print("使用 --help 查看帮助信息")
        print("示例: python script.py urls.txt")
        print("支持处理逗号分隔的IP地址，如: 180.169.38.49,192.168.100.66,31.0.6.78")
        sys.exit(1)

    # 检查是否为批量处理模式
    if '--batch' in sys.argv:
        batch_process()
    else:
        main()