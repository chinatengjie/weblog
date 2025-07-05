import re
import argparse
from collections import defaultdict
import os
import chardet
from datetime import datetime
from urllib.parse import urlparse

def detect_encoding(file_path):
    with open(file_path, 'rb') as f:
        rawdata = f.read(10000)
    result = chardet.detect(rawdata)
    return result['encoding'] or 'gbk'

def parse_log_line(line):
    pattern = r'''
        ^(\S+)\s+                        # IP地址
        .*?                              
        \[\d+/\w+/\d+:\d+:\d+:\d+ 
        \s+\S+\]\s+                      
        "(\w+)\s+([^?"\s]+)[^"]*"        # 请求方法和URL
        \s+(\d+)\s+                      # 状态码
        (\d+)\s+                         # 传输字节数
        "([^"]*)"\s+                     # Referer
        "([^"]*)"                         # User-Agent
    '''
    match = re.search(pattern, line, re.VERBOSE | re.IGNORECASE)
    if match:
        ip = match.group(1)
        method = match.group(2)
        url = match.group(3)
        status = match.group(4)
        bytes_str = match.group(5)
        referer = match.group(6)
        user_agent = match.group(7)
        
        # 简化URL，移除查询参数
        if '?' in url:
            url = url.split('?', 1)[0]
        
        return ip, bytes_str, user_agent, url, referer
    return (None,) * 5

def format_size(bytes_size):
    units = ['B', 'KB', 'MB', 'GB']
    for unit in units:
        if bytes_size < 1024 or unit == 'GB':
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.2f} TB"

def generate_filename(original_path, report_type, output_dir=None):
    base_name = os.path.splitext(os.path.basename(original_path))[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{base_name}_{timestamp}_{report_type}.txt"
    
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        return os.path.join(output_dir, filename)
    return filename

def analyze_log(log_path, mode):
    ua_stats = defaultdict(lambda: {'traffic': 0, 'requests': 0})
    ip_stats = defaultdict(
        lambda: {'traffic': 0, 'requests': 0, 'user_agents': defaultdict(int)}
    )
    url_stats = defaultdict(lambda: {'traffic': 0, 'requests': 0})
    referer_stats = defaultdict(lambda: {'traffic': 0, 'requests': 0})
    
    total_bytes = 0
    line_count = 0
    invalid_lines = 0
    encoding = detect_encoding(log_path)

    try:
        with open(log_path, 'r', encoding=encoding, errors='replace') as f:
            for line in f:
                line_count += 1
                line = line.strip()
                if not line:
                    continue

                ip, bytes_str, user_agent, url, referer = parse_log_line(line)
                if not all([ip, bytes_str, user_agent, url, referer]):
                    invalid_lines += 1
                    continue

                try:
                    bytes_transferred = int(bytes_str)
                except ValueError:
                    invalid_lines += 1
                    continue

                total_bytes += bytes_transferred

                if mode in ['ua', 'all']:
                    ua_stats[user_agent]['traffic'] += bytes_transferred
                    ua_stats[user_agent]['requests'] += 1

                if mode in ['ip', 'all']:
                    ip_stats[ip]['traffic'] += bytes_transferred
                    ip_stats[ip]['requests'] += 1
                    ip_stats[ip]['user_agents'][user_agent] += 1
                
                if mode in ['url', 'all']:
                    url_stats[url]['traffic'] += bytes_transferred
                    url_stats[url]['requests'] += 1
                
                if mode in ['referer', 'all']:
                    # 简化Referer，只保留域名
                    if referer != "-":
                        parsed = urlparse(referer)
                        referer = f"{parsed.scheme}://{parsed.netloc}"
                    referer_stats[referer]['traffic'] += bytes_transferred
                    referer_stats[referer]['requests'] += 1

        print(f"\n分析完成：{os.path.basename(log_path)}")
        print(f"文件编码: {encoding}")
        print(f"总流量: {format_size(total_bytes)}")
        print(f"有效日志: {line_count - invalid_lines} 行")
        print(f"异常日志: {invalid_lines} 行")

        return {
            'ua_stats': ua_stats,
            'ip_stats': ip_stats,
            'url_stats': url_stats,
            'referer_stats': referer_stats,
            'total_bytes': total_bytes,
            'line_count': line_count,
            'invalid_lines': invalid_lines
        }

    except Exception as e:
        print(f"分析失败: {str(e)}")
        exit(1)

def generate_ua_report(data, output_path, limit=None):
    sorted_ua = sorted(
        data['ua_stats'].items(),
        key=lambda x: x[1]['traffic'],
        reverse=True
    )
    
    if limit and limit > 0:
        sorted_ua = sorted_ua[:limit]

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("User-Agent流量报告\n")
        f.write("="*60 + "\n")
        f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总流量: {format_size(data['total_bytes'])}\n")  # 新增总流量显示
        f.write(f"显示条目: {len(sorted_ua)}/{len(data['ua_stats'])}\n")
        f.write(f"{'排名':<5}{'流量占比':<10}{'流量总量':<15}{'请求数':<10}User-Agent\n")
        f.write("-"*90 + "\n")
        
        for rank, (ua, stats) in enumerate(sorted_ua, 1):
            percent = stats['traffic'] / data['total_bytes'] * 100
            f.write(
                f"#{rank:<4} "
                f"{percent:>6.2f}%  "
                f"{format_size(stats['traffic']):<15} "
                f"{stats['requests']:<10} "
                f"{ua}\n"
            )

def generate_ip_report(data, output_path, limit=None):
    sorted_ips = sorted(
        data['ip_stats'].items(),
        key=lambda x: x[1]['traffic'],
        reverse=True
    )
    
    if limit and limit > 0:
        sorted_ips = sorted_ips[:limit]

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("IP地址流量报告\n")
        f.write("="*60 + "\n")
        f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总流量: {format_size(data['total_bytes'])}\n")  # 新增总流量显示
        f.write(f"显示条目: {len(sorted_ips)}/{len(data['ip_stats'])}\n")
        f.write(f"{'排名':<5}{'IP地址':<18}{'流量占比':<10}{'流量总量':<15}{'请求数':<10}主要User-Agent\n")
        f.write("-"*100 + "\n")
        
        for rank, (ip, stats) in enumerate(sorted_ips, 1):
            percent = stats['traffic'] / data['total_bytes'] * 100
            top_ua = sorted(
                stats['user_agents'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:3]
            ua_str = " | ".join([f"{k} ({v})" for k, v in top_ua])
            
            f.write(
                f"#{rank:<4} "
                f"{ip:<18} "
                f"{percent:>6.2f}%  "
                f"{format_size(stats['traffic']):<15} "
                f"{stats['requests']:<10} "
                f"{ua_str}\n"
            )

def generate_url_report(data, output_path, limit=None):
    sorted_urls = sorted(
        data['url_stats'].items(),
        key=lambda x: x[1]['traffic'],
        reverse=True
    )
    
    if limit and limit > 0:
        sorted_urls = sorted_urls[:limit]

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("URL访问统计报告\n")
        f.write("="*60 + "\n")
        f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总流量: {format_size(data['total_bytes'])}\n")  # 新增总流量显示
        f.write(f"显示条目: {len(sorted_urls)}/{len(data['url_stats'])}\n")
        f.write(f"{'排名':<5}{'流量占比':<10}{'流量总量':<15}{'请求数':<10}访问URL\n")
        f.write("-"*90 + "\n")
        
        for rank, (url, stats) in enumerate(sorted_urls, 1):
            percent = stats['traffic'] / data['total_bytes'] * 100
            f.write(
                f"#{rank:<4} "
                f"{percent:>6.2f}%  "
                f"{format_size(stats['traffic']):<15} "
                f"{stats['requests']:<10} "
                f"{url}\n"
            )

def generate_referer_report(data, output_path, limit=None):
    sorted_referers = sorted(
        data['referer_stats'].items(),
        key=lambda x: x[1]['traffic'],
        reverse=True
    )
    
    if limit and limit > 0:
        sorted_referers = sorted_referers[:limit]

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("来路(Referer)流量统计报告\n")
        f.write("="*60 + "\n")
        f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总流量: {format_size(data['total_bytes'])}\n")  # 新增总流量显示
        f.write(f"显示条目: {len(sorted_referers)}/{len(data['referer_stats'])}\n")
        f.write(f"{'排名':<5}{'流量占比':<10}{'流量总量':<15}{'请求数':<10}来源域名\n")
        f.write("-"*90 + "\n")
        
        for rank, (referer, stats) in enumerate(sorted_referers, 1):
            percent = stats['traffic'] / data['total_bytes'] * 100
            display_referer = referer if referer != "-" else "直接访问/无来源"
            f.write(
                f"#{rank:<4} "
                f"{percent:>6.2f}%  "
                f"{format_size(stats['traffic']):<15} "
                f"{stats['requests']:<10} "
                f"{display_referer}\n"
            )

def main():
    parser = argparse.ArgumentParser(description='网站日志分析工具')
    parser.add_argument('log_file', help='日志文件路径')
    parser.add_argument('-m', '--mode', choices=['ua', 'ip', 'url', 'referer', 'all'], default='all',
                      help='分析模式: ua=用户代理, ip=IP地址, url=访问URL, referer=来路统计, all=全部（默认）')
    parser.add_argument('-l', '--limit', type=int, default=0,
                      help='限制输出条目数量（默认输出全部）')
    parser.add_argument('-f', '--output-dir', type=str, 
                      help='指定输出目录（默认当前目录）')
    args = parser.parse_args()

    if args.limit < 0:
        print("错误：limit参数不能为负数")
        exit(1)

    analysis_data = analyze_log(args.log_file, args.mode)

    # 生成报告文件路径
    report_generators = {
        'ua': ('ua', generate_ua_report),
        'ip': ('ip', generate_ip_report),
        'url': ('url', generate_url_report),
        'referer': ('referer', generate_referer_report)
    }
    
    generated_reports = []
    
    for mode_key, (report_type, generator) in report_generators.items():
        if args.mode in [mode_key, 'all']:
            report_path = generate_filename(args.log_file, report_type, args.output_dir)
            generator(analysis_data, report_path, args.limit if args.limit > 0 else None)
            generated_reports.append((report_type, report_path))
    
    print("\n报告生成完成:")
    for report_type, report_path in generated_reports:
        print(f"  {report_type}报告: {os.path.abspath(report_path)}")

if __name__ == "__main__":
    main()
