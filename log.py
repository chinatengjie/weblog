import re
import argparse
from collections import defaultdict
import os
import chardet
from datetime import datetime

def detect_encoding(file_path):
    with open(file_path, 'rb') as f:
        rawdata = f.read(10000)
    result = chardet.detect(rawdata)
    return result['encoding'] or 'gbk'

def parse_log_line(line):
    pattern = r'''
        ^(\S+)\s+                
        .*?                      
        \[\d+/\w+/\d+:\d+:\d+:\d+ 
        .*?"\w+\s(?:http[^"]+)?   
        \sHTTP/\d\.\d"\s\d+\s     
        (\d+)\s+                  
        "[^"]*"\s+                
        "([^"]*)"                 
    '''
    match = re.search(pattern, line, re.VERBOSE | re.IGNORECASE)
    return match.groups() if match else (None, None, None)

def format_size(bytes_size):
    units = ['B', 'KB', 'MB', 'GB']
    for unit in units:
        if bytes_size < 1024 or unit == 'GB':
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.2f} TB"

def generate_filename(original_path, report_type, output_dir=None):
    # 生成基础文件名
    base_name = os.path.splitext(os.path.basename(original_path))[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{base_name}_{timestamp}_{report_type}.txt"
    
    # 处理输出目录
    if output_dir:
        # 创建目录（如果不存在）
        os.makedirs(output_dir, exist_ok=True)
        return os.path.join(output_dir, filename)
    return filename

def analyze_log(log_path, mode):
    ua_stats = defaultdict(lambda: {'traffic': 0, 'requests': 0})
    ip_stats = defaultdict(
        lambda: {'traffic': 0, 'requests': 0, 'user_agents': defaultdict(int)}
    )
    
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

                ip, bytes_str, user_agent = parse_log_line(line)
                if not all([ip, bytes_str, user_agent]):
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

        print(f"\n分析完成：{os.path.basename(log_path)}")
        print(f"文件编码: {encoding}")
        print(f"总流量: {format_size(total_bytes)}")
        print(f"有效日志: {line_count - invalid_lines} 行")
        print(f"异常日志: {invalid_lines} 行")

        return {
            'ua_stats': ua_stats,
            'ip_stats': ip_stats,
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
                #f"{ua[:80]}{'...' if len(ua)>80 else ''}\n"/# 截断逻辑
                f"{ua}\n"  # 移除了截断逻辑
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

def main():
    parser = argparse.ArgumentParser(description='网站日志分析工具')
    parser.add_argument('log_file', help='日志文件路径')
    parser.add_argument('-m', '--mode', choices=['ua', 'ip', 'all'], default='all',
                      help='分析模式: ua=用户代理, ip=IP地址, all=全部（默认）')
    parser.add_argument('-l', '--limit', type=int, default=0,
                      help='限制输出条目数量（默认输出全部）')
    parser.add_argument('-f', '--output-dir', type=str, 
                      help='指定输出目录（默认当前目录）')
    args = parser.parse_args()

    # 参数验证
    if args.limit < 0:
        print("错误：limit参数不能为负数")
        exit(1)

    analysis_data = analyze_log(args.log_file, args.mode)

    # 生成报告文件路径
    if args.mode in ['ua', 'all']:
        ua_path = generate_filename(args.log_file, "ua", args.output_dir)
        generate_ua_report(analysis_data, ua_path, args.limit if args.limit > 0 else None)
        print(f"\nUA报告已生成: {os.path.abspath(ua_path)}")

    if args.mode in ['ip', 'all']:
        ip_path = generate_filename(args.log_file, "ip", args.output_dir)
        generate_ip_report(analysis_data, ip_path, args.limit if args.limit > 0 else None)
        print(f"IP报告已生成: {os.path.abspath(ip_path)}")

if __name__ == "__main__":
    main()
