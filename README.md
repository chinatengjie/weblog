# weblog
log日志流量分析工具

# 不指定目录（默认当前目录）
python log_analyzer.py app.log

# 指定输出到/var/reports目录
python log.py access.log -f /var/reports

# 混合使用参数
python log.py nginx.log -m ip -l 500 -f /var/reports
