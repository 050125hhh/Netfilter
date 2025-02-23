# 导入所需库
from scapy.all import sniff, IP, TCP, UDP  # 用于捕获和分析网络流量
import pandas as pd  # 用于数据处理
import numpy as np  # 用于数值计算
from sklearn.ensemble import RandomForestClassifier  # 用于流量分类
from sklearn.model_selection import train_test_split  # 用于数据集划分
from sklearn.metrics import classification_report  # 用于模型评估
import subprocess  # 用于调用系统命令（如iptables）
import logging  # 用于日志记录
import threading  # 用于多线程实现实时检测
import time  # 用于时间控制
import joblib  # 用于模型持久化

# 流量捕获类
class TrafficCapture:
    def __init__(self, interface="eth0", max_packets=1000):
        self.interface = interface  # 网络接口
        self.max_packets = max_packets  # 最大捕获包数
        self.packets = []  # 存储捕获的数据包

    def capture(self):
        """捕获网络流量"""
        self.packets = sniff(iface=self.interface, count=self.max_packets)

    def extract_features(self):
        """提取流量特征"""
        features = []
        for packet in self.packets:
            if IP in packet:  # 只处理IP包
                feature = {
                    "src_ip": packet[IP].src,  # 源IP
                    "dst_ip": packet[IP].dst,  # 目标IP
                    "protocol": packet[IP].proto,  # 协议类型
                    "length": len(packet),  # 包长度
                    "timestamp": packet.time,  # 时间戳
                }
                if TCP in packet:  # 如果是TCP包
                    feature["src_port"] = packet[TCP].sport  # 源端口
                    feature["dst_port"] = packet[TCP].dport  # 目标端口
                elif UDP in packet:  # 如果是UDP包
                    feature["src_port"] = packet[UDP].sport  # 源端口
                    feature["dst_port"] = packet[UDP].dport  # 目标端口
                features.append(feature)
        return pd.DataFrame(features)  # 返回特征DataFrame


# 高级特征提取类
class AdvancedFeatureExtractor:
    def __init__(self, window_size=10):
        self.window_size = window_size  # 时间窗口大小

    def extract(self, features):
        """提取高级特征"""
        # 计算每个源IP的包速率
        features["packet_rate"] = features.groupby("src_ip")["timestamp"].transform(lambda x: x.diff().mean())
        # 计算每个源IP的字节速率
        features["byte_rate"] = features.groupby("src_ip")["length"].transform(lambda x: x.sum() / self.window_size)
        return features



# 流量分类类
class TrafficClassifier:
    def __init__(self, model=None):
        self.model = model or RandomForestClassifier()  # 默认使用随机森林分类器

    def train(self, features, labels):
        """训练分类模型"""
        X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2)  # 划分训练集和测试集
        self.model.fit(X_train, y_train)  # 训练模型
        y_pred = self.model.predict(X_test)  # 预测测试集
        print(classification_report(y_test, y_pred))  # 打印分类报告

    def predict(self, features):
        """预测流量类型"""
        return self.model.predict(features)  # 返回预测结果

# 流量拦截类
class TrafficInterceptor:
    def __init__(self):
        # 配置日志记录
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("traffic_intercept.log"),  # 记录到文件
                logging.StreamHandler()  # 打印到控制台
            ]
        )

    def block_ip(self, ip):
        """使用iptables封锁IP"""
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])  # 调用iptables封锁IP
        logging.warning(f"Blocked IP: {ip}")  # 记录封锁日志

    def log_event(self, message, level="info"):
        """记录日志"""
        if level == "info":
            logging.info(message)
        elif level == "warning":
            logging.warning(message)
        elif level == "error":
            logging.error(message)

# 实时流量监控类
class RealTimeTrafficMonitor:
    def __init__(self, interface="eth0", capture_duration=10, classifier=None, interceptor=None):
        self.interface = interface  # 网络接口
        self.capture_duration = capture_duration  # 捕获间隔时间
        self.classifier = classifier  # 分类器
        self.interceptor = interceptor  # 拦截器
        self.running = False  # 监控状态

    def start(self):
        """启动实时监控"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor)  # 创建监控线程
        self.monitor_thread.start()  # 启动线程

    def stop(self):
        """停止实时监控"""
        self.running = False
        self.monitor_thread.join()  # 等待线程结束

    def _monitor(self):
        """实时监控流量"""
        while self.running:
            capture = TrafficCapture(interface=self.interface, max_packets=100)  # 捕获流量
            capture.capture()
            features = capture.extract_features()  # 提取特征

            if not features.empty:
                predictions = self.classifier.predict(features)  # 预测流量类型
                for i, prediction in enumerate(predictions):
                    if prediction == 1:  # 恶意流量
                        src_ip = features.iloc[i]["src_ip"]
                        self.interceptor.block_ip(src_ip)  # 封锁IP
                        self.interceptor.log_event(f"Malicious traffic detected from {src_ip}")  # 记录日志

            time.sleep(self.capture_duration)  # 等待下一次捕获

# 主程序
if __name__ == "__main__":
    # 初始化分类器和拦截器
    classifier = TrafficClassifier()
    interceptor = TrafficInterceptor()

    # 插入bg的模型
    # classifier.model = joblib.load("traffic_classifier.pkl")

    # 启动实时监控
    monitor = RealTimeTrafficMonitor(interface="eth0", capture_duration=10, classifier=classifier, interceptor=interceptor)
    monitor.start()

    # 模拟运行一段时间
    time.sleep(60)

    # 停止监控
    monitor.stop()