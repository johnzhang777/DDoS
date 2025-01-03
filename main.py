from net.topo import MyTopo
from net.generator import Generator
from config.config import Config
from log.log import LoggerConfig
import threading
import logging
import os

def stop_switches(net):
    count = {}
    for switch in net.switches:
        # if hasattr(switch, 'collector'):
        #     switch.collector.stop_capture()
        threading.Thread(target=switch.stop).start()
        # count[switch] = switch.stop()
    # print(count)

if __name__ == '__main__':

    log_file_path = './log/mininet.log'
    if os.path.exists(log_file_path):
        os.remove(log_file_path)
    
    
    # 初始化LoggerConfig类
    LoggerConfig(log_file='./log/mininet.log', level=logging.INFO, mode='w')

    # 获取logger实例
    logger = LoggerConfig.get_logger(__name__)

    topo = MyTopo()
    net = topo.run()
    generator = Generator(net)
    generator.check_results()

    if True:
        # 创建线程
        normal = threading.Thread(target=generator.normal)
        attack = threading.Thread(target=generator.attack)

        # 启动线程
        normal.start()
        attack.start()

        # 等待线程完成
        normal.join()
        attack.join()
    else:
        normal = threading.Thread(target=generator.normal)
        normal.start()
        normal.join()

    net.stop()
