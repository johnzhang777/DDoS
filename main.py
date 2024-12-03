from net.topo import MyTopo
from net.generator import Generator
from config.config import Config
import threading
import time
import nest_asyncio

def stop_switches(net):
    count = {}
    for switch in net.switches:
        # if hasattr(switch, 'collector'):
        #     switch.collector.stop_capture()
        threading.Thread(target=switch.stop).start()
        # count[switch] = switch.stop()
    # print(count)

if __name__ == '__main__':
    
    # nest_asyncio.apply()
    # 需要进入项目的目录执行main.py
    topo = MyTopo()
    net = topo.run()
    generator = Generator(net)
    generator.check_results()

    # 创建线程
    normal = threading.Thread(target=generator.normal)
    syn = threading.Thread(target=generator.syn_flood)

    # 启动线程
    normal.start()
    syn.start()

    # 等待线程完成
    normal.join()
    syn.join()

    # time.sleep(60)
    # stop_switches(net)

    net.stop()
