from net.topo import MyTopo
from net.generator import Generator
from config.config import Config
import threading



if __name__ == '__main__':
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

    generator.check_results()
    

    net.stop()
