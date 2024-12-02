from net.topo import MyTopo
from net.generator import Generator
from config.config import Config
from net.switch import CustomSwitch
import threading

def stop_switches(net, switch_names):
    for switch_name in switch_names:
        switch = net.get(switch_name)
        if switch:
            switch.stop()
        else:
            print(f"Switch {switch_name} not found.")

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

    switch_names = ['s1', 's2', 's3']
    stop_switches(net, switch_names)

    generator.check_results()
    

    net.stop()
