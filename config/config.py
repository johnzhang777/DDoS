from config import *
import yaml
import os


class Config:
    def __init__(self):
        self.cnt = 0
        # 获取当前文件的绝对路径
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # 构建 config.yaml 文件的路径
        config_file_path = os.path.join(current_dir, 'config.yaml')

        # 读取 YAML 文件
        with open(config_file_path, 'r') as file:
            self.config = yaml.safe_load(file)
    
    def get_ip(self, host):
        ip = self.config.get('host_ip')
        # 如果host='hi', 返回Hi_IP
        return ip[host.upper() + '_IP']
    
    def get_port(self, port_name):
        port = self.config.get('port')
        return port[port_name.upper() + '_PORT']
    
    def get_setting(self, setting, level='default'):
        attack_setting = self.config.get('attack_settings').get(level.upper())
        return attack_setting[setting.upper()]
    
    
if __name__ == '__main__':

    config = Config()
    x = config.get_ip('h1')
    y = config.get_ip('h2')
    print(config.get_port('ftp'))
    print(config.get_setting('duration'))