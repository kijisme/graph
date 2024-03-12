
import os
import subprocess
from slither.slither import Slither
from graph.callGraphUtils import GESCPrinters

path = '/workspaces/graph/smartbugs/other/crypto_roulette.sol'
version = '0.4.19'
command = f"solc-select use {version}"
subprocess.run(command, shell=True)
slither = Slither(path)

dataset_dir = '/workspaces/graph'

def get_cg(file_item, list_sol_file_vul_info):

    # 获取solc版本信息
    version = file_item['version']
    # 设置为当前版本
    command = f"solc-select use {version}"
    subprocess.run(command, shell=True)
    # 获取文件路径
    sol_file_path = file_item['path']
    # 获取文件名称
    sol_file_name = file_item['name']
    # 使用slither解析
    slither = Slither(os.path.join(dataset_dir, sol_file_path))
    # 初始化call生成器类
    call_graph_printer = GESCPrinters(slither, None)
    # 生成call图
    all_contracts_call_graph = call_graph_printer.generate_call_graph(sol_file_name, list_sol_file_vul_info)
    