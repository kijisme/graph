import subprocess
import networkx as nx
from slither.slither import Slither

path = '/workspaces/graph/smartbugs/other/crypto_roulette.sol'
version = '0.4.19'
command = f"solc-select use {version}"
subprocess.run(command, shell=True)
slither = Slither(path)

def get_token(node):
    if node.expression:
        return str(node.expression)
    else:
        if node.type.name == 'VARIABLE':
            var = node.variable_declaration
            if var.initialized:
                return str(var.expression)
            else:   
                return ' '.join([str(var.type), var.name])
        else:
            return str(node.type)
for contract in slither.contracts:
    # 全局变量 var
    for var in contract.variables:
        print('Variable.State', var.visibility, var.name, str(var.type), var.source_mapping.lines)
    for function in contract.functions + contract.modifiers:
        # 函数节点func
        print(function.function_type, function.visibility, function.full_name, function.source_mapping.lines)
        # 局部变量 var
        for var in function.variables:
            print('Variable.Local', var.visibility, var.name, str(var.type), var.source_mapping.lines)
        for node in function.nodes:
            # 函数内部节点node
            token = get_token(node)
            print(str(node.type), node.node_id, token, node.source_mapping.lines)