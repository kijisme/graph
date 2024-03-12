from copy import deepcopy
import os
import subprocess
import networkx as nx
from slither.slither import Slither
from slither.core.cfg.node import NodeType

# path = '/workspaces/graph/inherite.sol'
# version = '0.5.0'
# command = f"solc-select use {version}"
# subprocess.run(command, shell=True)
# slither = Slither(path)

dataset_dir = '/workspaces/graph'

def get_expression(node):
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

def get_vuln_of_node(node_code_lines, list_sol_file_vul_info):
    return None

def get_cfg(file_item, list_sol_file_vul_info):
    version = file_item['version']
    # 设置为当前版本
    command = f"solc-select use {version}"
    subprocess.run(command, shell=True)
    # 获取文件路径
    sol_file_path = file_item['path']
    # 获取文件名称
    sol_file_name = file_item['name']
    slither = Slither(os.path.join(dataset_dir, sol_file_path))
    # 全局文件图
    sol_file_graph = None
    for contract in slither.contracts:
        # 初始化合约图
        contract_name = contract.name
        contract_graph = nx.MultiDiGraph()
        # 添加全局变量节点
        for var in contract.variables:
            node_vuln_info = get_vuln_of_node(var.source_mapping.lines, list_sol_file_vul_info)
            contract_graph.add_node(var.name,
                                    node_token=f'{sol_file_name}_{contract_name}_{var.name}',
                                    node_type='Variable.State',
                                    node_expression=f'{var.visibility} {str(var.type)} {var.name}',
                                    node_code_lines=var.source_mapping.lines,
                                    node_vuln_info=node_vuln_info)
        # 全局变量使用字典
        state_variables_dict = {}

        for function in contract.functions + contract.modifiers:
            function_name = function.full_name
            # 添加函数节点
            node_vuln_info = get_vuln_of_node(function.source_mapping.lines, list_sol_file_vul_info)
            contract_graph.add_node(function_name,
                                    node_token=f'{sol_file_name}_{contract_name}_{function_name}',
                                    node_type=str(function.function_type),
                                    node_expression=f'{function.visibility} {str(function.function_type)} {function_name}',
                                    
                                    node_code_lines=function.source_mapping.lines,
                                    node_vuln_info=node_vuln_info)
            # 初始化函数图
            func_graph =  nx.MultiDiGraph()
            # 添加局部变量
            for var in function.variables:
                node_vuln_info = get_vuln_of_node(var.source_mapping.lines, list_sol_file_vul_info)
                func_graph.add_node(var.name,
                                    node_token=f'{function_name}_{var.name}',
                                    node_type='Variable.Local',
                                    node_expression=f'{var.visibility} {str(var.type)} {var.name}',
                                    node_code_lines=var.source_mapping.lines,
                                    node_vuln_info=node_vuln_info)
            
            for node in function.nodes:
                expression = get_expression(node)
                node_vuln_info = get_vuln_of_node(node.source_mapping.lines, list_sol_file_vul_info)
                func_graph.add_node(node.node_id,
                                    node_token=f'{str(node.type)}_{expression}',
                                    node_type=str(node.type),
                                    node_expression=expression,
                                    node_code_lines=node.source_mapping.lines,
                                    node_vuln_info=node_vuln_info)

                # 添加控制边
                if node.type in [NodeType.IF, NodeType.IFLOOP]:
                    true_node = node.son_true
                    if true_node:
                        if true_node.node_id not in func_graph.nodes():
                            # 获取节点信息
                            expression = get_expression(true_node)
                            node_vuln_info = get_vuln_of_node(true_node.source_mapping.lines, list_sol_file_vul_info)
                            # 添加节点    
                            func_graph.add_node(true_node.node_id,
                                                node_token=f'{str(true_node.type)}_{expression}',
                                                node_type=str(true_node.type),
                                                node_expression=expression,
                                                node_code_lines=true_node.source_mapping.lines,
                                                node_vuln_info=node_vuln_info)
                        # 添加边
                        func_graph.add_edge(node.node_id, 
                                            true_node.node_id,
                                            edge_type='if_true')

                    false_node = node.son_false
                    if false_node:
                        if false_node.node_id not in func_graph.nodes():
                        # 获取节点信息
                            expression = get_expression(false_node)
                            node_vuln_info = get_vuln_of_node(false_node.source_mapping.lines, list_sol_file_vul_info)
                            # 添加节点    
                            func_graph.add_node(false_node.node_id,
                                                node_token=f'{str(false_node.type)}_{expression}',
                                                node_type=str(false_node.type),
                                                node_expression=expression,
                                                node_code_lines=false_node.source_mapping.lines,
                                                node_vuln_info=node_vuln_info)
                        # 添加边
                        func_graph.add_edge(node.node_id, 
                                            false_node.node_id,
                                            edge_type='if_false')      
                # 添加顺序边
                else:
                    for son_node in node.sons:
                        if son_node.node_id not in func_graph.nodes():
                            # 获取节点信息
                            expression = get_expression(son_node)
                            node_vuln_info = get_vuln_of_node(son_node.source_mapping.lines, list_sol_file_vul_info)
                            # 添加节点    
                            func_graph.add_node(son_node.node_id,
                                                node_token=f'{str(son_node.type)}_{expression}',
                                                node_type=str(son_node.type),
                                                node_expression=expression,
                                                node_code_lines=son_node.source_mapping.lines,
                                                node_vuln_info=node_vuln_info)
                        # 添加边
                        func_graph.add_edge(node.node_id,
                                            son_node.node_id,
                                            edge_type='next')

                # 统计变量使用
                local_variables_use = set(node.local_variables_read + node.local_variables_written)
                state_variables_use = set(node.state_variables_read + node.state_variables_written)
                # 添加局部变量边
                if local_variables_use:
                    for var in local_variables_use:
                        func_graph.add_edge(var.name,
                                            node.node_id,
                                            edge_type='use')
                # 添加状态变量
                if state_variables_use:
                    for var in state_variables_use:
                        id = var.name
                        if id not in state_variables_dict:
                            state_variables_dict[id] = []
                        state_variables_dict[id].append(f'{function_name}_{node.node_id}')


            if len(func_graph.nodes) != 0:
                # 添加函数名称
                func_graph = nx.relabel_nodes(func_graph,  \
                            lambda x: f'{function_name}_{str(x)}', copy=False)

            # 合并图 func_graph->contract_graph
            if contract_graph is None:
                contract_graph = deepcopy(func_graph)
            else:
                contract_graph = nx.compose(contract_graph, func_graph)

            # 添加函数边
            if f'{function_name}_0' in contract_graph.nodes():
                contract_graph.add_edge(function_name, 
                                        f'{function_name}_0', 
                                        edge_type='next')
                

        # 添加全局变量边
        for state_varibale in state_variables_dict:
            for node_id in state_variables_dict[state_varibale]:
                contract_graph.add_edge(state_varibale,
                                        node_id,
                                        edge_type='use')
        # 添加合约名称
        if len(contract_graph.nodes) != 0:
            # 添加函数名称
            contract_graph = nx.relabel_nodes(contract_graph,  \
                        lambda x: f'{contract_name}_{str(x)}', copy=False)        

        if sol_file_graph is None:
            sol_file_graph = deepcopy(contract_graph)
        elif sol_file_graph is not None:
            sol_file_graph = nx.compose(sol_file_graph, contract_graph)    
    
    return sol_file_graph

if __name__ == "__main__":
    # /workspaces/graph/
    path = 'inherite.sol'
    name = 'inherite.sol'
    version = '0.5.0'

    file_item = {
        'path':path,
        'name':name,
        'version':version,
    }
    list_sol_file_vul_info = None
    cfg = get_cfg(file_item, list_sol_file_vul_info)
    nx.write_gpickle(cfg, os.path.join(dataset_dir, 'cfg.gpickle'))
    