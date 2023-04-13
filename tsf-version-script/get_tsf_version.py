#!/usr/bin/env python
# -*- coding:utf-8 -*-

import urllib.request
import json
import configparser
import paramiko
import time
from datetime import datetime


def get_rsp():
    """请求tsf api。输入前置机ip地址。输出json格式数据"""
    url = 'http://127.0.0.1:17600/tsfModule/findModuleDetailList'
    headers = {'Content-Type': 'application/json'}
    data = {"regionId": "1", "serviceType": "tsfmanager", "parameterConfigType": "installInformation"}
    request = urllib.request.Request(url, headers=headers, data=json.dumps(data).encode("utf-8"), method="POST")
    response = urllib.request.urlopen(request, timeout=5)
    body = response.read().decode()
    resultObj = json.loads(body)['Result']
    return resultObj

def write_file(filename,content):
    with open(filename,'a') as f:
        f.write(content)
        f.write("\n")
        f.close()

def handle_rsp(resultObj):
    """ 处理tsf接口返回数据。输入：tsfapi返回数据，类型为json。输出：模块名称，对应运行状态的节点IP列表，类型为字典"""
    dict_module_instance = {}
#    with open(result, "r") as fp:
#        data = json.loads(fp)
#        fp.close()

    for module in resultObj:
        inst_ips = []
        module_name = module['moduleName']
#        print(module_name)
        for isinstance_detail in module['instances']:
            if isinstance_detail['status'] == "运行":
               inst_ips.append(isinstance_detail['ip'])
        dict_module_instance[module_name] = inst_ips

    for repo_serv_pkg in ['tsf-agent','consul-template','TencentCloudJvmMonitor','ot-agent-release']:
        repo_pkg_name = 'tsf-repository-server' + '_' + repo_serv_pkg
        repo_iplist = dict_module_instance['tsf-repository-server']
        dict_module_instance[repo_pkg_name] = repo_iplist

    for master_module in ['dsgp_master_ccd','dsgp_master_mcd','dsgp_master_dcc','dsgp_master_watchdog','dsgp_master_mcd.so']:
        master_module_name = 'tsf-master' + '_' + master_module
        master_iplist = dict_module_instance['tsf-master']
        dict_module_instance[master_module_name] = master_iplist
    print(dict_module_instance)
    return dict_module_instance

def config_analyse(module_name,option):
    """配置文件解析，输入option，section，返回value"""
    conf = configparser.ConfigParser()
    conf.read('config.ini', encoding="utf-8")
    res = conf.get(module_name,option)
    return res

def ssh_client_passwd(ip,port,username,passwd,command):
    """密码方式登录节点，输入ip,port,用户名，密码，查询版本命令，返回版本信息"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip,port,username,passwd)
        stdin, stdout, stderr = ssh.exec_command(command)
        time.sleep(1)
        ssh.close()
        return stderr.readlines(), stdout.readlines()
    except Exception as err:
        return str(err), None

def ssh_client_key(ip,port,username,key,command):
    """免密方式登录节点，输入ip,port,用户名，id_rsa路径，查询版本命令，返回版本信息"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key=paramiko.RSAKey.from_private_key_file(key)
    try:
        ssh.connect(ip, port, username, pkey=key)
        stdin, stdout, stderr = ssh.exec_command(command)
        time.sleep(1)
        ssh.close()
        return stderr.readlines(), stdout.readlines()
    except Exception as err:
        return str(err),None


def main():
    now = datetime.now()
    resultObj = get_rsp()
    module_list = handle_rsp(resultObj)
    l_title = "%-*s %-*s %-*s %-*s" % (30, 'Module', 40,'MD5file',40, 'MD5', 40, 'Version')
    #print(l_title)
    write_file('version_result.txt',str(now))
    write_file('version_result.txt',l_title)

    for module,ip_list in module_list.items():
        print("================",module,"================")

        try:
            path = config_analyse(module,'path')
            command = config_analyse(module,'command')
            md5file = config_analyse(module,'md5file')
        except:
            print("config read error")
            continue

        if ip_list == []:
            print("========No alive Instance")
            l = "%-*s %-*s %-*s %-*s" % (30, module, 40, md5file, 40, 'FATAL: No alive Instance', 40, '-')
            write_file('version_result.txt', l)
            continue

        get_version_command = 'cd %s && %s' % (path,command)
        if module in ['tsf-ctsdb', 'tsf-elasticsearch']:
            get_md5_command = "curl -s localhost:9201 |grep build_date|awk '{print $3}'"
        else:
            get_md5_command = 'cd %s && md5sum %s' % (path,md5file)
        print("========获取版本命令",get_version_command)
        print("========获取md5值",get_md5_command)

        md5_list = []
        version_list = []
        for instance_ip in ip_list:
            print("====",instance_ip)
            #获取jar包或二进制文件MD5
            #err,md5 = ssh_client_passwd(instance_ip,22,'root','passwdForRoot',get_md5_command)
            err,md5 = ssh_client_key(instance_ip,22,'root','/root/.ssh/id_rsa',get_md5_command)
            if err != []:
                md5_output = err[0].strip("\n")
            else:
                md5_output = md5[0].split(' ')[0].strip("\n")
            md5_list.append(md5_output)


            #获取版本信息
            #err,version = ssh_client_passwd(instance_ip,22,'root','passwdForRoot',get_version_command)
            err,version = ssh_client_key(instance_ip,22,'root','/root/.ssh/id_rsa',get_version_command)
            if err != []:
                version_output = err[0].strip("\n")
            elif len(version) != 0:
                version_output = version[0].strip("\n")
            else:
                version_output = "Get version failed"
            version_list.append(version_output)

            print("Version: %s | MD5: %s" % (version_output,md5_output))

        #模块下多个实例MD5值去重，大于1说明实例间MD5值不同
        set_md5_list = list(set(md5_list))
        if len(set_md5_list) == 1:
            module_md5_info = set_md5_list[0]
        else:
            module_md5_info = "FATAL: MD5 has different value"

        #模块下多个实例version去重，大于1说明实例间version不同
        set_version_list = list(set(version_list))
        if len(set_version_list) == 1:
            module_version_info = set_version_list[0]
        else:
            module_version_info = "FATAL: Version has different value"

        l = "%-*s %-*s %-*s %-*s" % (30,module,40,md5file,40,module_md5_info,40,module_version_info)
        #print(l)
        write_file('version_result.txt', l)

if __name__ == "__main__":
    main()
