# -*- coding: utf-8 -*-
"""
ChatPy官方API
作者：Hz6826
email：huangzhen6826@gmail.com
"""
import random
import threading
import time
import urllib.request
import json
import hashlib
import os
import warnings

SERVER_IP = "124.221.74.246"
PORT = 82
APP_ID = ""
APP_KEY = os.environ.get('PYCHAT_APP_KEY')
PROTOCOL = "http"


class ChatAPI:
    """
    ChatAPI对象，用于管理服务器通信，密钥，等等
    """

    def __init__(self, server_ip:str|None=None, port:int|None=None, app_id:str|None=None, app_key:str|None=None):
        """
        创建ChatAPI实例。通常其会以 形参 -> py头部全局常量 的优先顺序进行配置，特别地，app_key会在形参为None时查找环境变量。
        :param server_ip: 服务器IP地址
        :param port: 服务器端口号
        :param app_id: 鉴权id
        :param app_key: 鉴权密钥
        """
        self.server_ip = server_ip if server_ip else SERVER_IP
        self.port = port if port else PORT
        self.app_id = app_id if app_id else APP_ID
        self.app_key = app_key if app_key else APP_KEY
        self.connected = False
        self.username = ""
        self.session = ""
        self.exception_stack = []

    def _gen_salt(self):
        """
        内部方法，用于生成一个盐字符串
        :return: 盐字符串
        """
        return str(random.randint(1, 100000))

    def _get_sign(self, *args: str, **kwargs):
        """
        内部方法，用于生成签名
        :param args: 可变形参，按顺序传入签名内容，需全部是字符串
        :param kwargs: 现在还没什么用，只是为了代码完整性
        :return: sha256签名字符串
        """
        sign_str = self.app_id + self.app_key
        for i in args:
            sign_str += i
        return hashlib.sha256(sign_str.encode()).hexdigest()

    def _send_request(self, api_name: str, data: dict) -> dict:
        """
        内部方法，向服务器发送一个API请求
        :param api_name: API请求名称，会拼接在 {PROTOCOL}://{self.server_ip}:{self.port}/api/v1/ 后面
        :param data: 数据，字典形式
        :return: API返回结果
        """
        url = f"{PROTOCOL}://{self.server_ip}:{self.port}/api/v1/{api_name}"
        headers = {'Content-Type': 'application/json'}
        json_data = json.dumps(data).encode('utf8')
        req = urllib.request.Request(url=url, data=json_data, headers=headers)
        response = urllib.request.urlopen(req)
        result = response.read().decode('utf8')
        return json.loads(result)

    def _handle_exception(self, data: dict):
        """
        内部方法，用于处理异常，压入异常栈
        :param data: 异常数据
        """
        warnings.showwarning(f"ChatAPI警告：{data['err_no']}: {data['err_info']}", UserWarning, 'chatapi.py', 0)
        self.exception_stack.append({
            'err_no': data['err_no'],
            'err_info': data['err_info']
        })

    def register_user(self, username:str, password: str, description: str = ""):
        """
        注册用户
        :param username: 用户名
        :param password: 密码
        :param description: 描述，可选
        """
        salt = self._gen_salt()
        result = self._send_request(
            api_name="register_user",
            data={
                'app_id': self.app_id,
                'username': username,
                'password': password,
                'description': description,
                'salt': salt,
                'sign': self._get_sign(username, password, description, salt)
            }
        )
        if result['status'] == 0:
            pass
        else:
            self._handle_exception(result)

    def login_user(self, username:str, password:str, heartbeat_interval:int=60):
        """
        登录用户
        :param username: 用户名
        :param password: 密码
        :param heartbeat_interval: 心跳数据包发送间隔，可选，默认为60s，设置为-1禁用heartbeat
        """
        salt = self._gen_salt()
        result = self._send_request(
            api_name="login_user",
            data={
                'app_id': self.app_id,
                'username': username,
                'password': password,
                'salt': salt,
                'sign': self._get_sign(username, password, salt)
            }
        )
        if result['status'] == 0:
            self.connected = True
            self.username = username
            self.session = result['session']
            if heartbeat_interval > 0:
                threading.Thread(target=lambda: self.start_heartbeat(heartbeat_interval), daemon=True).start()
        else:
            self._handle_exception(result)

    def start_heartbeat(self, heartbeat_interval:int):
        """
        心跳数据包线程
        :param heartbeat_interval: 心跳数据包发送间隔，可选，默认为60s，设置为-1禁用heartbeat
        """
        while self.connected:
            self.heartbeat()
            time.sleep(heartbeat_interval)

    def heartbeat(self):
        """
        发送一次心跳数据包
        """
        salt = self._gen_salt()
        result = self._send_request(
            api_name="heartbeat",
            data={
                'app_id': self.app_id,
                'session': self.session,
                'salt': salt,
                'sign': self._get_sign(self.session, salt)
            }
        )
        if result['status'] == 0:
            pass
        else:
            self._handle_exception(result)

    def get_user_info(self, username:str) -> dict:
        """
        获取用户信息
        :param username: 用户名
        :return: 字典，包括用户信息 username, role, description, reg_time, last_use_time
        """
        salt = self._gen_salt()
        result = self._send_request(
            api_name="get_user_info",
            data={
                'app_id': self.app_id,
                'session': self.session,
                'username': username,
                'salt': salt,
                'sign': self._get_sign(self.session, username, salt)
            }
        )
        if result['status'] == 0:
            return result
        else:
            self._handle_exception(result)

    def change_password(self, username:str, new_password:str) -> dict:
        """
        修改用户密码\n
        权限说明：\n
        0 普通用户只可以改变自己的密码\n
        1,2 admin和super admin可以改变任何人的密码
        :param username: 要修改的用户名
        :param new_password: 新的密码
        :return:
        """
        salt = self._gen_salt()
        result = self._send_request(
            api_name="change_password",
            data={
                'app_id': self.app_id,
                'session': self.session,
                'username': username,
                'new_password': new_password,
                'salt': salt,
                'sign': self._get_sign(self.session, username, new_password, salt)
            }
        )
        if result['status'] == 0:
            return result
        else:
            self._handle_exception(result)

    def send_direct_message(self, recv_user:str, message:str) -> dict:
        """
        发送私聊消息
        :param recv_user: 发送对象，用户名
        :param message: 消息
        :return:
        """
        salt = self._gen_salt()
        result = self._send_request(
            api_name="send_direct_message",
            data={
                'app_id': self.app_id,
                'session': self.session,
                'recv_user': recv_user,
                'message': message,
                'salt': salt,
                'sign': self._get_sign(self.session, recv_user, message, salt)
            }
        )
        if result['status'] == 0:
            return result
        else:
            self._handle_exception(result)

    def get_direct_message(self) -> dict:
        """
        获取最新私聊消息（注：服务器端会在私聊消息已阅后自动删除，所以请在客户端保存消息）
        返回格式：
        {"count": 1,
        "messages": [{"message": "Howdy!", "send_time": "Sat, 09 Dec 2023 17:16:02 GMT", "username": "test4"}, etc.],
        "status": 0}
        :return: 私聊消息
        """
        salt = self._gen_salt()
        result = self._send_request(
            api_name="get_direct_message",
            data={
                'app_id': self.app_id,
                'session': self.session,
                'salt': salt,
                'sign': self._get_sign(self.session, salt)
            }
        )
        if result['status'] == 0:
            return result
        else:
            self._handle_exception(result)

    def send_group_message(self, gid: int, message: str) -> dict:
        """
        发送群聊消息，格式：
        {"count": 1,
        "messages": [{"message": "Howdy!", "send_time": "Sat, 09 Dec 2023 17:16:02 GMT", "username": "test4"}, etc.],
        "status": 0}
        :param gid: 群聊id
        :param message: 消息
        :return:
        """
        salt = self._gen_salt()
        gid = str(gid)
        result = self._send_request(
            api_name="send_group_message",
            data={
                'app_id': self.app_id,
                'session': self.session,
                'gid': gid,
                'message': message,
                'salt': salt,
                'sign': self._get_sign(self.session, gid, message, salt)
            }
        )
        if result['status'] == 0:
            return result
        else:
            self._handle_exception(result)

    def get_group_message(self, gid:int)->dict:
        """
        获取群聊消息
        :param gid: 群聊id
        :return:
        """
        salt = self._gen_salt()
        gid = str(gid)
        result = self._send_request(
            api_name="get_group_message",
            data={
                'app_id': self.app_id,
                'session': self.session,
                'gid': gid,
                'salt': salt,
                'sign': self._get_sign(self.session, gid, salt)
            }
        )
        if result['status'] == 0:
            return result
        else:
            self._handle_exception(result)

    def get_group_info(self, gid:int)->dict:
        """
        获取群聊信息，格式：
        {
            'status': ...,
            'gid': ...,
            'name': ...,
            'description': ...,
            'reg_time': ...,
            'last_use_time': ...
        }
        :param gid: 群聊id
        :return:
        """
        salt = self._gen_salt()
        gid = str(gid)
        result = self._send_request(
            api_name="get_group_info",
            data={
                'app_id': self.app_id,
                'session': self.session,
                'gid': gid,
                'salt': salt,
                'sign': self._get_sign(self.session, gid, salt)
            }
        )
        if result['status'] == 0:
            return result
        else:
            self._handle_exception(result)

    def register_group(self, group_name:str, description:str="")->dict:
        """
        创建群聊
        :param group_name: 群聊名称
        :param description: 描述
        :return:
        """
        salt = self._gen_salt()
        result = self._send_request(
            api_name="get_group_info",
            data={
                'app_id': self.app_id,
                'session': self.session,
                'group_name': group_name,
                'description': description,
                'salt': salt,
                'sign': self._get_sign(self.session, group_name, description, salt)
            }
        )
        if result['status'] == 0:
            return result
        else:
            self._handle_exception(result)


if __name__ == '__main__':
    api_test = ChatAPI(
        server_ip='127.0.0.1',
        port=5000,
        app_id='MZFiLAzmJu',
        app_key='vUCiKf167oNUfpdbsxKs'
    )
    api_test.login_user("apitest", "idk", heartbeat_interval=5)
    print(api_test.get_user_info(api_test.username))
    print(api_test.get_user_info('test'))
    print(api_test.send_group_message(1, 'Hello, world!'))
    print(api_test.get_group_info(1))
    print(api_test.get_group_message(1))
    time.sleep(100)
