import http.client
import os
import socket
import json
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer, HTTPServer
from io import IOBase, TextIOBase
TEA_MODULE = "module"
TEA_FUN_NAME = "fun_name"
TEA_METHODS = "methods"
REQ_PARAM_QUERY = "query"
REQ_PARAM_BODY = "body"
_MAXLINE = 65536
CONTENT_TYPE_FORM = "multipart/form-data"
CONTENT_TYPE_XFORM = "application/x-www-form-urlencoded"
CONTENT_TYPE_RAW_JSON = "application/json"
CONTENT_TYPE_RAW_TEXT = "text/plain"
CONTENT_TYPE_RAW_XML = "application/xml"
CONTENT_TYPE_RAW_HTML = "text/html"
CONTENT_TYPE_RAW_BIN = "application/octet-stream"
conf_lock = threading.Lock()


def formate_url_parameter(data):
    """ Format url parameter """
    query = data.split("&")
    params = {}
    for item in query:
        if "=" in item:
            key, value = item.split("=")
            params[key] = value
    return params


class CustomRequestHandler(BaseHTTPRequestHandler):
    """ 自定义请求处理扩展

        继承自 BaseHTTPRequestHandler ，在其基础上增加：
            1. 根据Tea的注册进行请求分发
            2. 增加post请求body 解析类型  (详见 parse_body())
            3. 重写返回数据多类型支持

        Custom request processing extension
        
        Inherited from BaseHTTPRequestHandler and added on its basis:
            1. Request distribution according to the registration of Tea
            2. Add post request body parsing type (see parse_body () for details)
            3. Rewrite return data multi-type support
    """
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.requestline = None
        self.request_version = None
        self.command = None
        self.path = None
        self.uri = None
        self.headers = None
        self.close_connection = None
        self.req_params = None

    def parse_header(self):
        """
        解析头部信息

        Parsing header information
        """
        # Copy from BaseHTTPRequestHandler
        # Examine the headers and look for a Connection directive.
        try:
            self.headers = http.client.parse_headers(self.rfile,
                                                     _class=self.MessageClass)
        except http.client.LineTooLong as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Line too long",
                str(err))
            return False
        except http.client.HTTPException as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Too many headers",
                str(err)
            )
            return False
        return True

    def is_keep_connection(self):
        """
        判断是否保持连接

        Determine whether to stay connected
        """
        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = True
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = False
        # Examine the headers and look for an Expect directive
        expect = self.headers.get('Expect', "")
        if (expect.lower() == "100-continue" and
                self.protocol_version >= "HTTP/1.1" and
                self.request_version >= "HTTP/1.1"):
            if not self.handle_expect_100():
                return False
        return True

    def parse_request(self):
        """
        解析请求相关信息

        Parsing request related information
        """
        raw_request_line = self.rfile.readline(_MAXLINE+1)
        if len(raw_request_line) > _MAXLINE:
            self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
            return
        if not raw_request_line:
            return
        request_line = str(raw_request_line, TeaConf.encoding())
        request_line = request_line.rstrip('\r\n')
        self.requestline = request_line
        words = request_line.split()  # get request base info
        if len(words) == 0:
            self.send_error(
                HTTPStatus.BAD_REQUEST,
                "empty request line ")
            return False
        if len(words) >= 3:
            version = words[-1]
            try:
                if not version.startswith('HTTP/'):
                    raise ValueError
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad request version (%r)" % version)
                return False
            if version_number >= (2, 0):
                self.send_error(
                    HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
                    "Invalid HTTP version (%s)" % base_version_number)
                return False
            self.request_version = version

        if not 2 <= len(words) <= 3:
            self.send_error(
                HTTPStatus.BAD_REQUEST,
                "Bad request syntax (%r)" % request_line)
            return False
        command, path = words[:2]
        if len(words) == 2:
            self.close_connection = True
            if command != 'GET':
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad HTTP/0.9 request type (%r)" % command)
                return False
        self.command, self.path = command, path
        if not self.parse_header() or not self.is_keep_connection() or not self.parse_params():
            return False
        return True

    def parse_params(self):
        """
        解析请求参数
            目前是全部解析 不分辨请求

        Parsing request parameters
            Currently, all requests are resolved.

        """
        self.req_params = {}
        self.parse_query()
        return self.parse_body()

    def parse_query(self):
        """
            解析url上的参数并设置uri

            Parse parameters on url and set uri
        """
        if "?" in self.path:
            url_info = self.path.split("?")
            self.uri = url_info[0]
            params = formate_url_parameter(url_info[1])
            self.req_params[REQ_PARAM_QUERY] = params
        else:
            self.uri = self.path

    def parse_body(self):
        """解析 HTTP 请求体中的参数

        multipart/form-data 按照标准解析，文件请求二进制值并不解析，由用户自行处理
        application/x-www-form-urlencoded  application/json 按照标准解析
        text/plain  application/xml  按照字符串解析 不验证格式
        其他格式皆返回二进制值

        Parse the parameters in the HTTP request body
        
        -Multipart / form-data is parsed according to the standard,
        the binary value of the file request is not parsed, and is
        handled by the user
        
        -application / x-www-form-urlencoded application / json is
        parsed according to the standard
        
        - text / plain application / xml parsing according to the
        string without verifying the format
        
        - All other formats return binary values
        """
        encoding = TeaConf.encoding()
        content_length = self.headers.get("Content-Length")
        if content_length and content_length != 0:
            body = self.rfile.read(int(content_length))
            content_type = self.headers.get('Content-Type')
            content_type_up = content_type.upper()
            params = None
            if CONTENT_TYPE_FORM.upper() in content_type_up:
                """
                    ...
                    Content-Type: multipart/form-data; boundary=${boundary} 
                    
                    --${boundary}
                    ...
                    ... 

                    --${boundary}--
                """
                boundary = content_type.split("boundary=")[1]
                tag = b'--'
                bin_boundary = tag + boundary.encode() + b'\r\n'
                bin_boundary_end = tag + boundary.encode() + tag + b'\r\n'
                if not body.startswith(bin_boundary):
                    self.send_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "multipart/form-data format error")
                    return False
                if not body.endswith(bin_boundary_end):
                    self.send_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "multipart/form-data format error")
                    return False
                body = body[len(bin_boundary):]
                body = body[:-len(bin_boundary_end)]
                content_list = body.split(bin_boundary)
                params = {}
                key = ""
                for line in content_list:
                    meta_key, meta_value = line.split(b'\r\n\r\n')
                    meta_key = meta_key.decode(encoding)
                    name_begin = meta_key.find("name=\"") + 6
                    name_end = meta_key.find("\"", name_begin)
                    name = meta_key[name_begin:name_end]
                    if not name.strip():
                        continue
                    file_name_begin = meta_key.find("filename=\"")
                    if file_name_begin == -1:
                        meta_value = meta_value.decode(encoding)
                        value = meta_value.rstrip('\r\n')
                        params[name] = value
                    else:
                        file_name_begin += 10
                        file_name_end = meta_key.find("\"", file_name_begin)
                        file_name = meta_key[file_name_begin:file_name_end]
                        file_type = meta_key[meta_key.find("Content-Type:") + 13:]
                        value = meta_value[:-len(b'\r\n')]
                        # record file info
                        params[name] = {"file_name": file_name,
                                        "file_type": file_type,
                                        "value": value}
            elif CONTENT_TYPE_XFORM.upper() in content_type_up:
                content = body.decode(encoding)
                params = formate_url_parameter(content)
            elif CONTENT_TYPE_RAW_JSON.upper() in content_type_up:
                content = body.decode(encoding)
                params = json.loads(content)
            elif CONTENT_TYPE_RAW_XML.upper() in content_type_up or CONTENT_TYPE_RAW_TEXT.upper() in content_type_up:
                params = body.decode(encoding)
            else:
                params = body
            self.req_params[REQ_PARAM_BODY] = params
            return True
        return True

    def build_req_info(self):
        """"构建请求对象

            Build request object
        """
        return Req(self.req_params, self.headers.items(), self.uri, self.command)

    def send_result(self, result):
        """"
        发送结果数据

        如果 result 继承自Res 则会通过get_data()获取最终的数据data

        1.data 继承自dict或list则默认返回为json
        2.data 继承自IO 则认为是文件下载
        3.其他情况则按照默认 CONTENT_TYPE_RAW_TEXT 或者用户指定的Res的tpye

        Send result data

        If result inherits from Res, it will get the final data through get_data ()
        
        1.Data inherits from dict or list and returns to json by default
        2.data inherited from IO is considered to be a file download
        3. Otherwise, follow the default CONTENT_TYPE_RAW_TEXT or user-specified Res tpye
        """
        self.send_response(HTTPStatus.OK)
        body = None
        if not result:
            pass
        elif isinstance(result, Res):
            data = result.get_data()
            header = result.get_header()
            for h_key, h_value in header:
                self.send_header(h_key, h_value)
            content_type = result.get_type()
            if content_type is None:
                content_type = CONTENT_TYPE_RAW_TEXT
            if isinstance(data, dict) or isinstance(data, list):
                body = json.dumps(result).encode(TeaConf.encoding(), 'replace')
                self.send_header("Content-Type", CONTENT_TYPE_RAW_JSON)
                self.send_header('Content-Length', str(len(body)))
            elif isinstance(data, IOBase):
                body_length = 0
                while True:
                    info = data.read(_MAXLINE*100)
                    if not info:
                        break
                    body_length += len(info)
                data.seek(0)
                file_name = ''
                if hasattr(data, "name"):
                    file_name = os.path.basename(data.name)
                self.send_header("Content-Type", CONTENT_TYPE_RAW_BIN)
                self.send_header("Content-Disposition", "attachment; filename=\"" + file_name+"\"")
                self.send_header('Content-Length', str(body_length))
            else:
                body = data.encode(TeaConf.encoding(), 'replace')
                self.send_header("Content-Type", content_type)
                self.send_header('Content-Length', str(len(body)))
        else:
            body = json.dumps(result).encode(TeaConf.encoding(), 'replace')
            self.send_header("Content-Type", "json")
            self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        # HEAD 不返回任何body
        if self.command != 'HEAD' and body:
            self.wfile.write(body)
        elif self.command != 'HEAD':
            while True:
                temp_data = data.read(_MAXLINE*100)
                if not temp_data:
                    break
                if data and isinstance(data, TextIOBase):
                    temp_data = temp_data.encode(TeaConf.encoding())
                self.wfile.write(temp_data)

    def handle(self):
        """
            请求处理，解析原始请求信息，查找路由表中处理函数进行处理

            Request processing, parse the original request
            information, look up the processing function in
            the routing table for processing

        """
        if not self.parse_request():
            return
        try:
            fun = Tea.find_handler(self.uri, self.command)
            mw = TeaConf.compose()
            result = mw(self.build_req_info(), fun)
            self.send_result(result)
        except socket.timeout as e:
            self.log_error("Request timed out: %r", e)
            return
        except Exception as e:
            print(e)
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)


def run(host: str = "", port: int = 9000, dmt: bool = False):
    if dmt:
        server = ThreadingHTTPServer((host, port), CustomRequestHandler)
    else:
        server = HTTPServer((host, port), CustomRequestHandler)
    server.serve_forever()


class Tea:
    _rule_map = {}
    _fun_map = {}
    """
        配合CustomRequestHandler 实现方法路由，分发处理
        记录服务配置
        e.g. app = Tea()
            @app.router()
            def fun()
        
    """

    def __init__(self, module: str, prefix: str = "", encoding: str = None):
        self._route_map = {}
        self._module = module
        self._prefix = prefix
        if encoding is not None:
            Tea._encoding = encoding

    def add_route_rule(self, rule, handle_fun, **option):
        real_url = self._prefix + rule
        fun_name = handle_fun.__name__
        methods = option.get("methods")
        if methods is None:
            methods = []
        elif isinstance(methods, str):
            methods = [methods]
        elif isinstance(methods, list):
            methods = [x.upper() for x in methods if isinstance(x, str)]
        Tea._rule_map[real_url] = {TEA_MODULE: self._module,
                                   TEA_FUN_NAME: fun_name,
                                   TEA_METHODS: methods}
        self._route_map[fun_name] = handle_fun
        if Tea._fun_map.get(self._module):
            Tea._fun_map[self._module].update(self._route_map)
        else:
            Tea._fun_map[self._module] = self._route_map

    def router(self, rule: str, **options):
        def decorator(f):
            self.add_route_rule(rule, f, **options)
            return f
        return decorator

    @staticmethod
    def find_handler(url: str, method: str):
        rule_map = Tea._rule_map.get(url)
        fun_map = Tea._fun_map
        fun = None
        if rule_map:
            module = rule_map[TEA_MODULE]
            fun_name = rule_map[TEA_FUN_NAME]
            methods = rule_map[TEA_METHODS]
            if methods:
                if method in methods:
                    fun = fun_map.get(module).get(fun_name)
            fun = fun_map.get(module).get(fun_name)

        def handle_fun(context):
            if fun is None:
                raise Exception("There is no matching method")
            else:
                return fun(context)
        return handle_fun


class Req:
    """"请求信息对象
    集成 请求参数、头部信息、资源标识、方法

    Request information object
    Integration request parameters, header information,
    resource identification, methods
    """
    def __init__(self, req_params, header, uri, method):
        self._req_params = req_params
        self._header = header
        self._uri = uri
        self._method = method

    def get_query(self):
        return self._req_params.get(REQ_PARAM_QUERY)

    def get_body(self):
        return self._req_params.get(REQ_PARAM_BODY)

    def get_params(self):
        if self._method == "GET":
            return self._req_params.get(REQ_PARAM_QUERY)
        else:
            return self._req_params.get(REQ_PARAM_BODY)

    def get_uri(self):
        return self._uri

    def get_method(self):
        return self._method

    def get_header(self):
        return self._header


class Res:
    """
        基础返回结果对象

        用户可以继承此对象并重写 get_data()方法来定义自己的返回格式

        Basic return result object
        
        Users can inherit this object and override the get_data()
        method to define their own return format
    """
    def __init__(self, data, header: dict = {}, content_type: str = None):
        self._data = data
        self._type = content_type
        self._header = header

    def get_data(self):
        return self._data

    def get_type(self):
        return self._type

    def get_header(self):
        return self._header


class TeaConf:
    """
    Tea 的配置对象

    支持配置字符集编码、中间件、是否使用环境变量

    Tea configuration object

    Support for configuring character set encoding,
    middleware, and whether to use environment variables
    """
    _encoding = "utf-8"

    _middleware = []

    _use_env = False

    @staticmethod
    def add_middleware(fun, index=None):
        with conf_lock:
            if isinstance(fun, list):
                TeaConf._middleware.extend(fun)
            elif index is not None:
                TeaConf._middleware.insert(index, fun)
            else:
                TeaConf._middleware.append(fun)

    @staticmethod
    def compose():
        """
        构建中间件执行序列解析方法

        Construct middleware execution sequence analysis method
        """
        index = 0

        def middle(context, handle):
            def dispatch():
                nonlocal index
                if index == len(TeaConf._middleware):
                    return handle(context)
                else:
                    fun = TeaConf._middleware[index]
                    index += 1
                    return fun(context, dispatch)
            return dispatch()
        return middle

    @staticmethod
    def encoding():
        return TeaConf._encoding

    @staticmethod
    def set_encoding(encoding):
        with conf_lock:
            TeaConf._encoding = encoding
