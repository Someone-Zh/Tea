"""
    简单ftp服务，只支持文件上传和下载，而且并没有安全校验，仅用于环境内文件导入
"""
import os
import json
from functools import partial
from http.server import SimpleHTTPRequestHandler , test
from http import HTTPStatus
ENCODING = "utf-8"
UPLOAD_DIR = "upload"
CONTENT_TYPE_FORM = "multipart/form-data"
CONTENT_TYPE_RAW_JSON = "application/json"


class CustomRequestHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, directory=None, **kwargs):
        if directory is None:
            directory = os.getcwd()
        self.directory = directory
        # 上传文件夹初始化
        dir_path = os.path.join(directory, UPLOAD_DIR)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        self.upload_dir = dir_path
        super().__init__(*args, directory=directory, **kwargs)

    def do_POST(self):
        self.parse_body()
        file_info = self.req_params["stream"]
        f = open(os.path.join(self.upload_dir, file_info['file_name']), 'wb')
        f.write(file_info['value'])
        f.close()
        self.send_result({"code": 200})

    def send_result(self, result):
        self.send_response(HTTPStatus.OK)
        body = json.dumps(result).encode(ENCODING, 'replace')
        self.send_header("Content-Type", CONTENT_TYPE_RAW_JSON)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
        encoding = ENCODING
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
            self.req_params = params


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--cgi', action='store_true',
                        help='Run as CGI Server')
    parser.add_argument('--bind', '-b', default='', metavar='ADDRESS',
                        help='Specify alternate bind address '
                             '[default: all interfaces]')
    parser.add_argument('--directory', '-d', default=os.getcwd(),
                        help='Specify alternative directory '
                             '[default:current directory]')
    parser.add_argument('port', action='store',
                        default=8000, type=int,
                        nargs='?',
                        help='Specify alternate port [default: 8000]')
    args = parser.parse_args()
    handler_class = partial(CustomRequestHandler,
                                directory=args.directory)
    test(HandlerClass=handler_class, port=args.port, bind=args.bind)
