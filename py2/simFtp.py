# -*- coding: UTF-8 -*-
"""
    简单ftp服务，只支持文件上传和下载，而且并没有安全校验，仅用于环境内文件导入
"""
import os
import json
from SimpleHTTPServer import SimpleHTTPRequestHandler, test
from enum import IntEnum

ENCODING = "utf-8"
UPLOAD_DIR = "upload"
CONTENT_TYPE_FORM = "multipart/form-data"
CONTENT_TYPE_RAW_JSON = "application/json"


class HTTPStatus(IntEnum):

    def __new__(cls, value, phrase, description=''):
        obj = int.__new__(cls, value)
        obj._value_ = value

        obj.phrase = phrase
        obj.description = description
        return obj

    # success
    OK = 200, 'OK', 'Request fulfilled, document follows'
    MOVED_PERMANENTLY = (301, 'Moved Permanently',
                         'Object moved permanently -- see URI list')
    # client error
    BAD_REQUEST = (400, 'Bad Request',
                   'Bad request syntax or unsupported method')
    NOT_FOUND = (404, 'Not Found',
                 'Nothing matches the given URI')


class CustomRequestHandler(SimpleHTTPRequestHandler):

    def do_POST(self):
        self.parse_body()
        file_info = self.req_params["stream"]
        f = open(os.path.join(UPLOAD_DIR, file_info['file_name']), 'wb')
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
    test(HandlerClass=CustomRequestHandler)
