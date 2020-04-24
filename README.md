# Tea
一个简单的restful api 服务器 
=======

## 简单的开始使用
```
from Tea import Tea, run
app = Tea(__name__)

@app.router("/test")
def fun(req):
  .....

run()
```

## 基础配置
+ 启动 run(host:绑定地址, port: 端口, dmt: 多线程处理)
+ 默认字符集 Tea.TeaConf.set_encoding()
+ 中间件 Tea.TeaConf.add_middleware()
+ 参数获取来自入口方法的参数为 Tea.Req 

## 深入配置
> 默认返回结果为Tea.Res 类，可以自己继承Res 重写 get_data()方法来定义自己的返回格式
> 如果返回的不是Res对象 默认返回json


# Tea
A simple python restful api server
=======

## Easy to start with
```
from Tea import Tea, run
app = Tea(__name__)

@app.router("/test")
def fun(req):
  .....

run()
```

## Basic configuration
+ Start run (host: bind address, port: port, dmt: multi-threaded processing)
+ Default character set Tea.TeaConf.set_encoding ()
+ Middleware Tea.TeaConf.add_middleware ()
+ Parameter acquisition The parameter from the entry method is Tea.Req

## In-depth configuration
> The default return result is Tea.Res class, you can inherit Res and override get_data () method to define your own return format
> If the returned object is not a Res object, the default is to return json
