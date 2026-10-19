import re
import requests
import argparse
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor,as_completed
import json


class ApiTest():
    def __init__(self,url,method,content_type,headers,payloads,delay,concurrency,timeout,output,data = None):
        self.url = url
        self.method = method
        self.data = data
        self.content_type = content_type
        self.headers = headers
        self.payloads = payloads
        self.delay = delay
        self.concurrency = concurrency
        self.timeout = timeout
        self.output = output
        self.at_dict = {
            "sql":["'", '"', "\\", "--", "/*", "1' or '1'='1"],
            "type":[None, True, False, 0, 1, -1, 3.14, "1", "abc", "", [], ["test"], {}, {"test": 1}, (), ("test",)],
            "data":[None, True, False, 0, 1, -1, 3.14, "1", "abc", "", [], ["test"], {}, {"test": 1}, (), ("test",)]
        }
        try:
            if self.payloads:
                with open(self.payloads,"r",encoding="utf-8") as f:
                    self.at_dict = json.load(f) 
                    if not isinstance(self.at_dict,dict):
                        raise ValueError("文件内容格式错误，必须是字典，请检查后重新输入！")
            self.headers = self.headers.lstrip()
            if self.headers.startswith("{"):
                self.headers = json.loads(self.headers)
            else:
                raise ValueError("请重新输入正确的json格式字符")
            if not method in ["GET","POST","PUT","DELETE"]:
                raise ValueError("输入的请求类型非法，请检查后重新输入")
            if content_type not in ["json","data"]:
                raise ValueError("请输入类型，json或data")
            if "{FUZZ}" not in url :
                raise ValueError("地址内必须包含{FUZZ}标记注入点，请检查后重新输入")
            if content_type=="data" and not self.data:
                raise ValueError("设定为data模式时，必须传入data,请检查后重新输入")
        except Exception :
            print("json加载或打开指定的字典文件失败，请检查后重新输入")
            return 

    def benchmark(self):
        try:
            if self.content_type == "json":
                start = time.time()
                req = requests.request(self.method,url=self.url,json=self.data,headers=self.headers,timeout=self.timeout)
            elif self.content_type == "data" and self.data:
                start = time.time()
                req = requests.request(self.method,url=self.url,data=self.data.encode("utf-8"),headers=self.headers,timeout=self.timeout)
            else:
                raise ValueError("若指定了类型为data,则请输入请求体内容，请检查后重新输入")
            end = time.time()
            ela_t = end - start
            self.benchmark_code = req.status_code
            self.benchmark_len = len(req.content)
            self.benchmark_ela = ela_t
        except requests.exceptions.Timeout:
            print(f"[TIMEOUT] {self.url} 基准测试时请求超时")
            return
        except requests.exceptions.ConnectionError:
            print(f"[CONN-ERR] {self.url} 基准测试时连接失败（DNS/拒绝/网络不通）")
            return
        except requests.exceptions.HTTPError as e:
            print(f"[HTTP-ERR] {self.url} 基准测试时状态码异常: {e.response.status_code}")
            return
        except requests.exceptions.RequestException as e:
            print(f"[REQ-ERR] {self.url} 基准测试时其他请求异常: {e}")
            return
        except Exception :
            print("未知错误，请重新输入")
            return 

    def do_test(self,sql_inject = None,type_inject = None,data_inject = None):
        req = None
        data = self.data
        p = []
        if data and data_inject is not None: 
            data = self.data.replace("{FUZZ_data}",str(data_inject))
        try:
            if sql_inject is not None:
                url = self.url.replace("{FUZZ}",str(sql_inject))
                inject = sql_inject
                severity = "HIGH"
                vuln_type = "SQL_SYNTAX_LEAK"
                description = "目标 API 回显了底层 MySQL 数据库语法报错，存在高危 SQL 注入风险"
                if self.content_type == "json":
                    req = requests.request(self.method,url=url,json=data,headers=self.headers,timeout=self.timeout)
                elif self.content_type == "data":
                    req = requests.request(self.method,url=url,data=data.encode("utf-8"),headers=self.headers,timeout=self.timeout)
                p = [p for p in ["You have an error in your SQL syntax","pg_query()","ORA-01756","unrecognized token"] if p in req.text]
            
            elif type_inject is not None:
                url = self.url.replace("{FUZZ}",str(type_inject))
                inject = type_inject
                severity = "MEDIUM"
                vuln_type= "UNHANDLED_EXCEPTION"
                description = "服务端未妥善捕获溢出异常，泄露了后端 Python 堆栈源码路径"
                if self.content_type == "json":
                    req = requests.request(self.method,url=url,json=data,headers=self.headers,timeout=self.timeout)
                elif self.content_type == "data":
                    req = requests.request(self.method,url=url,data=data.encode("utf-8"),headers=self.headers,timeout=self.timeout)
                p = [p for p in ["Traceback (most recent call last)","Whitelabel Error Page (type=Internal Server Error)","Fatal error:"] if p in req.text]
            
            if req is None: return

            if req.status_code in (self.benchmark_code,500) and p and len(req.content) != self.benchmark_len or re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",req.text):
                return vuln_type,severity,inject,f"{self.method} {req.request.path_url}",req.status_code,p,description
            
            elif req.status_code == 500 and "Internal Server Error" in req.text:
                return vuln_type,severity,inject,f"{self.method} {req.request.path_url}",req.status_code,["Internal Server Error"],description
            
            elif req.status_code == self.benchmark_code and any([p for p in ["email","token","password"] if p in req.text]):
                return vuln_type,severity,inject,f"{self.method} {req.request.path_url}",req.status_code,[],description
            else:
                return
            
        except requests.exceptions.Timeout:
            print(f"[TIMEOUT] {self.url} 请求超时")
            return
        except requests.exceptions.ConnectionError:
            print(f"[CONN-ERR] {self.url} 连接失败（DNS/拒绝/网络不通）")
            return
        except requests.exceptions.HTTPError as e:
            print(f"[HTTP-ERR] {self.url} 状态码异常: {e.response.status_code}")
            return
        except requests.exceptions.RequestException as e:
            print(f"[REQ-ERR] {self.url} 其他请求异常: {e}")
            return
        except Exception :
            print("未知错误，请重新输入")
            return 

    def TPE(self):
        with ThreadPoolExecutor(max_workers=self.concurrency) as T:
            futures = []
            for key,value in self.at_dict.items():
                if key == "sql":
                    for inject in value:
                        futures.append(T.submit(self.do_test,sql_inject=inject))
                        time.sleep(self.delay)
                if key == "type":
                    for inject in value:
                        futures.append(T.submit(self.do_test,type_inject=inject))
                        time.sleep(self.delay)
                if key == "data":
                    for inject in value:
                        futures.append(T.submit(self.do_test,data_inject=inject))
                        time.sleep(self.delay)

            vulnerabilities_detected = []
            text = {
            "api_target": self.url,
            "method": self.method,
            "baseline": {
                "status_code": self.benchmark_code,
                "content_length": self.benchmark_len,
                "response_time_ms": self.benchmark_ela
            },
            "total_payloads_tested": len(futures),
            "vulnerabilities_detected": vulnerabilities_detected
                }
            

            with open(self.output,"w",encoding="utf-8") as f1:
                for f in as_completed(futures):
                    if f.result():
                        vulnerabilities_detected.append({
                            "vuln_type": f.result()[0],
                            "severity": f.result()[1],
                            "payload_used": f.result()[2],
                            "request_evidence": f.result()[3],
                            "status_code": f.result()[4],
                            "matched_signature": f.result()[5],
                            "description": f.result()[6]
                        })
                json.dump(text,f1,indent=4,ensure_ascii=False)

    def run(self):
        self.benchmark()
        if not hasattr(self, "benchmark_code"): return
        self.TPE()


if __name__ == "__main__":
    arg = argparse.ArgumentParser()
    arg.add_argument("-u","--url",required=True,help="目标 API URL（必须支持包含 {FUZZ} 标记）")
    arg.add_argument("-m","--method",required=True,help="请求方式，支持 GET、POST、PUT、DELETE（默认 GET）。")
    arg.add_argument("-d","--data",help="POST/PUT 请求体内容（支持包含 {FUZZ_data} 的 JSON 或表单字符串）。")
    arg.add_argument("--content-type",required=True,help="指定请求类型，json或data")
    arg.add_argument("-H","--headers",required=True,help='自定义请求头')
    arg.add_argument("-p","--payloads",help="外部字典文件路径（若不指定，默认加载内置的通用 SQL/异常测试 Payload 集合）。请注意:文件内容格式为dict，其中键名必须分别为json、type、data，值为列表")
    arg.add_argument("--delay",default=0.5,type=float,help="请求间歇休眠时间，浮点数，单位秒（默认 0.5）。")
    arg.add_argument("-c","--concurrency",default=5,type=int,help="并发探测线程数（默认 5）。")
    arg.add_argument("--timeout",default=5.0,type=float,help="单次请求超时（默认 5.0）。")
    arg.add_argument("-o","--output",default="api_vuln_report.json",help="输出结果文件名（JSON 格式）。")
    vt = arg.parse_args()
    api = ApiTest(vt.url,vt.method,vt.content_type,vt.headers,vt.payloads,vt.delay,vt.concurrency,vt.timeout,vt.output,vt.data)
    api.run()