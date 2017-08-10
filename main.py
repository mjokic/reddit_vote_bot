from requests import requests
import re
import threading,queue
import time
from select import *
import argparse

def load(filename):
	f = open(filename,"r")
	lines = f.readlines()
	f.close()
	return lines

def save(string):
	f = open("successfull_accs.txt","a")
	f.write(string)
	f.close()


def login(username,password,proxy):
	print(username,password,proxy)
	url = "https://m.reddit.com/login"

	proxies = {
		'http':'http://'+proxy,
		'https':'http://'+proxy,
	}

	s = requests.Session()
	s.headers['User-Agent'] = "Opera/9.80 (Android 4.0.4; Linux; Opera Mobi/ADR-1205181138; U; pl) Presto/2.10.254 Version/12.00"

	try:
		g = s.get(url,proxies=proxies)


		lista = re.findall(r'name="csrf-token" content="(.*?)"',g.text)
		token = lista[0]

		# print(token)

		data = {
			"username":username,
			"password":password,
			"newsletter":"False",
			"_csrf":token,
		}


		try:
			p = s.post(url,json=data,proxies=proxies)
			resp = p.json()

			rtoken = resp['token']['token']['access_token']

			s.nesto = rtoken

			s.headers['Cookie'] = p.headers['Set-Cookie']

			# print(resp)
			print(p.status_code)

			if p.status_code == 400:
				return False,None
			elif p.status_code == 200:
				return True,s
		except:
			return None,None
	except:
		return None,None


def like(s,post_id,proxy):
	print("Liking now",post_id,proxy)
	url = "https://oauth.reddit.com/api/vote?raw_json=1&app=mweb-client"

	data = {
		'id':post_id,
		'dir':'1'
	}



	token = s.nesto
	# print(token)

	headers1 = {
		'Host': 'oauth.reddit.com',
		'User-Agent': 'Opera/9.80 (Android 4.0.4; Linux; Opera Mobi/ADR-1205181138; U; pl) Presto/2.10.254 Version/12.00',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language': 'en-US,en;q=0.5',
		'Accept-Encoding': 'gzip, deflate, br',
		'Authorization': 'bearer '+token,
		'Content-Type': 'application/x-www-form-urlencoded',
		'Referer': 'https://m.reddit.com/r/OTAmory/comments/4z83a8/this_is_the_weirdest_subreddit/?compact=true&utm_source=mweb_redirect',
		'Content-Length': '18',
		'origin': 'https://m.reddit.com',
		'Connection': 'keep-alive'
	}

	# s.headers = headers1

	proxies = {
		'http':'http://'+proxy,
		'https':'http://'+proxy,
	}

	try:
		o = s.options("https://oauth.reddit.com/api/vote?raw_json=1&app=mweb-client")
		p = s.post(url,data=data,headers=headers1,proxies=proxies)

		print("STATUS CODEEE",p.status_code)

		if p.status_code == 200:
			return True

		elif p.status_code == 403:
			return False

	except:
		return None


def test_save(string):
	f = open("testpage.html","w")
	f.write(string)
	f.close()


def worker(Q,Q1,post_id):
	# post_id = "t3_4z83a8"
	while not Q.empty() or Q1.empty():
		proxy = Q1.get()
		up = Q.get()
		l = up.strip().split(":")
		username = l[0]
		password = l[1]

		status,session = login(username,password,proxy)

		if status == True:
			print("SUCCESSFUL LOGIN",username,password)
			# save(username+":"+password+specs+"\n")
			like_status = like(session,post_id,proxy)

			if like_status == True:
				save(username+":"+password+"\n")
				print("[+] LIKE SUCCESS")

			elif like_status == False:
				print("[-] LIKE FAILED!!!")				

			elif like_status == None:
				print("FAILED!!! PROBABLY SHITTY PROXY!!!")


			Q1.put(proxy)

		elif status == None:
			print("[!] PROXY ERROR!!!")
			Q.put(up)

		else:
			print("[-] FAIL TO LOGIN!!! WRONG PASSWORD!!! ("+username+":"+password+")")
			Q1.put(proxy)


		Q.task_done()

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("PostID",help="Reddit post ID")
	parser.add_argument("Threads",help="Number of threads")

	args = parser.parse_args()

	post_id = "t3_"+args.PostID
	tn = args.Threads

	lines = load("accounts.txt")
	proxies = load("proxy.txt")

	try:
		thread_num = int(tn)
	except:
		exit("Threads need to be number!")

	if thread_num <= 0:
		exit("Threads need to be bigger then 0")

	Q = queue.Queue()
	Q1 = queue.Queue()

	for line in lines:
		Q.put(line)

	for proxy in proxies:
		Q1.put(proxy.strip())


	for num in range(thread_num):
		t = threading.Thread(target=worker,args=(Q,Q1,post_id))
		t.start()

	Q.join()

if __name__ == '__main__':
	main()
