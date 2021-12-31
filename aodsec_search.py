# coding:utf-8

import configparser
import requests
import base64
import sys
import shodan

def echoMessage():
	version = """  
	  [#] Create By ::
	    _                     _    ___   __   ____                             
	   / \   _ __   __ _  ___| |  / _ \ / _| |  _ \  ___ _ __ ___   ___  _ __  
	  / _ \ | '_ \ / _` |/ _ \ | | | | | |_  | | | |/ _ \ '_ ` _ \ / _ \| '_ \ 
	 / ___ \| | | | (_| |  __/ | | |_| |  _| | |_| |  __/ | | | | | (_) | | | |
	/_/   \_\_| |_|\__, |\___|_|  \___/|_|   |____/ \___|_| |_| |_|\___/|_| |_|
	               |___/            By https://aodsec.com                                           
	"""
	print(version)
def saveMessage(content,file):
    tt = content.replace("http://","").replace("https://","")
    fp = open(file,'a+', encoding='utf-8-sig')
    fp.write("http://"+tt+"\n")
    fp.close()

def getFofaMsg(email,api_key,flag,size):
	api = r'https://fofa.so/api/v1/search/all?email={}&key={}&qbase64={}&size={}'
	print(api.format(email,api_key,flag,size))
	response = requests.get(api.format(email,api_key,flag,size))
	print(response.json())
	results = response.json()["results"]
	print("共搜索到{}条记录！".format(len(results)))

	return results

def getShodanMsg(key,words):
	api=shodan.Shodan(key)
	results = api.search(words)
	print("共搜索到{}条记录！".format(results['total']))
	shodan_list=[]
	if len(results['matches'])>0:
		for result in results['matches']:
			url = result['ip_str'] + ":" + str(result['port'])
			url.replace("\n","").replace("\r","")
			shodan_list.append(url)
	return shodan_list

def getFlag(words):
	return base64.b64encode(words.encode()).decode().replace("=","%3D")

def readConfig():
	conf = configparser.ConfigParser()
	conf.read('config.ini')

	email = conf.get("fofa","email")
	api_key = conf.get("fofa","api_key")
	size = conf.get("fofa","size")
	words = conf.get("fofa","words")

	shodan_key = conf.get("shodan","key")
	shodan_words = conf.get("shodan","words")

	return email,api_key,size,words,shodan_key,shodan_words


if __name__ == '__main__':
	echoMessage()
	email,api_key,size,words,shodan_key,shodan_words=readConfig()
	if len(sys.argv) < 2:
		print("usage:\n\tpython3 aodsec_search.py [fofa|shodan]")
	else:
		name = sys.argv[1]
		if(name == "fofa"):
			flag = getFlag(words)
			msg_list = getFofaMsg(email,api_key,flag,size)
			file_name = r"{}.txt".format(flag)
			for url in msg_list:
				saveMessage(url[0],file_name)
			print("已经将数据保存至\t"+file_name)
		elif(name == "shodan"):
			msg_list=getShodanMsg(shodan_key,shodan_words)
			file_name = r"{}.txt".format(getFlag(shodan_words))
			for url in msg_list:
				saveMessage(url,file_name)
			print("已经将数据保存至\t"+file_name)
		else:
			print("参数错误")
			print("usage:\n\tpython3 aodsec_search.py [fofa|shodan]")
