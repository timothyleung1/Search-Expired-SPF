#!/usr/bin/python

'''
	Tim Leung - tleung0504[at]gmail[dot]com
'''

import dns.resolver
import tldextract
import re
import threading 
import Queue 
import requests 
import logging 


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class GrabSPFDomainThread (threading.Thread):
	def __init__(self, tasks):
		threading.Thread.__init__(self) 
		self.tasks = tasks 


	def extractTLD(self, domain):
		e = tldextract.extract(domain) 
		tld = "{}.{}".format(e.domain, e.suffix)
		return tld 

	def extractSPFs(self, domain):
		result = [] 
		try:
			answer = dns.resolver.query(domain, "TXT").rrset 
			for a in answer:
				if a.to_text().find("v=spf") != -1: # found 
					# improvement : recursively call include instead of stopping at the first level 
					extractedDomains = re.findall("\s(?:mx:|a:|exists:|include:|redirect=|exp=)([\w\W]+?)\s", a.to_text()) # find all domain in the query 
					result = result + extractedDomains
		except dns.resolver.NoAnswer:
			logging.debug(bcolors.WARNING + "[-] extractSPFs: No TXT answer for " + domain + bcolors.ENDC )
		except dns.resolver.NoNameservers:
			logging.debug(bcolors.WARNING + "[-] extractSPFs: No name server for " + domain + bcolors.ENDC )
		except dns.resolver.NXDOMAIN:
			print bcolors.OKBLUE + "[*] NXDOMAIN for parent domain " + domain + bcolors.ENDC 
		except:
			logging.debug(bcolors.WARNING + "[-] extractSPFs: Unknown error while extracting SPF for " + domain + bcolors.ENDC)
		return result 

	''' only print when receive NXDOMAIN while resolving ''' 
	def resolveDomain(self, domain, spf ):
		try: # just run dig and run CNAME on TLD 
			answers = dns.resolver.query(spf, "CNAME").rrset 
			# for all answers call resolveDomain 
			for a in answers : 
				# just do recursively 
				tld = self.extractTLD(a.target_to_text())
				if tld.split(".")[-1] == "" :
					logging.debug("[-] Config Error " + tld )
					return 
				self.resolveDomain(domain, tld)
		except dns.resolver.NXDOMAIN:
			print bcolors.OKGREEN + "[*] Found orphan domain " + spf + " from " + domain + bcolors.ENDC
		except dns.resolver.NoAnswer:
			logging.debug(bcolors.WARNING + "[-] resolveDomain: No CNAME answer for " + spf + bcolors.ENDC)
		except dns.resolver.NoNameservers:
			logging.debug(bcolors.WARNING + "[-] resolveDomain: No name server for " + spf + bcolors.ENDC) 
		except Exception as e:			
			logging.debug(bcolors.WARNING + "[-] resolveDomain: Unknown Error for " + spf + bcolors.ENDC)
			logging.debug(str(e))

	def run(self): 
		while True: 
			t = self.tasks.get()
			spfs = self.extractSPFs(t)
			for spf in spfs: 
				spf_tld = self.extractTLD(spf)
				if spf_tld.split(".")[-1]=="":
					continue
				if spf_tld not in collectedDomains:
					collectedDomains[spf_tld] = t 	
					self.resolveDomain(t, spf_tld) 
			self.tasks.task_done() 


if __name__ == "__main__":
	tasks = Queue.Queue() # create an empty task list 
	fout = open("test_200k-1m.csv", "r") 
	for i in fout.readlines():
		tasks.put(i.split(",")[1].strip()) 

	collectedDomains = {} # store all the collected domains from SPF record 
	logging.basicConfig(level=logging.INFO)# change to INFO if no DEBUG msg want to be printed 

	num_threads = 30
	for i in range(num_threads):
		t = GrabSPFDomainThread(tasks)
		t.setDaemon(True)
		t.start() 

	tasks.join() 
