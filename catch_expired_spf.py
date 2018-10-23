#!/usr/bin/python
import dns.resolver
import tldextract
import re
# read the efile line by line 
import multiprocessing.dummy as mp 
import whois 
import numpy as np 
import requests

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


#f = open("~/Download/top_1m.csv","r")
f = open("test.csv","r")
list_of_domains = []
for i in f.readlines():
	d = i.split(',')[1].strip()
	list_of_domains.append(d) 

corrected_domain = [] 
for d in list_of_domains:
	e=tldextract.extract(d)
	corrected_domain.append("{}.{}".format(e.domain,e.suffix)) 

corrected_domain= list(set(corrected_domain))
h = {} 

def do_TXT_query(domain):
    try:
        answer = dns.resolver.query(domain, "TXT").response.answer[0]
        for a in answer:
            plain_ans = a.strings[0]
            if plain_ans.find("v=spf1")!=-1:
                # extract all the a:
                extracted_spf_domain = re.findall("a:([^\s]+)", plain_ans)
                for j in extracted_spf_domain :
                    e = tldextract.extract(j)
                    tmp = "{}.{}".format(e.domain,e.suffix)
                    if tmp not in h:
                        h[tmp] = domain 
    except dns.resolver.NoAnswer:
        print "No TXT answer for " +domain 
    except dns.resolver.NoNameservers:
        print "No name server for " + domain
    except dns.resolver.NXDOMAIN:
        print "NXDOMAIN for " + domain
    except :
        print "UNKNOWN exception for" + domain	
	return

# hacky
print corrected_domain
p = mp.Pool(8)
p.map(do_TXT_query, corrected_domain)
p.close()
p.join()
# wait for all the threads to be completed 

np.save('output.npy',h)

# should hv a list of all spf records domain 			
for key,val in h.iteritems():
	try: 
		print "[*] Trying to check " + key + " (" + val +")" 
		whois.whois(key) 
	except:
		print bcolors.WARNING +  "[!] Domain " + key + " might be hijackable" + bcolors.ENDC
		print bcolors.WARNING + "Checking with GoDaddy" + bcolors.ENDC 
		godaddy_endpoint = "https://api.ote-godaddy.com/v1/domains/available?domain=globalnoticias.pt&checkType=fast&forTransfer=false"
		r = requests.get(godaddy_endpoint, headers={"accept":"application/json",'Authorization':"sso-key UzQxLikm_46KxDFnbjN7cQjmw6wocia:46L26ydpkwMaKZV6uVdDWe"})
		print r.text	
