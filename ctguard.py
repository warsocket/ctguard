#!/usr/bin/env python3

#CTguard
#Copyright (C) 2017 Bram Staps
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU Affero General Public License as
#published by the Free Software Foundation, either version 3 of the
#License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU Affero General Public License for more details.
#
#You should have received a copy of the GNU Affero General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

import requests
import os
import json
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend

file = os.path.join(os.path.expanduser("~"), ".ctguard.json")

def fetch_domain(domain):
	#json = requests.get("https://certspotter.com/api/v0/certs?domain=%s" % domain).json()
	json = requests.get("https://certspotter.com/api/v1/issuances?expand=dns_names&expand=cert&domain=%s" % domain).json()
	m = {}
	for item in json:
		digest = item["cert"]["sha256"]
		m[digest] = item
		#m[digest]

		#mapping values extracted form certificate within
		pem_data = "-----BEGIN CERTIFICATE-----\n" + m[digest]["cert"]["data"] + "\n-----END CERTIFICATE-----" 
		cert = x509.load_pem_x509_certificate(pem_data.encode(),default_backend())
		m[digest]["issuer"] = cert.issuer.rfc4514_string()
	return m


#init 
if os.path.isfile(file):
	with open(file, "r") as f:
		fullmap = json.loads(f.read())
else:
	fullmap = json.loads("{}")


for domain in sys.argv[1:]:
	newobject = fetch_domain(domain)

	try:
		oldobject = fullmap[domain]
	except KeyError:
		oldobject = {}


	#check to see differences
	issuers = set()
	domains = set()
	for digest in newobject.keys():
		obj = newobject[digest]
		if digest not in oldobject: #found a new cert
			#now we need to report a new cert
			print("New certificate found for domain %s:" % domain)
			print(digest)
			print("\tDomain(s): %s" % ", ".join(obj["dns_names"]) )
			print("\tIssuer: %s" % obj["issuer"] )
			print("\tNot before: %s" % obj["not_before"])
			print("\tNot After: %s" % obj["not_after"])
			print("\tNovel domains: %s" % ", ".join(list(set(obj["dns_names"]) - domains)) )
			print("\tNovel Issuer: %s" % ["No", "Yes"][int(obj["issuer"] not in issuers)] )

			#print("\tNovel issuer domains: %s")

		#this needs to be done for statistics(to tack novel usage of domains and issuers per query / domain)
		issuers.add(obj["issuer"])
		domains.union(set(obj["dns_names"]))

	#update
	fullmap[domain] = newobject


#done
with open(file, "w") as f:
	f.write(json.dumps(fullmap))
