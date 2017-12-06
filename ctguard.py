#!/usr/bin/env python3

# CTguard
# Copyright (C) 2017  Bram Staps

# This file is part of CTguard.
# CTguard is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# CTguard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with CTguard. If not, see <http://www.gnu.org/licenses/>.

import requests
import os
import json
import sys

file = os.path.join(os.path.expanduser("~"), ".ctguard.json")

def fetch_domain(domain):
	json = requests.get("https://certspotter.com/api/v0/certs?domain=%s" % domain).json()
	m = {}
	for item in json:
		m[item["sha256"]] = item

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
	for digest in newobject.keys():
		if digest not in oldobject:
			obj = newobject[digest]
			#now we need to report a new cert
			print("New certificate found for domain %s:" % domain)
			print(digest)
			print("\tDomain(s): %s" % ", ".join(obj["dns_names"]) )
			print("\tIssuer: %s" % obj["issuer"] )
			print("\tNot before: %s" % obj["not_before"])
			print("\tNot After: %s" % obj["not_after"])
			print("")

	#update
	fullmap[domain] = newobject


#done
with open(file, "w") as f:
	f.write(json.dumps(fullmap))