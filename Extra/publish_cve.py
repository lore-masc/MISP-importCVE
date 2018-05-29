#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pymisp import PyMISP
import json
import sys
sys.path.append('../')
from keys import misp_url, misp_key, misp_verifycert

def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json', debug=False)

misp = init(misp_url, misp_key)

result = misp.search_index(published=0)
#print(json.dumps(result['response']))

for cve in result['response']:
	cve_id = cve['id']
	event = misp.get_event(cve_id)
	if event['Event']['published'] == False:
		cve_info = event['Event']['info']
		misp.fast_publish(cve_id)
		print(cve_info + " published\n")
