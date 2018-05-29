#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pymisp import PyMISP
import json
import sys
sys.path.append('../')
from keys import misp_url, misp_key

def init(url, key):
	print("argument needed")
	return PyMISP(url, key, False, 'json', debug=False)

misp = init(misp_url, misp_key)

if len(sys.argv) < 2:
	sys.exit()
tag = sys.argv[1];

result = misp.search_index(tag=tag)
#print(result)

if len(result['response']) != 0:
	for found in result['response']:
		event_id = found['id']
		event = misp.get_event(event_id)
		response = misp.get_csv(eventid=event_id)
		event_csv = event_id + ".csv"
		with open(event_csv, 'w') as f:
			f.write(response)
else:
	print("There isn't any event to export with tag " + tag)