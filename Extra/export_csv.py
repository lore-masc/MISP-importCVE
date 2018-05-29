#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pymisp import PyMISP
import json
import sys
import json
import os
sys.path.append('../')
from keys import misp_url, misp_key

def init(url, key):
	return PyMISP(url, key, False, 'json', debug=False)

misp = init(misp_url, misp_key)
if len(sys.argv) < 3:
	print("Error:")
	print("export_csv.py <tag_event> <path_export> <type_attribute>")
	sys.exit()

#configs
tag = sys.argv[1]
path = sys.argv[2]

#check path end char
if not path.endswith(os.sep):
	path = path + os.sep

#check setted data type to export
if len(sys.argv) < 5:
	data_type = sys.argv[3]
else:
	data_type = ""

#set name csv file
csv_name = path + "events-" + data_type + ".csv"
SEPARATOR = ","

#search event with specified tag
result = misp.search_index(tag=tag)

#remove old csv, if exists
if os.path.isfile(csv_name):
    os.remove(csv_name)

if len(result['response']) != 0:
	for found in result['response']:
		event_id = found['id']
		event = misp.get_event(event_id)
		event_info = event['Event']['info']
		event_attributes = event['Event']['Attribute']
		for attr in event_attributes:
			attr_type = attr['type']
			attr_value = attr['value']
			if attr_type == data_type:
				line = event_info + SEPARATOR + attr_value + '\n'
				f = open(csv_name, 'a')
				f.write(line)
				f.close()
		print("File exported in " + csv_name)
else:
	print("There isn't any event to export with tag " + tag)
