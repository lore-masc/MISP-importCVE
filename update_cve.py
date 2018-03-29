#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pymisp import PyMISP
from keys import misp_url, misp_key
from os import listdir
from os.path import isfile, join
import requests
import re
import zipfile
import json
import sys
import random

def init(url, key):
    return PyMISP(url, key, False, 'json', debug=False)

misp = init(misp_url, misp_key)

#Scarico gli zip dai feed JSON di NVD
if len(sys.argv) == 2 and sys.argv[1] == "u":
	print("Script started in update mode\n")
	r_file = requests.get('https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.zip', stream=True)
	with open("nvd_recent/nvdcve_recent.zip", 'wb') as f:
                        for chunk in r_file:
                                f.write(chunk)
	files = [f for f in listdir("nvd_recent/") if isfile(join("nvd_recent/", f))]
	print("Download of nvdcve-1.0-recent.json.zip")
elif len(sys.argv) == 2 and sys.argv[1] == "l":
	print("Script started in local mode\n")
	files = [f for f in listdir("nvd/") if isfile(join("nvd/", f))]
else:
	r = requests.get('https://nvd.nist.gov/vuln/data-feeds')
	for filename in re.findall("nvdcve-1.0-[0-9]*\.json\.zip",r.text):
		print("Download of " + filename)
		r_file = requests.get("https://static.nvd.nist.gov/feeds/json/cve/1.0/" + filename, stream=True)
		with open("nvd/" + filename, 'wb') as f:
			for chunk in r_file:
				f.write(chunk)
	files = [f for f in listdir("nvd/") if isfile(join("nvd/", f))]
files.sort()

for file in files:
	archive = zipfile.ZipFile(join("nvd/", file), 'r')
	jsonfile = archive.open(archive.namelist()[0])
	cve_dict = json.loads(jsonfile.read().decode('utf8'))
	jsonfile.close()
	for cve in cve_dict['CVE_Items']:
			#Raccolgo informazioni sul contenuto del cve
			#Leggo il punteggio per ricavare il livello della minaccia

			try:
				score = cve['impact']['baseMetricV2']['cvssV2']['baseScore']
				if score < 4:
					cve_threat = 3
				elif score >= 4 and score <= 8:
					cve_threat = 2
				else:
					cve_threat = 1
			except:
				cve_threat = 4

			cve_distrib = 2		#Solo per questa istanza
			cve_analysis = 2	#Analisi completata

			#cerco se l'evento già esiste
			cve_info =  cve['cve']['CVE_data_meta']['ID']
			cve_comment = str(cve['cve']['description']['description_data'][0]['value'])
			result = misp.search_all(cve_info)

			#Verifico che il CVE non sia stato ritirato
			if "** REJECT **" in cve_comment:
				continue

			#Aggiorno eventuale evento esistente
			if len(result['response']) != 0:
				cve_id = result['response'][0]['Event']['id']
				event = misp.get_event(cve_id)
				print(cve_info + " already exists: " + event['Event']['uuid'] + "\n")
			else:
				cve_date = cve['publishedDate']
				event = misp.new_event(cve_distrib, cve_threat, cve_analysis, cve_info, cve_date)
				print(cve_info + " added: " + event['Event']['uuid'] + "\n")

			#Aggiungo la descrizione dell'evento
			misp.add_named_attribute(event, 'comment', cve_comment)
			print("CVE description added to " + cve_info)

			#Aggiungo i link di riferimento del cve
			try:
				for ref in cve['cve']['references']['reference_data']:
					cve_link = str(ref['url'])
					misp.add_named_attribute(event, 'link', cve_link)
				print("Added " + len(cve['cve']['references']['reference_data']) + " links into event " + cve_info + "\n")
			except:
				print("No references added to " + cve_info + "\n")

			#Aggiungo tag all'evento
			try:
				#Itero sui product vendor
				for vendor in cve['cve']['affects']['vendor']['vendor_data']:
					#Itero sui product name
					for product in vendor['product']['product_data']:
						cve_malware_platform = str(vendor['vendor_name']) + " " + str(product['product_name'])
						tag_text = "ms-caro-malware:malware-platform=" + cve_malware_platform
						color = "%06x" % random.randint(0, 0xFFFFFF)
						misp.new_tag(tag_text, colour=color)
						misp.tag(event['Event']['uuid'], tag_text)
						print("Added tag to " + cve_info + ": " + cve_malware_platform + "\n")
			except:
				print("No malware platform added to " + cve_info + "\n")
