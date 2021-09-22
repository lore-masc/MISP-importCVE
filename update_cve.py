#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPTag
from keys import misp_url, misp_key, misp_verifycert
from os import listdir
from os.path import isfile, join
import requests
import re
import zipfile
import json
import sys
import datetime


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')


def create_attribute(typ, value, category, comment):
    attribute = MISPAttribute()
    attribute.type = typ
    attribute.value = value
    attribute.category = category
    attribute.comment = comment

    return attribute


misp = init(misp_url, misp_key)


# Scarico gli zip dai feed JSON di NVD
if len(sys.argv) >= 2 and sys.argv[1] == "u":
    print("Script started in update mode\n")
    r_file = requests.get('https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip', stream=True)
    with open("nvd_recent/nvdcve_recent.zip", 'wb') as f:
        for chunk in r_file:
            f.write(chunk)
    files = [f for f in listdir("nvd_recent/") if not f.startswith('.') and isfile(join("nvd_recent/", f))]
    print("Download of nvdcve-1.0-recent.json.zip")
elif len(sys.argv) >= 2 and sys.argv[1] == "l":
    print("Script started in local mode\n")
    files = [f for f in listdir("nvd/") if not f.startswith('.') and isfile(join("nvd/", f))]
else:
    r = requests.get('https://nvd.nist.gov/vuln/data-feeds')
    for filename in re.findall("nvdcve-1.1-[0-9]*.json.zip", r.text):
        print("Download of " + filename)
        r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
        with open("nvd/" + filename, 'wb') as f:
            for chunk in r_file:
                f.write(chunk)
    files = [f for f in listdir("nvd/") if not f.startswith('.') and isfile(join("nvd/", f))]
files.sort()

skip = False
i = 0
j = 0
for file in files:
    if len(sys.argv) >= 2 and sys.argv[1] == "u":
        dirname = "nvd_recent"
    else:
        dirname = "nvd/"
    archive = zipfile.ZipFile(join(dirname, file), 'r')
    jsonfile = archive.open(archive.namelist()[0])
    cve_dict = json.loads(jsonfile.read().decode('utf8'))
    jsonfile.close()

    new_tag = MISPTag()
    tag_text = 'NVD dump'
    new_tag.from_dict(name=tag_text, colour=color)
    misp.add_tag(new_tag)

    for cve in cve_dict['CVE_Items']:
        mispEvent = MISPEvent()
        cve_info = cve['cve']['CVE_data_meta']['ID']
        # Salto fino a {cve info}
        if not skip and len(sys.argv) == 3 and sys.argv[2] not in cve_info:
            print(cve_info + " skipped\n")
            continue
        elif not skip and len(sys.argv) == 3 and sys.argv[2] in cve_info:
            skip = True

        # Raccolgo informazioni sul contenuto del cve
        # Leggo il punteggio per ricavare il livello della minaccia

        try:
            score = cve['impact']['baseMetricV3']['cvssV3']['baseScore']
            if score < 4:
                cve_threat = 3
            elif score >= 4 and score <= 8:
                cve_threat = 2
            else:
                cve_threat = 1
        except Exception:
            cve_threat = 4

        cve_distrib = 2  # Solo per questa istanza
        cve_analysis = 2  # Analisi completata

        # cerco se l'evento gia' esiste
        cve_comment = cve['cve']['description']['description_data'][0]['value']
        result = misp.search_index(eventinfo=cve_info)

        # Verifico che il CVE non sia stato ritirato
        if "** REJECT **" in cve_comment:
            continue

        # Aggiorno eventuale evento esistente
        if len(result) != 0:
            cve_id = result[0]['id']
            event = misp.get_event(cve_id)
            print(f"{cve_info} already exists: {event['Event']['uuid']}\n")
            j = j + 1
        else:
            cve_date = cve['publishedDate']
            mispEvent.analysis = cve_analysis
            mispEvent.date = cve_date
            mispEvent.distribution = cve_distrib
            mispEvent.info = cve_info
            mispEvent.threat_level_id = cve_threat
            event = misp.add_event(mispEvent)
            print(f"{cve_info} added: {event['Event']['uuid']}\n")
            i = i + 1

        # Aggiungo la descrizione dell'evento
        cve_description = create_attribute('text', cve_comment, 'External analysis', 'CVE description')
        misp.add_attribute(event, cve_description)
        print("CVE description added to " + cve_info)

        # Adding direct link to the CVE
        cve_link = create_attribute('link', f'https://nvd.nist.gov/vuln/detail/{cve_info}', 'External analysis', 'CVE direct link')
        misp.add_attribute(event, cve_link)
        print(f'CVE direct link added to {cve_info}')

        # Aggiungo i link di riferimento del cve
        try:
            for ref in cve['cve']['references']['reference_data']:
                link = create_attribute('link', ref['url'], 'External analysis', 'Link linked to the CVE')
                misp.add_attribute(event, link)
            print(f"Added {len(cve['cve']['references']['reference_data'])} links into event {cve_info}\n")
        except Exception as e:
            print(e)
            print("No references added to " + cve_info + "\n")

        # Adding tags to identify the events comming from NVD dump
        misp.tag(event['Event']['uuid'], new_tag)

f = open("log.txt", "a")
f.write(f"{datetime.datetime.now()}\n")
f.write(f"Added {i} new events\n")
f.write(f"Found {j} events already existed\n")
f.write("----------------------------------------\n")
f.close()
