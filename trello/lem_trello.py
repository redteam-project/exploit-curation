#!/usr/bin/env python

import yaml
import trello
from jinja2 import Template
import requests
from BeautifulSoup import BeautifulSoup
from HTMLParser import HTMLParser

h = HTMLParser()

board_id = '59d783e1223296065e9347d1'
rhel7_mapped_id = '59d783f012bd1e829eca3d9d'
rhel7_curated_id = '59d783f4998482cf43a130be'
label_vulnerable_id = '59d783e11314a339990503e2'
label_notvulnerable_id = '59d783e11314a339990503e4'

test_system = 'RHEL 7.0, no patches'

description_mapped_template = Template("""
**Source**: EDB
**EDB ID**: {{ edb_id }}
**EDB URL**: {{ edb_url }}
**CVE IDs**: {{ cve_ids }}
**Test system reproducer**: {{ test_system }}
""")

description_curated_template = Template("""
**Source**: EDB
**EDB ID**: {{ edb_id }}
**EDB URL**: {{ edb_url }}
**CVE IDs**: {{ cve_ids }}
**Test system reproducer**: {{ test_system }}
**CPE**: {{ cpe }}
**Scoring standard**: {{ scoring }}
**Score**: {{ score }}
""")

# don't forget to add auth.yaml to your .gitignore!
with open('auth.yml') as f:
    y = yaml.safe_load(f)

with open('rhel7_cves.csv') as f:
    rhel7_cves_csv = f.readlines()

exploits = {}
for line in rhel7_cves_csv:
    if len(line.split(',')) > 2:
        edb_id, cve_id, cpe, scoring, score = line.split(',')
        if exploits.get(edb_id):
            exploits[edb_id]['cve_ids'] = exploits[edb_id]['cve_ids'] + ', ' + cve_id.rstrip()
        else:
            exploits[edb_id] = {}
            exploits[edb_id]['edb_id'] = edb_id
            exploits[edb_id]['cve_ids'] = cve_id.rstrip()
            exploits[edb_id]['cpe'] = cpe
            exploits[edb_id]['scoring'] = scoring
            exploits[edb_id]['score'] = score
            exploits[edb_id]['curated'] = True
    else:
        edb_id, cve_id = line.split(',')
        if exploits.get(edb_id):
            exploits[edb_id]['cve_ids'] = exploits[edb_id]['cve_ids'] + ', ' + cve_id.rstrip()
        else:
            exploits[edb_id] = {}
            exploits[edb_id]['edb_id'] = edb_id
            exploits[edb_id]['cve_ids'] = cve_id.rstrip()

# TODO: assess centos 7 and fedora 26, add their cves

client = trello.TrelloClient(
    api_key=y['auth']['api_key'],
    api_secret=y['auth']['api_secret'],
    token=y['auth']['token'],
    token_secret=y['auth']['token_secret']
)
elem_board = client.get_board(board_id=board_id)
elem_labels = elem_board.get_labels()
rhel7_mapped = elem_board.get_list(rhel7_mapped_id)
rhel7_mapped_cards = rhel7_mapped.list_cards()
rhel7_curated = elem_board.get_list(rhel7_curated_id)
rhel7_curated_cards = rhel7_curated.list_cards()

rhel7_mapped_extant = {}
for card in rhel7_mapped_cards:
    rhel7_mapped_extant[card.name] = card.id

rhel7_curated_extant = {}
for card in rhel7_curated_cards:
    rhel7_curated_extant[card.name] = card.id

counter = 0
for key in exploits.keys():
    exploit = exploits[key]

    edb_url = 'https://www.exploit-db.com/exploits/' + exploit['edb_id'] + '/'
    headers = {'User-Agent': 'Mozilla/5.0'}
    edb_html = requests.get(edb_url, headers=headers)
    soup = BeautifulSoup(edb_html.content)
    title_tag = soup.findAll('h1', itemprop='headline')
    title = h.unescape(title_tag[0].contents[0])

    if exploit.get('curated'):
        if rhel7_curated_extant.get(title):
            continue
        description = description_curated_template.render({'edb_id': exploit['edb_id'],
                                                         'edb_url': edb_url,
                                                         'cve_ids': exploit['cve_ids'],
                                                         'test_system': test_system,
                                                         'cpe': exploit['cpe'],
                                                         'scoring': exploit['scoring'],
                                                         'score': exploit['score']})
        # TODO: labeling logic isn't working for some reason. need to fix
        # if exploit['score'] == '000000':
        #     label_id = label_notvulnerable_id
        # else:
        #     label_id = label_vulnerable_id
        # rhel7_curated.add_card(name=title,
        #                        desc=description,
        #                        labels=[label_id])
        rhel7_curated.add_card(name=title,
                               desc=description)
    else:
        if rhel7_mapped_extant.get(title):
            continue
        description = description_mapped_template.render({'edb_id': exploit['edb_id'],
                                                         'edb_url': edb_url,
                                                         'cve_ids': exploit['cve_ids'],
                                                         'test_system': test_system})
        rhel7_mapped.add_card(name=title,
                              desc=description)

    print str(counter) + ': ' + title
    counter += 1


1