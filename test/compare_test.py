import os
import yaml
import json
import time
import socket
import logging
import requests
import datetime
import argparse
import warnings
import subprocess
import configparser
from datetime import timedelta
from pprint import pprint
from os.path import dirname, abspath
from elasticsearch import Elasticsearch

warnings.filterwarnings("ignore")

def default_all(minion):
	if ',' in minion:
		minion = f"-L '{minion}'"
	if minion.lower() == 'all' or minion.lower() == 'a':
		minion = "'*'"
	return minion


def default_schedule(value):
	current_date = datetime.date.today()
	minion = "'*'"
	job = ""
	range = "5"
	max = "1000"
	elastic = "elastic"
	integer = []
	string = []

	for v in value:
		if v.isdigit():
			integer.append(v)
		else:
			string.append(v)

	try:
		minion = default_all(string[0])
		job = string[1]
		if "elastic" in string[2].lower():
			elastic = "elastic"
		if "log" in string[2].lower():
			elastic = "logz"
	except:
		pass

	try:
		range = integer[0]
		max = integer[1]
	except:
		pass

	return minion, job, range, max, elastic


def verbose(message):
	if a.verbose:
		print(message)


def query(index, value, value2):
	query = {
		"track_total_hits": True,
		"query": {
			"range": {
					"timestamp": {
						"gte": value,
						"lte": value2
				}
			}
		}
	}
	result = mes.search(index=index, body=query)

	return result['hits']["total"]["value"]

def query2(index, value, value2):
	query = {
		"track_total_hits": True,
		"query": {
			"range": {
					"timestamp": {
						"gte": value,
						"lte": value2
				}
			}
		}
	}
	result = es.search(index=index, body=query)

	return result['hits']["total"]["value"]

def comparison(minion):
	verbose(f'[-] Getting total events of {minion}.')
	total_hits = os.popen(f'salt {minion} cmd.run "python3 /opt/atd/test/compare_test.py -cm"').readlines()
	# total_hits = os.popen(f'salt {minion} cmd.run "python3 /opt/atd/atd.py -c"').readlines()
	print(total_hits[1].strip())

	verbose(f'[-] Getting total events on master for {minion}.')
	master_index = f'events-{minion}*'
	indices = mes.indices.get_alias(master_index).keys()

	if indices:
		index = sorted(indices)[-1]
		mid = index[-10:].replace(".", "-")
		midnight = mid + "T00:00:00"

		now = 'now'
		result_now = query(index, midnight, now)
		verbose(f'[-] Getting docs {index} total count {result_now}.')

		ten = "now-10m"
		result_ten = query(index, midnight, ten)

		last_hours = datetime.datetime.now().replace(microsecond=0, second=0, minute=0)
		minutes_diff = (datetime.datetime.now() - last_hours).total_seconds() / 60.0
		rounded = round(minutes_diff)
		last_hour = f"now-{rounded}m"
		result_last_hour = query(index, midnight, last_hour)
		print(f"[+] Master now - {result_now}, 10min - {result_ten}, last_hr - {result_last_hour}")


if __name__ == "__main__":
	try:
		example_text = ''''''
		master = socket.gethostname()
		params = argparse.ArgumentParser(description='Afovos Security Operations Center', epilog=example_text, formatter_class=argparse.RawDescriptionHelpFormatter)
		params.add_argument('-c', '--comparison', dest='comparison', nargs='?', const="'*'", type=str, metavar='minion', help="")
		params.add_argument('-cm', '--comparison_minion', dest='comparison_minion', action="store_true", help="")
		params.add_argument('-ve', '--verbose', dest='verbose', action="store_true", help="")
		a = params.parse_args()

		config = configparser.ConfigParser() # Config settings
		path = abspath(dirname(__file__))
		config.read(path + '/atd.conf')
		mes_host = config.get(master, 'mes_host')
		mes = Elasticsearch(mes_host, retry_on_Offline=True, read_Offline=2000)
		site = socket.gethostname()
		es_host = config.get(site, 'es_host')
		es = Elasticsearch(es_host, retry_on_Offline=True, read_Offline=2000)

		if a.comparison:
			mini = os.popen('ls -1 /var/cache/salt/master/minions').readlines()
			minions = [s.rstrip() for s in mini]
			minion = default_all(a.comparison)
			if minion == "'*'":
				for m in minions:
					comparison(m)
			else:
				comparison(minion)
			exit(0)

		if a.comparison_minion:
			minion_index = "logstash-alert*"
			indices = es.indices.get_alias(minion_index).keys()

			if indices:
				index = sorted(indices)[-1]
				mid = index[-10:].replace(".", "-")
				midnight = mid + "T00:00:00"

				now = 'now'
				result_now = query2(index, midnight, now)
				verbose(f'[-] Getting docs {index} total count {result_now}.')

				ten = "now-10m"
				result_ten = query2(index, midnight, ten)

				last_hours = datetime.datetime.now().replace(microsecond=0, second=0, minute=0)
				minutes_diff = (datetime.datetime.now() - last_hours).total_seconds() / 60.0
				rounded = round(minutes_diff)
				last_hour = f"now-{rounded}m"
				result_last_hour = query2(index, midnight, last_hour)
				print(f"[+] {site.capitalize()} now - {result_now}, 10min - {result_ten}, last_hr - {result_last_hour}")
			exit(0)

	except Exception as e:
		print('[!] ASOC experienced an Error: %s report it to Allan of Afovos.' % e)
		logging.error('[!] ASOC encountered an Error: %s report it to Allan of Afovos.' % e)