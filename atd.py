#!/usr/bin/env python3
# Afovos Threat Detection System.
# Copyright (c) 2023 Afovos <afovos at afovos.com.au>
# Author: Allan Abendanio

import os
import sys
import pytz
import json
import yaml
import time
import socket
import logging
import grequests
import datetime
import argparse
import requests
import warnings
import subprocess
import configparser
from pprint import pprint
from tabulate import tabulate
from datetime import timedelta
from os.path import dirname, abspath
from elasticsearch import Elasticsearch

warnings.filterwarnings("ignore")
# logging.basicConfig(filename='/var/log/salt/minion', level=logging.INFO, format='%(asctime)s [%(levelname)s] [%(process)d] %(message)s')

RULESDIR = '/opt/atd/scirius.rules'
CONFIG = ["alert","drop","log","pass","reject","sdrop","activate","dynamic", "config"]


def process(r, index_events):
	try:
		verbose('[-] Getting UTC, Local, PH Timezone.')
		UTC_timezone = pytz.timezone('UTC')
		adelaide_timezone = pytz.timezone('Australia/Adelaide')
		ph_timezone = pytz.timezone('Asia/Manila')
		original = datetime.datetime.strptime(r['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=pytz.utc)
		UTC = original.astimezone(UTC_timezone)
		adl = original.astimezone(adelaide_timezone)
		ph = original.astimezone(ph_timezone)
		transfered = datetime.datetime.now()
		r['id'] = int(datetime.datetime.timestamp(datetime.datetime.now()))
		r['timestamp_utc'] = UTC.strftime('%Y-%m-%dT%H:%M:%S') + '.%03d' % (UTC.microsecond / 1000) + 'Z'
		r['timestamp_local'] = adl.strftime('%Y-%m-%dT%H:%M:%S') + '.%03d' % (adl.microsecond / 1000) + adl.strftime('%z')
		r['timestamp_ph'] = ph.strftime('%Y-%m-%dT%H:%M:%S') + '.%03d' % (ph.microsecond / 1000) + ph.strftime('%z')
		r['timestamp_transfered'] = transfered.strftime('%Y-%m-%d %H:%M:%S') + '.%03d' % (transfered.microsecond / 1000)

		verbose('[-] Processing alert data.')
		r['dst_ip'] = r['dest_ip']
		del r['dest_ip']
		r['dst_port'] = r['dest_port']
		del r['dest_port']
		if r['alert']['severity'] == 1 or r['alert']['severity'] == 2:
			r['description'] = 'directive_event: ' + r['alert']['signature']
		else:
			r['description'] = r['alert']['signature']
		r['site'] = site
		r['device_ip'] = siem
		r['scanner'] = 'ATD'
		try:
			r['location'] = {'lat': r['geoip']['latitude'], 'lon': r['geoip']['longitude']}
		except:
			r['location'] = None

		if a.elastic:
			verbose('[-] Sending processed alert data to master Elasticsearch.') 
			elastic_search(r, index_events)
		if a.logz:
			verbose('[-] Sending processed alert data to Logz.io.') 
			logz_loader(r)
	except Exception as e:
		print('[!] ERROR on process: %s' % (e))
		# logging.error('[!] ERROR on process: %s' % (e))


def master_indices(profile):
	index = f'events-{profile}*'
	indices = list(mes.indices.get_alias(index).keys())
	if not indices:
		indices = []

	return indices


def minion_indices(profile):
	bodies = "curl -s -XGET 'http://" + parameter + ":9200/_cat/indices/logstash-alert*?&s=index:desc&h=index'"
	responses = subprocess.Popen(['salt', profile, 'cmd.run', bodies], stdout=subprocess.PIPE)
	response = responses.stdout.readlines()
	indices = [s.strip().decode() for s in response]
	if not indices:
		indices = []

	return indices


def get_mis_alert(i):
	try:
		master_index = f'events-{profile}-{i}'
		minion_index = f'logstash-alert-{i}'
		last_timestamp = ''
		while True:
			minion_total = 0
			try:
				bodies = "curl -s 'http://" + parameter + ":9200/" + minion_index + "/_count'"
				responses = subprocess.Popen(['salt', profile, 'cmd.run', bodies], stdout=subprocess.PIPE)
				response = responses.stdout.readlines()
				result = json.loads(response[1])
				minion_total = result['count']
			except Exception as e:
				print(f'[+] {e}')
				# logging.error(f'[!] {e}')

			master_total = 0
			try:
				time.sleep(2)
				response = mes.count(index=master_index)
				master_total = response['count']
			except Exception as e:
				print(f'[!] {e}')
				# logging.error(f'[!] {e}')

			difference = int(minion_total) - int(master_total)

			if difference <= 0:
				break

			if difference >= a.max:
				difference = a.max

			if not last_timestamp:
				body = "curl -s 'http://" + parameter + ":9200/" + minion_index + "/_search?size=" + str(difference) + "&sort=timestamp:desc' -H 'Content-Type: application/json'"
				responses = subprocess.Popen(['salt', profile, 'cmd.run', body], stdout=subprocess.PIPE)
				response = responses.stdout.readlines()
				result = json.loads(response[1])
				last_timestamp = result['hits']['hits'][-1]['sort'][0]
			else:
				body = "curl -s 'http://" + parameter + ":9200/" + minion_index + "/_search' -H 'Content-Type: application/json' -d '{\"size\": difference, \"sort\": {\"@timestamp\": \"desc\"}, \"search_after\": [last_timestamp], \"query\": {\"match_all\": {}}}'"
				body = body.replace("difference", str(difference))
				body = body.replace("last_timestamp", str(last_timestamp))
				responses = subprocess.Popen(['salt', profile, 'cmd.run', body], stdout=subprocess.PIPE)
				response = responses.stdout.readlines()
				result = json.loads(response[1])
				try:
					last_timestamp = result['hits']['hits'][-1]['sort'][0]
				except:
					break

			print(difference)
			for re in result['hits']['hits']:
				r = re['_source']
				r['logstash_index'] = re['_index']
				r['logstash_id'] = re['_id']
				if a.notification:
					verbose('[-] Notify user if serverity is high or critical.') 
					if r['alert']['severity'] == 1 or r['alert']['severity'] == 2:
						y = yaml.safe_dump(r, default_flow_style=False)
						y = "******** WARNING! WARNING! WARNING! *********\nDETECTED ON " + profile +  " " + r['description'] + " " + str(r['alert']['signature_id']) + "\n" + y + "******** WARNING! WARNING! WARNING! *********"
						viber_alert(y)
				process(r, master_index)
	except Exception as e:
		print('[!] ERROR on get_miss_alert: %s' % (e))
		# logging.error('[!] ERROR on get_miss_alert: %s' % (e))


def main(parameter, profile):
	#TODO: disable job
	# master = socket.gethostname()
	# os.system(f"salt {master} schedule.disable_job job_{profile}")

	try:
		masters = master_indices(profile)
		minions = minion_indices(profile)[1:]

		master = [s[-10:] for s in masters]
		minion = [s[-10:] for s in minions]
		# print(master, minion)
		index_difference = sorted(list(set(minion) - set(master)))
		print(index_difference)

		present_minion = sorted(minion)[-1]
		present_master = sorted(master)[-1]

		if not index_difference:
			index_difference = [present_minion]

		master_current_date = datetime.datetime.strptime(present_master[-10:], '%Y.%m.%d')
		minion_current_date = datetime.datetime.strptime(present_minion[-10:], '%Y.%m.%d')
		date_diff = minion_current_date - master_current_date
		if date_diff.days == 1:
			get_mis_alert(present_master)

		for i in index_difference:
			master_index = f'events-{profile}-{i}'
			minion_index = f'logstash-alert-{i}'
			last_timestamp = ''
			while True:	
				minion_total = 0
				try:
					bodies = "curl -s 'http://" + parameter + ":9200/" + minion_index + "/_count'"
					responses = subprocess.Popen(['salt', profile, 'cmd.run', bodies], stdout=subprocess.PIPE)
					response = responses.stdout.readlines()
					result = json.loads(response[1])
					minion_total = result['count']
				except Exception as e:
					print(f'[!] {e}')
					# logging.error(f'[!] {e}')

				master_total = 0
				try:
					time.sleep(2)
					response = mes.count(index=master_index)
					master_total = response['count']
				except Exception as e:
					print(f'[!] {e}')
					# logging.error(f'[!] {e}')

				difference = int(minion_total) - int(master_total)
				# print(difference, minion_total, master_total)

				if difference <= 0:
					break

				if difference >= a.max:
					difference = a.max

				if not last_timestamp:
					body = "curl -s 'http://" + parameter + ":9200/" + minion_index + "/_search?size=" + str(difference) + "&sort=timestamp:desc' -H 'Content-Type: application/json'"
					responses = subprocess.Popen(['salt', profile, 'cmd.run', body], stdout=subprocess.PIPE)
					response = responses.stdout.readlines()
					result = json.loads(response[1])
					last_timestamp = result['hits']['hits'][-1]['sort'][0]
				else:
					body = "curl -s 'http://" + parameter + ":9200/" + minion_index + "/_search' -H 'Content-Type: application/json' -d '{\"size\": difference, \"sort\": {\"@timestamp\": \"desc\"}, \"search_after\": [last_timestamp], \"query\": {\"match_all\": {}}}'"
					body = body.replace("difference", str(difference))
					body = body.replace("last_timestamp", str(last_timestamp))
					responses = subprocess.Popen(['salt', profile, 'cmd.run', body], stdout=subprocess.PIPE)
					response = responses.stdout.readlines()
					result = json.loads(response[1])
					try:
						last_timestamp = result['hits']['hits'][-1]['sort'][0]
					except:
						break

				print(difference)
				for re in result['hits']['hits']:
					r = re['_source']
					r['logstash_index'] = re['_index']
					r['logstash_id'] = re['_id']
					if a.notification:
						verbose('[-] Notify user if serverity is high or critical.') 
						if r['alert']['severity'] == 1 or r['alert']['severity'] == 2:
							y = yaml.safe_dump(r, default_flow_style=False)
							y = "******** WARNING! WARNING! WARNING! *********\nDETECTED ON " + profile +  " " + r['description'] + " " + str(r['alert']['signature_id']) + "\n" + y + "******** WARNING! WARNING! WARNING! *********"
							viber_alert(y)
					process(r, master_index)
	except Exception as e:
		print('[!] ERROR on main: %s' % (e))
		# logging.error('[!] ERROR on main: %s' % (e))
	# os.system(f"salt {master} schedule.enable_job job_{profile}")


def validate_ip(s):
	a = s.split('.')
	if len(a) != 4:
		return False
	for x in a:
		if not x.isdigit():
			return False
		i = int(x)
		if i < 0 or i > 255:
			return False
	return True


def elastic_search(results, index_events):
	try:
		auth_json = json.dumps(results)

		if not mes.indices.exists(index=index_events):
			res = mes.indices.create(index=index_events, settings=request_body)
			print("[-] Response: %s" % res)

		mes.index(index=index_events, document=auth_json)
		print('[+] Successfully pushed alerts data to Elasticsearch from %s.' % (profile))
		# logging.info('[+] Successfully pushed alerts data to Elasticsearch from %s.' % (profile))
	except Exception as e:
		print('[!] Elasticsearch Error: %s' % (e))
		# logging.error('[!] Elasticsearch Error: %s' % (e))


def logz_loader(data):
	with open('output.json', 'w') as f:
		json.dump(data, f)

	response = os.popen('curl -T output.json https://listener-au.logz.io:8071/?token=eXFjFxRkSdsmtHIboiKcKEsgYfLqPjen').readlines()
	print(response)
	# logging.info(response)


def viber_alert(data): # Alert on viber Afobot
	headers = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0',
		'Accept': '*/*',
		'Accept-Language': 'en-US,en;q=0.5',
		'X-Viber-Auth-Token': '4de14050ffe7d8bf-9a6d2608a4fa259b-d9e3f3642b0f9ad1',
		'Connection': 'keep-alive',
		'x-viber-content-signature': 'a4dfbb2407d16354089a2e084ca86b3de21b73a22c37331609375c7caaeef11e',
		'Content-Type': 'application/json',
		'Accept-Encoding': 'gzip, deflate, br',
	}
	body = {
		"receiver":"2LUXspgINOpo9NEfjm2vGA==",
		"min_api_version":1,
		"sender":{
			"name":"AfoBot",
			"avatar":"http://viber.com/avatar.jpg"
		},
		"tracking_data":"tracking data",
		"type":"text",
		"text":data
	}
	response = requests.post('https://chatapi.viber.com/pa/send_message', headers=headers, data=json.dumps(body))
	result = response.json()
	if result['status'] == 0:
		print('[+] Successfully send alerts on Afovos Viber from %s.' % (profile))
		# logging.info('[+] Successfully send alerts on Afovos Viber from %s.' % (profile))
	else:
		print('[!] Viber has failed to send alerts. Error: %s' % response.text)
		# logging.error('[!] Viber has failed to send alerts. Error: %s' % response.text)


def divide_chunks(l, n):
	for i in range(0, len(l), n):
		yield l[i:i + n]


def get_status():
	package = os.popen('docker exec scirius dpkg -s sqlite3').readlines()
	if len(package) <= 2:
		os.system("docker exec scirius bash -c 'apt-get update -y; apt-get upgrade -y; apt-get install sqlite3 -y'")
	# rules = os.popen('docker exec scirius sqlite3 data/scirius.sqlite3 "select sid, msg from rules_rule inner join rules_ruletransformation on rules_rule.sid = rules_ruletransformation.rule_transformation_id;"').readlines()
	rules = os.popen('docker exec scirius sqlite3 data/scirius.sqlite3 "select rule_id, threshold_type, net, count, seconds, track_by from rules_threshold;"').readlines()
	status = []
	for r in rules:
		stat = {}
		stats = r.split('|')
		# stat['status'] = 'OFF'
		# stat['sid'] = stats[0]
		# stat['msg'] = stats[1]
		stat['rule_id'] = stats[0]
		stat['threshold_type'] = stats[1]
		stat['net'] = stats[2]
		stat['count'] = stats[3]
		stat['seconds'] = stats[4]
		stat['track_by'] = stats[5]
		status.append(stat)

	return status


def threshold(threshold):
	try:
		package = os.popen('docker exec scirius dpkg -s sqlite3').readlines()
		if len(package) <= 2:
			os.system("docker exec scirius bash -c 'apt-get update -y; apt-get upgrade -y; apt-get install sqlite3 -y'")
		# rules = os.popen(f'''docker exec scirius sqlite3 data/scirius.sqlite3 "insert into rules_threshold(descr, threshold_type, gid, track_by, net, count, seconds, rule_id, ruleset_id, type) values ('', 'threshold', 1, 'by_src', '', 1, 60, 2404300, 1, 'limit');"''').readlines()
		os.popen(f'''docker exec scirius sqlite3 data/scirius.sqlite3 "insert into rules_threshold(descr, threshold_type, gid, track_by, net, count, seconds, rule_id, ruleset_id, type) values ('', 'threshold', 1, 'by_src', '', {threshold[1]}, {threshold[2]}, {threshold[0]}, 1, 'both');"''').readlines()
		print('[+] Successfully threshold sid %s.' % (threshold[0]))
	except Exception as e:
		print('[!] ERROR on threshold: %s' % (e))
		# logging.error('[!] ERROR on threshold: %s' % (e))

def suppress(suppress):
	try:
		# print(type(suppress[1]))
		package = os.popen('docker exec scirius dpkg -s sqlite3').readlines()
		if len(package) <= 2:
			os.system("docker exec scirius bash -c 'apt-get update -y; apt-get upgrade -y; apt-get install sqlite3 -y'")
		os.popen(f'''docker exec scirius sqlite3 data/scirius.sqlite3 "insert into rules_threshold(descr, threshold_type, gid, track_by, net, count, seconds, rule_id, ruleset_id, type) values ('', 'suppress', 1, '{suppress[2]}', '{suppress[1]}', 0, 0, {suppress[0]}, 1, 'both');"''').readlines()
		print('[+] Successfully suppress sid %s.' % (suppress[0]))
	except Exception as e:
		print('[!] ERROR on suppress: %s' % (e))
		# logging.error('[!] ERROR on suppress: %s' % (e))


def un_threshold_suppress(rule, flag):
	try:
		package = os.popen('docker exec scirius dpkg -s sqlite3').readlines()
		if len(package) <= 2:
			os.system("docker exec scirius bash -c 'apt-get update -y; apt-get upgrade -y; apt-get install sqlite3 -y'")
		os.popen(f'''docker exec scirius sqlite3 data/scirius.sqlite3 "DELETE FROM rules_threshold WHERE rule_id = {rule} AND threshold_type = '{flag}';"''').readlines()
		print(f'[+] Successfully un{flag} sid {rule}')
	except Exception as e:
		print('[!] ERROR on un_threshold_suppress: %s' % (e))
		# logging.error('[!] ERROR on un_threshold_suppress: %s' % (e))


def verbose(message):
	if a.verbose:
		print(message)


def query(index, value, value2):
	query = {
		"track_total_hits": True,
		"query": {
			"range": {
					"@timestamp": {
						"gte": value,
						"lte": value2
				}
			}
		}
	}
	result = es.search(index=index, body=query)

	return result['hits']["total"]["value"]


if __name__ == "__main__":
	try:
		example_text = '''example:
  python3 atd.py local
  python3 atd.py local 80000
  python3 atd.py -f minions.txt
  python3 atd.py selk01,selk02,selk03 80000 --elastic'''

		host = socket.gethostname()
		params = argparse.ArgumentParser(description='Afovos Threat Detection System', epilog=example_text, formatter_class=argparse.RawDescriptionHelpFormatter)
		params.add_argument('profile', nargs='?', default=host, type=str, metavar='minions', help="minions profile, sections on a config file that will lookup for IP address and cookie")
		params.add_argument('max', nargs='?', default=2000, type=int, metavar='max', help="Maximum number of alert data to be parse.")
		params.add_argument('-u', '--update', dest='update', action="store_true", help="Update sid rules.")
		params.add_argument('-s', '--status', dest='status', action="store_true", help="Status of sid rules.")
		params.add_argument('-t', '--threshold', dest='threshold', nargs='*', metavar='sid, count, seconds', help="")
		params.add_argument('-su', '--suppress', dest='suppress', nargs='*', metavar='sid, net, track_by', help="")
		params.add_argument('-ut', '--unthreshold', dest='unthreshold', metavar='sid', help="")
		params.add_argument('-us', '--unsuppress', dest='unsuppress', metavar='sid', help="")
		params.add_argument('-f', '--file', dest='file', metavar='file', help="input list file of minions profile that will be parse for atd alerts.")
		params.add_argument('-el', '--elastic', dest='elastic', action="store_true", help="save the parse results to Afovos ElasticSearch")
		params.add_argument('-l', '--logz', dest='logz', action="store_true", help="save the parse results to Logz.io")
		params.add_argument('-n', '--notification', dest='notification', action="store_true", help="Enable notification.")
		params.add_argument('-c', '--comparison', dest='comparison', nargs='?', const="local", help="Comparison of master and minions alert data.")
		params.add_argument('-de', '--debug', dest='debug', action="store_true", help="Setup log level to debug.")
		params.add_argument('-in', '--info', dest='info', action="store_true", help="Setup log level to info.")
		params.add_argument('-ve', '--verbose', dest='verbose', action="store_true", help="Turn on verbose.")
		params.add_argument('-v', '--version', action='version', version='%(prog)s 0.09')

		a = params.parse_args()
		verbose('[-] Initializing variables.')
		profile = ''
		profiles = []

		verbose('[-] Initializing Config settings.')
		config = configparser.ConfigParser()
		path = abspath(dirname(__file__))
		config.read(path + '/atd.conf')
		# site = socket.gethostname
		# siem = socket.gethostbyname(site + ".local")
		# TODO: if profile is many
		if a.profile:
			site = a.profile
		else:
			site = socket.gethostname()
		siem = config.get(site, 'siem_host')
		token = config.get(site, 'token')

		verbose('[-] Initializing Elasticsearch settings.')
		es_host = config.get(site, 'es_host')
		es = Elasticsearch(es_host, retry_on_Offline=True, read_Offline=2000)
		master = socket.gethostname()
		mes_host = config.get(master, 'mes_host')
		mes = Elasticsearch(mes_host, retry_on_Offline=True, read_Offline=2000)
		request_body = {
			"number_of_shards": 2,
			"number_of_replicas": 0
		}

		if a.debug:
			verbose('[-] Changing log level of minion to debug.')
			with open('/etc/salt/minion', 'r') as file :
				filedata = file.read()
			filedata = filedata.replace('log_level: info', 'log_level: debug')
			with open('/etc/salt/minion', 'w') as file:
				file.write(filedata)
			os.system('sudo systemctl restart salt-minion')
			exit(0)

		if a.info:
			verbose('[-] Changing log level of minion to info.')
			with open('/etc/salt/minion', 'r') as file :
				filedata = file.read()
			filedata = filedata.replace('log_level: debug', 'log_level: info')
			with open('/etc/salt/minion', 'w') as file:
				file.write(filedata)
			os.system('sudo systemctl restart salt-minion')
			exit(0)


		if a.comparison:
			minion_index = "logstash-alert*"
			indices = es.indices.get_alias(minion_index).keys()
			total_hits = 0
			if indices:
				index = sorted(indices)[-1]
				index2 = sorted(indices)[-2]
				mid = index[-10:].replace(".", "-")
				midnight = mid + "T00:00:00"

				local_midnights = datetime.datetime.strptime(midnight, '%Y-%m-%dT%H:%M:%S') - timedelta(hours=9, minutes=30)
				if a.comparison.lower() == 'utc' or a.comparison.lower() == 'u':
					local_midnights = datetime.datetime.strptime(midnight, '%Y-%m-%dT%H:%M:%S')
				local_midnight = local_midnights.strftime('%Y-%m-%dT%H:%M:%S')

				now = 'now-5m'
				result = query(index, midnight, now)
				result2 = query(index2, local_midnight, midnight)
				result_now = int(result) + int(result2)
				verbose(f'[-] Getting docs {index} total count {result_now}.')

				ten = "now-10m"
				result = query(index, midnight, ten)
				result2 = query(index2, local_midnight, midnight)
				result_ten = int(result) + int(result2)

				last_hours = datetime.datetime.now().replace(microsecond=0, second=0, minute=0)
				minutes_diff = (datetime.datetime.now() - last_hours).total_seconds() / 60.0
				rounded = round(minutes_diff)
				last_hour = f"now-{rounded}m"
				result = query(index, midnight, last_hour)
				result2 = query(index2, local_midnight, midnight)
				result_last_hour = int(result) + int(result2)
			print(f"[+] {host.capitalize()} now - {result_now}, 10min - {result_ten}, last_hr - {result_last_hour}")
			exit(0)

		if a.threshold:
			verbose('[-] Thresholding sid rules.')
			threshold(a.threshold)
			exit(0)

		if a.suppress:
			verbose('[-] Suppressing sid rules.')
			suppress(a.suppress)
			exit(0)

		if a.unthreshold:
			verbose('[-] Unthresholding sid rules.')
			un_threshold_suppress(a.unthreshold, "threshold")
			exit(0)

		if a.unsuppress:
			verbose('[-] Unsuppressing sid rules.')
			un_threshold_suppress(a.unsuppress, "suppress")
			exit(0)

		if a.update:
			verbose('[-] Updating sid rules.')
			os.system('docker exec scirius python /opt/scirius/manage.py updatesuricata || echo "Eroor on pushing ruleset to suricata!"')
			exit(0)

		if a.status:
			verbose('[-] Status sid rules.')
			get_stat = get_status()
			pdtabulate=lambda summary_str:tabulate(get_stat, headers='keys', tablefmt='psql')
			print(pdtabulate(get_stat))
			exit(0)

		if a.profile:
			if ',' in a.profile:
				profiles = [x.strip() for x in a.profile.split(',')]
			else:
				profile = a.profile
		if a.file:
			f = open(a.file,'r')
			profiles = f.readlines()

		if profile:
			parameter = config.get(profile, 'parameter')
			main(parameter, profile)
		elif profiles:
			for profile in profiles:
				try:
					parameter = config.get(profile, 'parameter')
					main(parameter, profile)
				except Exception as e:
					if 'No section' in str(e):
						print('[!] No %s minion on atd.conf please fill up user, site, parameter etc. first on conf file.' % profile)
						# logging.warning('[!] No %s minion on atd.conf please fill up user, site, parameter etc. first on conf file.' % profile)
					pass
		else:
			params.print_help()
			# main()
	except Exception as e:
		if 'No section' in str(e):
			print('[!] No %s minion on atd.conf please fill up user, site, parameter etc. first on conf file.' % a.profile)
			# logging.warning('[!] No %s minion on atd.conf please fill up user, site, parameter etc. first on conf file.' % a.profile)
		else:
			print('[!] ATD experienced an Error: %s report it to Allan of Afovos.' % e)
			# logging.error('[!] ATD ERROR: %s report it to Allan of Afovos.' % e)