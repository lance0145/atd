#!/usr/bin/env python3
# Afovos Security Operations Center.
# Copyright (c) 2023 Afovos <afovos at afovos.com.au>
# Author: Allan Abendanio

import os
import yaml
import json
import time
import socket
import logging
import requests
import datetime
import ipaddress
import argparse
import warnings
import subprocess
import configparser
from datetime import timedelta
from pprint import pprint
from os.path import dirname, abspath
from elasticsearch import Elasticsearch

warnings.filterwarnings("ignore")
# logging.basicConfig(filename='/var/log/salt/minion', level=logging.INFO, format='%(asctime)s [%(levelname)s] [%(process)d] %(message)s')


def default_all(minion):
	if ',' in minion:
		minion = f"-L '{minion}'"
	if minion.lower() == 'all' or minion.lower() == 'a':
		minion = "'*'"
	return minion


def default(value):
	minion = "'*'"
	sid = "all"
	if len(value) == 1:
		if value[0] == "'*'" or value[0].lower() == 'all':
			pass
		elif value[0].isdigit():
			sid = value[0]
		else:
			minion = value[0]
	elif len(value) > 1:
		minion = default_all(value[0])
		sid = value[1]
	return minion, sid


def default_schedule(value):
	# current_date = datetime.date.today()
	# date_string = current_date.strftime('%Y-%m-%d')
	minion = "'*'"
	# job = "job_" + date_string
	job = ""
	range = "5"
	max = "1000"
	splay = "60"
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
		splay = integer[2]
	except:
		pass

	# ranges = int(range) * 60
	# return minion, job, str(ranges), elastic #,delay
	return minion, job, range, max, elastic, splay


def default_threshold(value):
	minion = "'*'"
	# job = "job_" + date_string
	sid = ""
	count = "1"
	seconds = "60"
	integer = []
	string = []

	for v in value:
		if v.isdigit():
			integer.append(v)
		else:
			string.append(v)

	try:
		minion = default_all(string[0])
	except:
		pass

	try:
		sid = integer[0]
		count = integer[1]
		seconds = integer[2]
	except:
		pass

	return minion, sid, count, seconds


def default_suppress(value):
	minion = "'*'"
	sid = ""
	net = "0.0.0.0/0"
	track_by = "by_src"
	integer = []
	string = []

	def has_numbers(inputString):
		return any(char.isdigit() for char in inputString)

	for v in value:
		if has_numbers(v):
			integer.append(v)
		else:
			string.append(v)

	try:
		minion = default_all(string[0])
		if "dst" in string[1].lower() or "dest" in string[1].lower():
			track_by = "by_dst"
	except:
		pass

	try:
		sid = integer[0]
		net = integer[1]
	except:
		pass

	return minion, sid, net, track_by


def default_un(value):
	minion = "'*'"
	sid = ""

	for v in value:
		if v.isdigit():
			sid = v
		else:
			minion = default_all(v)

	return minion, sid


def default_job(value):
	minion = "'*'"
	job = ""
	if len(value) == 1:
		if value[0] == "'*'" or value[0].lower() == 'all':
			pass
		elif value[0].isdigit():
			job = value[0]
		else:
			minion = value[0]
	elif len(value) > 1:
		minion = default_all(value[0])
		job = value[1]
	return minion, job


def default_list(value):
	minion = "'*'"
	num = "10"
	if len(value) == 1:
		if value[0] == "'*'" or value[0].lower() == 'all':
			pass
		elif value[0].isdigit():
			num = value[0]
		else:
			minion = value[0]
	elif len(value) > 1:
		print("c")
		minion = default_all(value[0])
		num = value[1]
	return minion, num


def check_os(box):
	if "Ubuntu 20.04.6" in box or "Kali GNU/Linux Rolling" in box:
		os.system('mkdir /etc/apt/keyrings; \
			sudo curl -fsSL -o /etc/apt/keyrings/salt-archive-keyring.gpg https://repo.saltproject.io/salt/py3/ubuntu/20.04/amd64/SALT-PROJECT-GPG-PUBKEY-2023.gpg; \
			echo "deb [signed-by=/etc/apt/keyrings/salt-archive-keyring.gpg arch=amd64] https://repo.saltproject.io/salt/py3/ubuntu/20.04/amd64/latest focal main" | sudo tee /etc/apt/sources.list.d/salt.list \
		')


def open_port():
	try:
		verbose(f'[-] Configuring docker-compose.yml to open SELKS sevice port.')
		with open('/opt/SELKS/docker/docker-compose.yml', 'r') as file:
			docker = yaml.safe_load(file)
		scirius_service = docker['services']['scirius']
		kibana_service = docker['services']['kibana']
		elasticsearch_service = docker['services']['elasticsearch']
		try:
			scirius_ports = scirius_service['ports']
			scirius_expose = scirius_service['expose']
			kibana_ports = kibana_service['ports']
			kibana_expose = kibana_service['expose']
			elasticsearch_ports = elasticsearch_service['ports']
			elasticsearch_expose = elasticsearch_service['expose']
			return '[+] Elasticsearch/Scirius ports already open.'
		except:
			scirius_service['ports'] = ['127.0.0.1:8000:8000']
			scirius_service['expose'] = ['8000']
			kibana_service['ports'] = ['127.0.0.1:5601:5601']
			kibana_service['expose'] = ['5601']
			elasticsearch_service['ports'] = ['127.0.0.1:9200:9200']
			elasticsearch_service['expose'] = ['9200']
			with open('/opt/SELKS/docker/docker-compose.yml', 'w') as file:
				yaml.dump(docker, file, default_flow_style=False)
			# os.system(f"salt {minion} cmd.run 'cd /opt/SELKS/docker/; docker-compose up -d'")
			os.system('cd /opt/SELKS/docker/; docker-compose up -d')
			return '[+] Succesfully open Elasticsearch/Scirius ports.'
	except Exception as e:
		print('[!] ERROR on open_port: %s' % (e))
		# logging.error('[!] ERROR on open_port: %s' % (e))


# TODO: define gateway ip address
def create_dash(ip_address):
	try:
		files = "dashboard.ndjson"
		content = ''.join(open(files, 'r').readlines())
		url = 'http://' + ip_address + ':5601/api/kibana/dashboards/import?exclude=index-pattern'
		print('POST ' + url)
		response = requests.post(
			url,
			headers={'kbn-xsrf': 'true', 'Content-Type': 'application/json'},
			data=content
		)
		if "statusCode" not in response.text:
			print("[+] Successfully created dashboard!")
		elif response.status_code == 200:
			print("[+] Successfully created dashboard!")
		else:
			# print("[!] Error: " + response.text)
			pprint(response)

		data = {}
		files = "index-pattern.ndjson"
		with open(files, "r") as json_file:
			my_dict = json.load(json_file)
		data["version"] = "7.16.1"
		data["objects"] = []
		data["objects"].append(my_dict)
		app_json = json.dumps(data)
		url = 'http://' + ip_address + ':5601/api/kibana/dashboards/import'
		print('POST ' + url)
		response = requests.post(
			url,
			headers={'kbn-xsrf': 'true', 'Content-Type': 'application/json'},
			data=app_json
		)
		if "statusCode" not in response.text:
			print("[+] Successfully created index-pattern!")
		elif response.status_code == 200:
			print("[+] Successfully created index-pattern!")
		else:
			print("[!] Error: " + response.text)

		verbose(f'[-] Adding oDirectives dashboard link on SELKS side menu.')
		os.system("docker cp /opt/atd/header_right.html scirius:/opt/scirius/rules/templates/rules/header_right.html")
		with open('/opt/SELKS/docker/docker-compose.yml', 'r') as file:
			docker = yaml.safe_load(file)

		if '.:/code' not in docker['services']['scirius']['volumes']:
			docker['services']['scirius']['volumes'].append('.:/code')

			with open('/opt/SELKS/docker/docker-compose.yml', 'w') as file:
				yaml.dump(docker, file, default_flow_style=False)
			os.system('cd /opt/SELKS/docker/; docker-compose up -d')
	except Exception as e:
		print('[!] ERROR on create_dash: %s' % (e))
		# logging.error('[!] ERROR on create_dash: %s' % (e))


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


def requirements():
	os.system("pip install elasticsearch==7.17.7")
	os.system("pip install tabulate==0.9.0")
	os.system("pip install grequests==0.6.0")
	os.system("pip install pytz==2023.3")


def config_file():
	try:
		verbose(f'[-] Configuring log level and max event size of minion.')
		with open('/etc/salt/minion', 'r') as file :
			filedata = file.read()
		filedata = filedata.replace('#log_level: warning', 'log_level: info')
		filedata = filedata.replace('#max_event_size: 1048576', 'max_event_size: 99999999999999999999999')
		with open('/etc/salt/minion', 'w') as file:
			file.write(filedata)
		print('[+] Succesfully update minion config file.')
	except Exception as e:
		print('[!] ERROR on config_file: %s' % (e))
		# logging.error('[!] ERROR on config_file: %s' % (e))


def verbose(message):
	if a.verbose:
		print(message)


def query(index, value, value2):
	try:
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
		result = mes.search(index=index, body=query)
	except Exception as e:
		print('[!] ERROR on query: %s' % (e))
		# logging.error('[!] ERROR on query: %s' % (e))

	return result['hits']["total"]["value"]


def comparison(minion):
	try:
		verbose(f'[-] Getting total events of {minion}.')
		total_hits = os.popen(f'salt {minion} cmd.run "python3 /opt/atd/atd.py -c"').readlines()
		if a.comparison_utc:
			total_hits = os.popen(f'salt {minion} cmd.run "python3 /opt/atd/atd.py -c utc"').readlines()
		print(total_hits[1].strip())

		verbose(f'[-] Getting total events on master for {minion}.')
		master_index = f'events-{minion}*'
		indices = mes.indices.get_alias(master_index).keys()

		now = 0
		if indices:
			index = sorted(indices)[-1]
			index2 = sorted(indices)[-2]
			mid = index[-10:].replace(".", "-")
			midnight = mid + "T00:00:00"

			local_midnights = datetime.datetime.strptime(midnight, '%Y-%m-%dT%H:%M:%S') - timedelta(hours=9, minutes=30)
			if a.comparison_utc:
				local_midnights = datetime.datetime.strptime(midnight, '%Y-%m-%dT%H:%M:%S')
			local_midnight = local_midnights.strftime('%Y-%m-%dT%H:%M:%S')

			now = 'now-5m'
			result = query(index, midnight, now)
			result2 = query(index2, local_midnight, midnight)
			result_now = int(result) + int(result2)
			# print(index2, result, result2)
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
		print(f"[+] Master now - {result_now}, 10min - {result_ten}, last_hr - {result_last_hour}")
	except Exception as e:
		print('[!] ERROR on comparison: %s' % (e))
		# logging.error('[!] ERROR on comparison: %s' % (e))


if __name__ == "__main__":
	try:
		example_text = '''example:
  python3 asoc.py --list
  python3 asoc.py --enable
  python3 asoc.py --status selk01
  python3 asoc.py --disable 2260000,2260001,2260002,2260003,2260004,2260005'''

		ips = os.popen('hostname -I').readline().strip()
		ip = ips.split(' ')[0]
		master = socket.gethostname()
		params = argparse.ArgumentParser(description='Afovos Security Operations Center', epilog=example_text, formatter_class=argparse.RawDescriptionHelpFormatter)
		params.add_argument('-u', '--update', dest='update', nargs='?', const="'*'", type=str, metavar='minion', help="Update suricata rules on minions.")
		params.add_argument('-s', '--status', dest='status', nargs='?', const="'*'", type=str, metavar='minion', help="Status of suricata rules on minions.")
		params.add_argument('-t', '--threshold', dest='threshold', nargs='*', metavar='minions, sid, count, seconds', help="")
		params.add_argument('-su', '--suppress', dest='suppress', nargs='*', metavar='minions, sid, net, track_by', help="")
		params.add_argument('-ut', '--unthreshold', dest='unthreshold', nargs='*', metavar='minions, sid', help="")
		params.add_argument('-us', '--unsuppress', dest='unsuppress', nargs='*', metavar='minions, sid', help="")
		params.add_argument('-m', '--master', dest='master', nargs='?', const=ip, type=str, metavar='master_ip', help="Setup master. Run this command on master.")
		params.add_argument('-mi', '--minion', dest='minion', type=str, metavar='master_ip', help="Setup minion to master. Run this command on minon.")
		params.add_argument('-a', '--add', dest='add', action="store_true", help="Add minion to master.")
		params.add_argument('-l', '--list', dest='list', action="store_true", help="List all minions on the master.")
		params.add_argument('-r', '--remove', dest='remove', type=str, metavar='minion', help="Remove minion from master.")
		params.add_argument('-lo', '--logging', dest='logging', action="store_true", help="Setup logging for master. Run this command on master.")
		params.add_argument('-lm', '--logging_minion', dest='logging_minion', action="store_true", help="Setup logging for minion. Run this command on minion.")
		params.add_argument('-ll', '--list_logging', dest='list_logging', nargs='*', metavar='minions, num', help="List logging of minions.")
		params.add_argument('-as', '--add_schedule', dest='add_schedule', nargs='*', metavar='minions, job, range, max, splay', help="Add schedule job of minions.")
		params.add_argument('-ms', '--modify_schedule', dest='modify_schedule', nargs='*', metavar='minions, job, range, max, splay', help="Modify schedule job of minions.")
		params.add_argument('-es', '--enable_schedule', dest='enable_schedule', nargs='*', metavar='minions, job', help="Enable minion schedule job on master.")
		params.add_argument('-ds', '--disable_schedule', dest='disable_schedule', nargs='*', metavar='minions, job', help="Disable minion schedule job on master.")
		params.add_argument('-ls', '--list_schedule', dest='list_schedule', nargs='?', const="'*'", type=str, metavar='minion', help="List all scheduled job on the minion.")
		params.add_argument('-rs', '--remove_schedule', dest='remove_schedule', nargs='*', metavar='minions, job', help="Remove minion schedule job on master.")
		params.add_argument('-op', '--open_port', dest='open_port', action="store_true", help="Open port 5636 for atd (parsing of alerts) and 8000 for scirius (enabling/disabling rules).")
		params.add_argument('-cd', '--create_dashboard', dest='create_dashboard', nargs='?', const="localhost", type=str, metavar='ip', help="Create a new oDirectives dashboard on master Kibana.")
		params.add_argument('-dd', '--delete_dashboard', dest='delete_dashboard', nargs='?', const="localhost", type=str, metavar='ip', help="Delete oDirectives dashboard on master Kibana.")
		params.add_argument('-um', '--uninstall_master', dest='uninstall_master', action="store_true", help="Uninstall salt-master.")
		params.add_argument('-ui', '--uninstall_minion', dest='uninstall_minion', nargs='?', const="'*'", type=str, metavar='minion', help="Uninstall salt-minion.")
		params.add_argument('-sm', '--status_master', dest='status_master', action="store_true", help="Service status of master.")
		params.add_argument('-si', '--status_minion', dest='status_minion', nargs='?', const="'*'", type=str, metavar='minion', help="Service status of minions.")
		params.add_argument('-rm', '--restart_master', dest='restart_master', action="store_true", help="Restart master service.")
		params.add_argument('-ri', '--restart_minion', dest='restart_minion', nargs='?', const="'*'", type=str, metavar='minion', help="Restart minions service.")
		params.add_argument('-cp', '--copy', dest='copy', nargs='?', const="'*'", type=str, metavar='minion', help="Copy ATD files to minons.")
		params.add_argument('-ir', '--install_requirements', nargs='?', const="'*'", type=str, metavar='minion', help="Install requirements to minions.")
		params.add_argument('-gp', '--generate_pcap', dest='generate_pcap', nargs='?', const=60, type=int, metavar='seconds', help="Generates test PCAP alerts. Run this command on minion.") #UNDER CONSTRUCTION
		params.add_argument('-up', '--update_minion', dest='update_minion', nargs='?', const="'*'", type=str, metavar='minion', help="Git update minions.")
		params.add_argument('-cf', '--config_file', dest='config_file', action="store_true", help="Setup master and minion config file.")
		params.add_argument('-c', '--comparison', dest='comparison', nargs='?', const="'*'", type=str, metavar='minion', help="Comparison of master and minions alert data total local time.")
		params.add_argument('-cu', '--comparison_utc', dest='comparison_utc', action="store_true", help="Comparison of master and minions alert data total utc time.")
		params.add_argument('-de', '--debug', dest='debug', nargs='?', const="'*'", type=str, metavar='minion', help="Setup log level to debug.")
		params.add_argument('-in', '--info', dest='info', nargs='?', const="'*'", type=str, metavar='minion', help="Setup log level to info.")
		params.add_argument('-ve', '--verbose', dest='verbose', action="store_true", help="Turn on verbose.")
		params.add_argument('-v', '--version', action='version', version='%(prog)s 0.0')

		a = params.parse_args()
		mini = os.popen('ls -1 /var/cache/salt/master/minions').readlines()
		minions = [s.rstrip() for s in mini]

		config = configparser.ConfigParser() # Config settings
		path = abspath(dirname(__file__))
		config.read(path + '/atd.conf')
		mes_host = config.get(master, 'mes_host')
		mes = Elasticsearch(mes_host, retry_on_Offline=True, read_Offline=2000)

		# TODO: Get token from scirius...
		if a.debug:
			answer = input(f"[+] Update logging level to debug on {a.debug} [Y]es/[N]o? ")
			if answer.lower() in ["y","yes"]:
				with open('/etc/salt/master', 'r') as file :
					filedata = file.read()
				filedata = filedata.replace('log_level: info', 'log_level: debug')
				with open('/etc/salt/master', 'w') as file:
					file.write(filedata)

				minion = default_all(a.debug)
				os.system(f'salt {minion} cmd.run "python3 /opt/atd/atd.py -de"')
				os.system('sudo systemctl restart salt-master')
				print('[+] Succesfully Updated logging level to debug.')
			exit(0)

		if a.info:
			answer = input(f"[+] Update logging level to info on {a.info} [Y]es/[N]o? ")
			if answer.lower() in ["y","yes"]:
				with open('/etc/salt/master', 'r') as file :
					filedata = file.read()
				filedata = filedata.replace('log_level: debug', 'log_level: info')
				with open('/etc/salt/master', 'w') as file:
					file.write(filedata)

				minion = default_all(a.info)
				os.system(f'salt {minion} cmd.run "python3 /opt/atd/atd.py -in"')
				os.system('sudo systemctl restart salt-master')
				print('[+] Succesfully Updated logging level to info.')
			exit(0)

		if a.comparison:
			minion = default_all(a.comparison)
			if minion == "'*'":
				for m in minions:
					comparison(m)
			else:
				comparison(minion)
			exit(0)

		if a.comparison_utc:
			for m in minions:
				comparison(m)
			exit(0)

		if a.generate_pcap:
			answer = input(f"[+] Generate PCAP Alerts {a.generate_pcap} seconds [Y]es/[N]o? ")
			if answer.lower() in ["y","yes"]:
				print("[+] This will take a while, please wait...")
				if not os.path.exists("2023-03-08-IcedID-with-BackConnect-and-VNC-traffic.pcap.zip"):
					os.system('wget https://www.malware-traffic-analysis.net/2023/03/08/2023-03-08-IcedID-with-BackConnect-and-VNC-traffic.pcap.zip')
					os.system('sudo apt install unzip -y')
					os.system("unzip -P 'infected' 2023-03-08-IcedID-with-BackConnect-and-VNC-traffic.pcap.zip")
					os.system('sudo apt install tcpreplay -y')
				command = ['tcpreplay', '-i', 'tppdummy0', '2023-03-08-IcedID-with-BackConnect-and-VNC-traffic.pcap']

				process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				timeout = a.generate_pcap
				start_time = time.time()

				while process.poll() is None:
					elapsed_time = time.time() - start_time
					if elapsed_time > timeout:
						process.kill()
						break
					time.sleep(0.1)

				stdout, stderr = process.communicate()
				return_code = process.returncode
				print('Output:', stdout.decode())
				print('Error:', stderr.decode())
				print('Return code:', return_code)
				os.system("rm 2023-03-08-IcedID-with-BackConnect-and-VNC-traffic.pcap.zip")
				os.system("rm 2023-03-08-IcedID-with-BackConnect-and-VNC-traffic.pcap")
			exit(0)

		if a.install_requirements:
			answer = input(f"[+] Install requirements on {a.install_requirements} [Y]es/[N]o? ")
			if answer.lower() in ["y","yes"]:
				minion = default_all(a.install_requirements)
				os.system(f"salt {minion} cmd.run 'sudo apt install python3-pip -y'")
				os.system(f"salt {minion} cmd.run 'pip install -r /opt/atd/requirements.txt'")
				os.system(f"salt {minion} cmd.run 'chmod +x /opt/atd/asoc.py'")
				os.system(f"salt {minion} cmd.run 'python3 /opt/atd/asoc.py -cf'")
				os.system(f"salt {minion} cmd.run 'python3 /opt/atd/asoc.py -op'")
				os.system(f"salt {minion} cmd.run 'sudo systemctl restart salt-minion'")
			exit(0)

		if a.config_file:
			config_file()
			exit(0)

		if a.copy:
			answer = input(f"[+] Copy ATD folder to {a.copy} [Y]es/[N]o? ")
			if answer.lower() in ["y","yes"]:
				print("[+] This will take a while, please wait...")
				minion = default_all(a.copy)
				os.system(f'salt-cp -C {minion} /opt/atd /opt')
			exit(0)

		if a.update_minion:
			verbose(f'[-] Updating ATD to latest version on {a.update_minion}.')
			minion = default_all(a.update_minion)
			check = os.popen('git -C /opt/atd/ pull origin master').read()
			if "Already up to date" not in check:
				os.system(f'salt-cp -C {minion} /opt/atd /opt')
			exit(0)

		if a.uninstall_master:
			answer = input(f"[+] Uninstall SALT master on {ip} [Y]es/[N]o? ")
			if answer.lower() in ["y","yes"]:
				os.system('sudo apt purge salt-master -y')
			exit(0)

		if a.uninstall_minion:
			answer = input(f"[+] Uninstall SALT Minion on {a.uninstall_minion} [Y]es/[N]o? ")
			if answer.lower() in ["y","yes"]:
				minion = default_all(a.uninstall_minion)
				os.system(f"salt {minion} cmd.run 'sudo apt purge salt-minion -y'")
			exit(0)

		if a.status_master:
			verbose('[-] Service status of master.')
			os.system('sudo systemctl status salt-master')
			exit(0)

		if a.status_minion:
			verbose(f'[-] Service status of {a.status_minion}.')
			minion = default_all(a.status_minion)
			os.system(f"salt {minion} cmd.run 'sudo systemctl status salt-minion'")
			exit(0)

		if a.restart_master:
			answer = input(f"[+] Restart SALT master service on {ip} [Y]es/[N]o? ")
			if answer.lower() in ["y","yes"]:
				os.system('sudo systemctl restart salt-master')
			exit(0)

		if a.restart_minion:
			answer = input(f"[+] Restart SALT Minion service on {a.restart_minion} [Y]es/[N]o? ")
			if answer.lower() in ["y","yes"]:
				minion = default_all(a.restart_minion)
				os.system(f"salt {minion} cmd.run 'sudo systemctl restart salt-minion'")
			exit(0)

		if a.master:
			if validate_ip(a.master):
				answer = input(f"[+] Install SALT master on {a.master} [Y]es/[N]o? ")
				if answer.lower() in ["y","yes"]:
					os.system('sudo apt install python3-pip -y')
					requirements()
					os.system('chmod +x asoc.py')
					box_os = os.popen('lsb_release -d | grep -oP "Description:\K.*"').readline().strip()
					check_os(box_os)
					os.system('sudo apt-get update -y; sudo apt-get install salt-master -y')

					with open('/etc/salt/master', 'r') as file :
						filedata = file.read()
					filedata = filedata.replace('#interface: 0.0.0.0', 'interface: ' + a.master)
					filedata = filedata.replace('#log_level: warning', 'log_level: info')
					filedata = filedata.replace('#max_event_size: 1048576', 'max_event_size: 99999999999999999')
					with open('/etc/salt/master', 'w') as file:
						file.write(filedata)

					open_port()
					os.system('sudo systemctl enable salt-master; sudo systemctl restart salt-master')
					create_dash(a.master)
					os.system(f'sudo salt-key -A -y')
			exit(0)

		if a.minion:
			verbose(f'[-] Installing SALT Minion on {a.minion}.')
			if validate_ip(a.minion):
				os.system('sudo apt install python3-pip -y')
				requirements()
				os.system('chmod +x asoc.py')
				box_os = os.popen('lsb_release -d | grep -oP "Description:\K.*"').readline().strip()
				check_os(box_os)
				os.system('sudo apt-get update -y; sudo apt-get install salt-minion -y')
				with open('/etc/salt/minion', 'r') as file :
					filedata = file.read()
				filedata = filedata.replace('#master: salt', 'master: ' + a.minion)
				with open('/etc/salt/minion', 'w') as file:
					file.write(filedata)
				config_file()
				open_port()
				os.system('sudo systemctl enable salt-minion; sudo systemctl restart salt-minion')
			exit(0)

		if a.create_dashboard:
			answer = input(f"[+] Create kibana dashboard on master {a.create_dashboard} [Y]es/[N]o? ")
			if answer.lower() in ["y","yes"]:
				create_dash(a.create_dashboard)
			exit(0)

		if a.delete_dashboard:
			answer = input(f"[+] Delete kibana dashboard on master {a.delete_dashboard} [Y]es/[N]o? ")
			if answer.lower() in ["y","yes"]:
				dashboard_id = 'ce1b2560-1431-11ea-b9df-09d5e6f7d0d2'
				url = 'http://' + a.delete_dashboard + ':5601/api/saved_objects/dashboard/' + dashboard_id
				print('DELETE ' + url)
				response = requests.delete(url,
					headers={'kbn-xsrf': 'true'},
				)
				if response.text == '{}':
					print("[+] Successfully deleted dashboard!")
				elif response.status_code == 200:
					print("[+] Successfully deleted dashboard!")
				else:
					print("[!] Error: " + response.text)

				
				index_id = '66c1b490-8f4b-11e8-ae01-dfa4c73ee11f'
				url = 'http://' + a.delete_dashboard + ':5601/api/saved_objects/index-pattern/' + index_id
				print('DELETE ' + url)
				response = requests.delete(url,
					headers={'kbn-xsrf': 'true'},
				)
				if response.text == '{}':
					print("[+] Successfully deleted index-pattern!")
				elif response.status_code == 200:
					print("[+] Successfully deleted index-pattern!")
				else:
					print("[!] Error: " + response.text)
			exit(0)

		if a.open_port:
			message = open_port()
			print(message)
			exit(0)

		if a.logging:
			verbose('[-] Enabling logging on SALT master.')
			with open('/etc/salt/master', 'r') as file :
				filedata = file.read()
			filedata = filedata.replace('#log_level: warning', 'log_level: info')
			with open('/etc/salt/master', 'w') as file:
				file.write(filedata)
			os.system('sudo systemctl restart salt-master')
			print('Logging is enabled on the salt master.')
			exit(0)

		if a.logging_minion:
			verbose('[-] Enabling logging on SALT minion.')
			with open('/etc/salt/minion', 'r') as file :
				filedata = file.read()
			filedata = filedata.replace('#log_level: warning', 'log_level: info')
			with open('/etc/salt/minion', 'w') as file:
				file.write(filedata)
			os.system('sudo systemctl restart salt-minion')
			print('Logging is enabled on the salt minion.')
			exit(0)

		if a.list_logging is not None:
			verbose('[-] Listing logs of SALT minion and master.')
			minion, num = default_list(a.list_logging)
			os.system(f"salt {minion} cmd.run 'tail -n {num} /var/log/salt/minion'")
			print("master:")
			os.system(f'tail -n {num} /var/log/salt/minion')
			exit(0)

		if a.add:
			verbose('[-] Accepting keys of SALT minion.')
			os.system(f'sudo salt-key -A')
			exit(0)

		if a.remove:
			verbose(f'[-] Removing of key of {a.revome} SALT minion.')
			minion = default_all(a.remove)
			os.system(f'salt-key -d {minion}')
			exit(0)

		if a.list:
			verbose('[-] Listing all SALT minion.')
			os.system("""salt '*' cmd.run 'hostname -I | grep -Eo "^[^ ]+" ; uname -a'""")
			exit(0)

		if a.list_schedule:
			verbose(f'[-] Listing scheduled jobs of {a.list_schedule}.')
			minion = default_all(a.list_schedule)
			os.system(f"salt {minion} schedule.list")
			exit(0)

		if a.remove_schedule:
			verbose(f'[-] Removing scheduled jobs of {a.remove_schedule}.')
			minion, job = default_job(a.remove_schedule)
			if minion == "'*'":
				for m in minions:
					j = f'job_{m}'
					os.system(f"salt {master} schedule.delete {j}")
			else:
				os.system(f"salt {minion} schedule.delete {job}")
			exit(0)

		if a.add_schedule:
			verbose(f'[-] Adding scheduled jobs of {a.add_schedule}.')
			minion, job, range, max, elastic, splay = default_schedule(a.add_schedule)
			if minion == "'*'":
				for m in minions:
					j = f'job_{m}'
					os.system(f"""salt {master} schedule.add {j} function='cmd.run' job_args="['python3 /opt/atd/atd.py {m} {max} --{elastic}']" seconds={range} splay={splay}""")
			else:
				os.system(f"""salt {master} schedule.add {job} function='cmd.run' job_args="['python3 /opt/atd/atd.py {minion} {max} --{elastic}']" seconds={range} splay={splay}""")
			exit(0)

		if a.modify_schedule:
			verbose(f'[-] Modifying scheduled jobs of {a.modify_schedule}.')
			minion, job, range, max, elastic, splay = default_schedule(a.modify_schedule)
			if minion == "'*'":
				for m in minions:
					j = f'job_{m}'
					os.system(f"""salt {master} schedule.modify {j} function='cmd.run' job_args="['python3 /opt/atd/atd.py {m} {max} --{elastic}']" seconds={range} splay={splay}""")
			else:
				os.system(f"""salt {master} schedule.modify {job} function='cmd.run' job_args="['python3 /opt/atd/atd.py {minion} {max} --{elastic}']" seconds={range} splay={splay}""")
			exit(0)

		if a.enable_schedule:
			verbose(f'[-] Enabling scheduled jobs of {a.enable_schedule}.')
			minion, job = default_job(a.enable_schedule)
			if minion == "'*'":
				for m in minions:
					j = f'job_{m}'
					os.system(f"salt {master} schedule.enable_job {j}")
			else:
				os.system(f"salt {minion} schedule.enable_job {job}")
			exit(0)

		if a.disable_schedule:
			verbose(f'[-] Disabling scheduled jobs of {a.disable_schedule}.')
			minion, job = default_job(a.disable_schedule)
			if minion == "'*'":
				for m in minions:
					j = f'job_{m}'
					os.system(f"salt {master} schedule.disable_job {j}")
			else:
				os.system(f"salt {minion} schedule.disable_job {job}")
			exit(0)

		if a.threshold:
			unlist = " ".join(a.threshold)
			answer = input(f"[+] Threshold rules {unlist} [Y]es/[N]o? ")
			verbose(f'[-] Thresholding rules of {unlist}.')
			if answer.lower() in ["y","yes"]:
				print("[+] This will take a while, please wait...")
				minion, sid, count, seconds = default_threshold(a.threshold)
				if minion == "'*'":
					for m in minions:
						os.system(f"salt {m} cmd.run 'python3 /opt/atd/atd.py --threshold {sid} {count} {seconds}'")
						#TODO: don't update if error
						os.system(f"salt {m} cmd.run 'python3 /opt/atd/atd.py --update'")
				else:
					os.system(f"salt {minion} cmd.run 'python3 /opt/atd/atd.py --threshold {sid} {count} {seconds}'")
					os.system(f"salt {minion} cmd.run 'python3 /opt/atd/atd.py --update'")
			exit(0)

		if a.suppress:
			unlist = " ".join(a.suppress)
			answer = input(f"[+] Suppress rule {unlist} [Y]es/[N]o? ")
			verbose(f'[-] Suppressing rules of {unlist}.')
			if answer.lower() in ["y","yes"]:
				print("[+] This will take a while, please wait...")
				minion, sid, net, track_by= default_suppress(a.suppress)
				if minion == "'*'":
					for m in minions:
						os.system(f"salt {m} cmd.run 'python3 /opt/atd/atd.py --suppress {sid} {net} {track_by}'")
						os.system(f"salt {m} cmd.run 'python3 /opt/atd/atd.py --update'")
				else:
					os.system(f"salt {minion} cmd.run 'python3 /opt/atd/atd.py --suppress {sid} {net} {track_by}'")
					os.system(f"salt {minion} cmd.run 'python3 /opt/atd/atd.py --update'")
			exit(0)

		if a.unthreshold:
			unlist = " ".join(a.unthreshold)
			answer = input(f"[+] Unthreshold rules {unlist} [Y]es/[N]o? ")
			verbose(f'[-] Unthresholding rules of {unlist}.')
			if answer.lower() in ["y","yes"]:
				print("[+] This will take a while, please wait...")
				minion, sid = default_un(a.unthreshold)
				if minion == "'*'":
					for m in minions:
						os.system(f"salt {m} cmd.run 'python3 /opt/atd/atd.py --unthreshold {sid}'")
						os.system(f"salt {m} cmd.run 'python3 /opt/atd/atd.py --update'")
				else:
					os.system(f"salt {minion} cmd.run 'python3 /opt/atd/atd.py --unthreshold {sid}'")
					os.system(f"salt {minion} cmd.run 'python3 /opt/atd/atd.py --update'")
			exit(0)

		if a.unsuppress:
			unlist = " ".join(a.unsuppress)
			answer = input(f"[+] Unsuppress rule {unlist} [Y]es/[N]o? ")
			verbose(f'[-] Unsuppressing rules of {unlist}.')
			if answer.lower() in ["y","yes"]:
				print("[+] This will take a while, please wait...")
				minion, sid = default_un(a.unsuppress)
				if minion == "'*'":
					for m in minions:
						os.system(f"salt {m} cmd.run 'python3 /opt/atd/atd.py --unsuppress {sid}'")
						os.system(f"salt {m} cmd.run 'python3 /opt/atd/atd.py --update'")
				else:
					os.system(f"salt {minion} cmd.run 'python3 /opt/atd/atd.py --unsuppress {sid}'")
					os.system(f"salt {minion} cmd.run 'python3 /opt/atd/atd.py --update'")
			exit(0)

		if a.update:
			answer = input(f"[+] Update rule {a.update} [Y]es/[N]o? ")
			if answer.lower() in ["y","yes"]:
				minion = default_all(a.update)
				os.system(f"salt {minion} cmd.run 'python3 /opt/atd/atd.py --update'")
			exit(0)

		if a.status:
			print(f'[+] Getting rule status. Please Wait...')
			minion = default_all(a.status)
			os.system(f"salt {minion} cmd.run 'python3 /opt/atd/atd.py --status'")
			exit(0)

		else:
			verbose('[-] Guide for ASOC commands.')
			params.print_help()
	except Exception as e:
		print('[!] ASOC experienced an Error: %s report it to Allan of Afovos.' % e)
		# logging.error('[!] ASOC encountered an Error: %s report it to Allan of Afovos.' % e)