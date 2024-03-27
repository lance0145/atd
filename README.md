---
gitea: none
include_toc: true
---

# Introduction
ATD (Afovos Threat Detection) System, It's a security tool composed of SALT/SELKS/Python technology used to monitor network or system activities for any signs of unauthorized access, malicious activities, or policy violations. The primary purpose of ATD is to detect and respond to potential security breaches.

# Installation of SaltStack and Afovos Threat Detection

## Install SaltStack on Master.
* Download ASOC (Afovos Security Operations Centre), for simple and fast commands of ATD and SaltStack to be run locally on master.
```
git clone http://10.254.10.1:3000/Allan/atd.git
cd atd
chmod +x asoc.py
./asoc.py -m || ./asoc.py --master
```
```
git clone http://10.254.10.1:3000/Allan/atd.git
Cloning into 'atd'...
remote: Counting objects: 459, done.
remote: Compressing objects: 100% (456/456), done.
remote: Total 459 (delta 299), reused 0 (delta 0)
Receiving objects: 100% (459/459), 19.39 MiB | 14.50 MiB/s, done.
Resolving deltas: 100% (299/299), done.
root@selk1:/opt# cd atd
root@selk1:/opt/atd# chmod +x asoc.py
root@selk1:/opt/atd# ./asoc.py -m
[+] Install SALT master on 10.254.10.11 [Y]es/[N]o? Y
Reading package lists... Done
Building dependency tree
Reading state information... Done
python3-pip is already the newest version (20.0.2-5ubuntu1.9).
0 upgraded, 0 newly installed, 0 to remove and 34 not upgraded...
```
```
Installation Includes:
1. Update machine
2. Install salt-master
3. Install python packages
4. Set master IP addrs
5. Enable logging
6. Increase max_event_size
7. Enable Elasticsearch, Kibana and Scirius services
8. Create Kibana index pattern and dashboard
9. Enable and restart salt-master service
10. Accept minion keys
```

## Install SaltStack on Minion.
* Download ASOC on minion and run ./asoc.py -mi <master IP addrs> to install salt-minion on your machine.
```
git clone http://10.254.10.1:3000/Allan/atd.git
cd atd
chmod +x asoc.py
./asoc.py -mi <master IP addrs> || ./asoc.py --minion <master IP addrs>
```
```
./asoc.py -mi 10.254.10.11
Reading package lists... Done
Building dependency tree
Reading state information... Done
python3-pip is already the newest version (20.0.2-5ubuntu1.9).
0 upgraded, 0 newly installed, 0 to remove and 34 not upgraded.
Requirement already satisfied: elasticsearch==7.17.7 in /usr/local/lib/python3.8/dist-packages (7.17.7)
Requirement already satisfied: certifi in /usr/lib/python3/dist-packages (from elasticsearch==7.17.7) (2019.11.28)
Requirement already satisfied: urllib3<2,>=1.21.1 in /usr/lib/python3/dist-packages (from elasticsearch==7.17.7) (1.25.8)
Requirement already satisfied: tabulate==0.9.0 in /usr/local/lib/python3.8/dist-packages (0.9.0)
Requirement already satisfied: grequests==0.6.0 in /usr/local/lib/python3.8/dist-packages (0.6.0)
Requirement already satisfied: gevent in /usr/local/lib/python3.8/dist-packages (from grequests==0.6.0) (22.10.2)
Requirement already satisfied: requests in /usr/lib/python3/dist-packages (from grequests==0.6.0) (2.22.0)
Requirement already satisfied: zope.interface in /usr/lib/python3/dist-packages (from gevent->grequests==0.6.0) (4.7.1)
Requirement already satisfied: zope.event in /usr/local/lib/python3.8/dist-packages (from gevent->grequests==0.6.0) (4.6)
Requirement already satisfied: setuptools in /usr/lib/python3/dist-packages (from gevent->grequests==0.6.0) (45.2.0)
Requirement already satisfied: greenlet>=2.0.0; platform_python_implementation == "CPython" in /usr/local/lib/python3.8/dist-packages (from gevent->grequests==0.6.0) (2.0.2)
Requirement already satisfied: pytz==2023.3 in /usr/local/lib/python3.8/dist-packages (2023.3)
mkdir: cannot create directory ‘/etc/apt/keyrings’: File exists...
```
```
Installation Includes:
1. Update machine
2. Install salt-minion
3. Install python packages
4. Set master IP addrs
5. Enable logging
6. Increase max_event_size
7. Enable Elasticsearch, Kibana and Scirius services
9. Enable and restart salt-minion service
```

## SaltStack Key Management
Salt uses AES Encryption for all the communication between the Master and the Minion. The communication between Master and Minion is authenticated through trusted, accepted keys.

### Listing Keys 
To list the mininos that have been accepted or are waiting to be accepted on the Salt master, run the following command:
```
./asoc.py -l || ./asoc.py -list

afovos-selk:
    100.100.100.1
    Linux afovos-selk 5.4.0-153-generic #170-Ubuntu SMP Fri Jun 16 13:43:31 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
business-sa-selk:
    100.64.6.1
    Linux business-sa-selk 5.4.0-152-generic #169-Ubuntu SMP Tue Jun 6 22:23:09 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
boileau-selk:
    100.64.1.1
    Linux boileau-selk 5.4.0-152-generic #169-Ubuntu SMP Tue Jun 6 22:23:09 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
one-solution-selk:
    100.64.9.1
    Linux one-solution-selk 5.4.0-152-generic #169-Ubuntu SMP Tue Jun 6 22:23:09 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```
### Accepting Keys on All Minion: 
You can accept all keys using the following command:
```
./asoc.py -a || ./asoc.py --add

The following keys are going to be accepted:
Unaccepted Keys:
so1.localdomain
Proceed? [n/Y]
```
Respond Y to accept the minion.


### Add section on ATD config file: 
Open /opt/atd/atd.conf and add section name, user, site, parameter etc.
```
nano atd.conf

[afovos-selk]
mes_host=100.100.100.1:9200
es_host=localhost:9200
siem_host=100.100.100.1
pass=Password123
user=root
site=Afovos-selk
siteid=
site_path=afovos-selk
parameter=localhost
token=...
```
# Schedule Afovos Threat Detection Job on all Minions.

Salt’s scheduling system allows incremental executions on minions or the master.

## Add Schedule Job.
The following command can add a new Afovos Threat Detection job on all minions. This job will run every 5 minutes. The alert data will be notify on Afovos Viber and it will be forward to Elasticsearch Server.
```
./asoc.py -as all job 120 2000 60 elastic || ./asoc.py --add_schedule all job 120 2000 60 elastic

afovos-selk:
    ----------
    changes:
        ----------
        job_boileau-selk:
            added
    comment:
        Added job: job_boileau-selk to schedule.
    result:
        True ...
```
all = all minions

job = schedule job name format

120 = occurrence time

2000 = max count of data transferred

60 = splay time

elastic = alert data forwarded to ElasticSearch

## Modify Schedule Job.
Modify an existing job in the schedule on all Minions.
```
./asoc.py -ms all job 60 2000 60 elastic || ./asoc.py --modify_schedule all job 60 2000 60 elastic

afovos-selk:
    ----------
    changes:
        ----------
        job_afovos-selk:
            ----------
            new:
                ----------
                args:
                    - python3 /opt/atd/atd.py afovos-selk 2000 --elastic
                enabled:
                    True
                function:
                    cmd.run
                jid_include:
                    True
                maxrunning:
                    1
                name:
                    job_afovos-selk
                seconds:
                    60
                splay:
                    60
            old:
                ----------
                args:
                    - python3 /opt/atd/atd.py afovos-selk 2000 --elastic
                enabled:
                    True
                function:
                    cmd.run
                jid_include:
                    True
                maxrunning:
                    1
                name:
                    job_afovos-selk
                seconds:
                    120
                splay:
                    60 ...
```

## Enable schedule Job.
An Afovos Threat Detection job can be enabled in the scheduler on all Minions.
```
./asoc.py -es all job || ./asoc.py --enable_schedule all job

afovos-selk:
    ----------
    changes:
        ----------
        job_afovos-selk:
            enabled
    comment:
        Enabled Job job_afovos-selk in schedule.
    result:
        True ...
```

## Disable Schedule Job.
An Afovos Threat Detection job can be enabled in the scheduler on all Minions.
```
./asoc.py -ds all job || ./asoc.py --disable_schedule all job

afovos-selk:
    ----------
    changes:
        ----------
        job_afovos-selk:
            disabled
    comment:
        Disabled Job job_afovos-selk in schedule.
    result:
        True ...
```

## List Schedule Job.
List the jobs currently scheduled on all minions.
```
./asoc.py -ls || ./asoc.py--list_schedule

afovos-selk:
    schedule:
      job_afovos-selk:
        args:
        - python3 /opt/atd/atd.py afovos-selk 2000 --elastic
        enabled: true
        function: cmd.run
        jid_include: true
        maxrunning: 1
        name: job_afovos-selk
        saved: true
        seconds: 120
        splay: 60
      job_business-sa-selk:
        args:
        - python3 /opt/atd/atd.py business-sa-selk 2000 --elastic
        enabled: true
        function: cmd.run
        jid_include: true
        maxrunning: 1
        name: job_business-sa-selk
        saved: true
        seconds: 120
        splay: 60 ...
```

## Delete Schedule Job.
Delete a job from all minion's schedule.
```
./asoc.py -ds afovos-selk job_so1.localdomain || ./asoc.py --delete_schedule afovos-selk job_so1.localdomain

afovos-selk:
    ----------
    changes:
        ----------
        job_so1.localdomain:
            removed
    comment:
        Deleted Job job1 from schedule.
    result:
        True ...
```

# SaltStack Logging on all Minions.

SaltStack has built-in logging functionality that allows you to capture and analyze events, errors, and other important information generated by the SaltStack infrastructure.

## Configure SaltStack Logging
* This will open the SaltStack configuration file, usually located at /etc/salt/minion on the minion or /etc/salt/master on the master. Will look for the Logging settings section, and enable salt logging by uncommenting log modules.
```
./asoc.py -lo || ./asoc.py --logging

Logging is enabled on the salt master.
```
* This will edit configuration file Logging settings log_level to info for more logging information.
```
log_level: info
```

## Restart SaltStack 
* Restart the SaltStack minion or master service to apply the new logging configuration. For example, on a Debian-based system, you can run
```
./asoc.py -rm || ./asoc.py --restart_master
./asoc.py -ri || ./asoc.py --restart_minion
```

## Check Logs on Minion and Master 
* Once the services are restarted and scheduled job is enabled, you can check the logs to see if they are working properly. You can check the logs of all minions by running the following command on the SaltStack master:
```
./asoc.py -ll || ./asoc.py --list_logging
selk01:
  2023-03-15 15:23:16,563 [WARNING] [2368378] [!] No all minion on ATD.conf please fill up user, site, parameter etc. first on conf file.
  2023-03-15 15:28:16,620 [WARNING] [2369718] [!] No all minion on ATD.conf please fill up user, site, parameter etc. first on conf file.
  2023-03-15 15:33:16,587 [WARNING] [2371071] [!] No all minion on ATD.conf please fill up user, site, parameter etc. first on conf file. ...
```

# Generate test alerts data

* To generates test alerts data. Run this command on minion.
```
./asoc.py -gp || ./asoc.py --generate_pcap

[+] Generate PCAP Alerts 60 seconds [Y]es/[N]o? Yes
[+] This will take a while, please wait...
--2023-08-02 16:07:38--  https://www.malware-traffic-analysis.net/2023/03/08/2023-03-08-IcedID-with-BackConnect-and-VNC-traffic.pcap.zip
Resolving www.malware-traffic-analysis.net (www.malware-traffic-analysis.net)... 199.201.110.204
Connecting to www.malware-traffic-analysis.net (www.malware-traffic-analysis.net)|199.201.110.204|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8586823 (8.2M) [application/zip]...
```

* Check Logs, Afovos Viber and ElasticSearch Server if the generated test alerts data is forwarded.

  Logs
```
./asoc.py -ll || ./asoc.py --list_logging

selk01:
  2023-03-16 02:00:43,031 [INFO] [2543451] [+] Successfully send alerts on Afovos Viber from localhost at 5 minutes until now.
  2023-03-16 02:00:43,041 [INFO] [2543451] GET http://10.254.10.20:9200/ [status:200 request:0.001s]
  2023-03-16 02:00:43,087 [INFO] [2543451] POST http://10.254.10.20:9200/events--2023.03.15/events--2023.03.15 [status:201 request:0.046s]
  2023-03-16 02:00:43,087 [INFO] [2543451] [+] Successfully pushed alerts data to Elasticsearch from localhost at 5 minutes until now.
  2023-03-16 02:00:44,319 [INFO] [2543451] [+] Successfully send alerts on Afovos Viber from localhost at 5 minutes until now.
  2023-03-16 02:00:44,330 [INFO] [2543451] POST http://10.254.10.20:9200/events--2023.03.15/events--2023.03.15 [status:201 request:0.011s]
  2023-03-16 02:00:44,331 [INFO] [2543451] [+] Successfully pushed alerts data to Elasticsearch from localhost at 5 minutes until now.
  2023-03-16 02:00:45,557 [INFO] [2543451] [+] Successfully send alerts on Afovos Viber from localhost at 5 minutes until now.
  2023-03-16 02:00:45,568 [INFO] [2543451] POST http://10.254.10.20:9200/events--2023.03.15/events--2023.03.15 [status:201 request:0.011s]
  2023-03-16 02:00:45,568 [INFO] [2543451] [+] Successfully pushed alerts data to Elasticsearch from localhost at 5 minutes until now.
```
  Afovos Viber
```
  ########### ALERT! ALERT! ALERT! ############
  '@timestamp': '2023-03-15T16:01:14.220Z'
  '@version': '1'
  alert:
    action: allowed
    category: Not Suspicious Traffic
    gid: 1
    metadata:
      created_at:
      - '2010_09_27'
      former_category:
      - POLICY
      updated_at:
      - '2022_05_03'
    rev: 7
    severity: 3
    signature: ET POLICY OpenSSL Demo CA - Internet Widgits Pty (O)
    signature_id: 2011540 ...
```
  ElasticSearch
```
  {
    "_index": "events--2023.03.15",
    "_type": "events--2023.03.15",
    "_id": "yDXp5YYBDOvdmgYrrxS3",
    "_version": 1,
    "_score": 2,
    "_source": {
      "@version": "1",
      "alert": {
        "action": "allowed",
        "category": "Not Suspicious Traffic",
        "gid": 1,
        "metadata": {
          "created_at": [
            "2010_09_27"
          ],
          "former_category": [
            "POLICY"
          ],
          "updated_at": [
            "2022_05_03"
          ]
        },
        "rev": 7,
        "severity": 3,
        "signature": "ET POLICY OpenSSL Demo CA - Internet Widgits Pty (O)",
        "signature_id": 2011540 ...
```

# Enable, Disable, Update, and Status of Suricata Rules

## Enable Suricata Rules of all Minions
* To enable all suricata rules on all minions.
```
./asoc.py -e || ./asoc.py --enable

[+] Enable rule  [Y]es/[N]o? Yes

selk01:
    suricata
    [+] Successfully enabled suricata rules.
selk03:
    suricata
    [+] Successfully enabled suricata rules.
selk02:
    suricata
    [+] Successfully enabled suricata rules.
```
* To enable single or more suricata rules on all minions.
```
salt '*' cmd.run 'python3 /opt/atd/ATD.py --enable 2260000'
salt '*' cmd.run 'python3 /opt/atd/ATD.py --enable 2260000,2260001,2260002'
```

## Disable Suricata Rules of all Minions
* To disable suricata rules on all minions.
```
./asoc.py -d || ./asoc.py --disable

[+] Disable rule  [Y]es/[N]o? Yes
selk01:
    suricata
    [!] Successfully disable suricata rules.
selk03:
    suricata
    [!] Successfully disable suricata rules.
selk02:
    suricata
    [!] Successfully disable suricata rules.
```
* To disable single or more suricata rules on all minions.
```
./asoc.py -d 2260000 || ./asoc.py --disable 2260000
./asoc.py -d 2260000,2260001,2260002 || ./asoc.py --disable 2260000,2260001,2260002
```

## Update Suricata Rules of all Minions
* To update suricata rules on all minions.
```
./asoc.py -u || ./asoc.py --update

[+] Update rule  [Y]es/[N]o? Yes
selk02:
    Successfully pushed ruleset to suricata "suricata"
selk01:
    Successfully pushed ruleset to suricata "suricata"
selk03:
    Successfully pushed ruleset to suricata "suricata"
```

## Status of Suricata Rules of all Minions
* To check the status of suricata rules on all minions.
```
./asoc.py -s || ./asoc.py --status

[+] Getting rule status. Please Wait...
selk03:
    +----------+---------+------------------------------------------------------+
    | status   |     sid | msg                                                  |
    |----------+---------+------------------------------------------------------|
    | OFF      | 2260000 | SURICATA Applayer Mismatch protocol both directions  |
    | OFF      | 2260001 | SURICATA Applayer Wrong direction first Data         |
    | OFF      | 2260002 | SURICATA Applayer Detect protocol only one direction |
    | OFF      | 2260003 | SURICATA Applayer Protocol detection skipped         |
    | OFF      | 2260004 | SURICATA Applayer No TLS after STARTTLS              |
    | OFF      | 2260005 | SURICATA Applayer Unexpected protocol                |
    +----------+---------+------------------------------------------------------+
selk02:
    +----------+---------+------------------------------------------------------+
    | status   |     sid | msg                                                  |
    |----------+---------+------------------------------------------------------|
    | OFF      | 2260000 | SURICATA Applayer Mismatch protocol both directions  |
    | OFF      | 2260001 | SURICATA Applayer Wrong direction first Data         |
    | OFF      | 2260002 | SURICATA Applayer Detect protocol only one direction |
    | OFF      | 2260003 | SURICATA Applayer Protocol detection skipped         |
    | OFF      | 2260004 | SURICATA Applayer No TLS after STARTTLS              |
    | OFF      | 2260005 | SURICATA Applayer Unexpected protocol                |
    +----------+---------+------------------------------------------------------+
selk01:
    +----------+---------+------------------------------------------------------+
    | status   |     sid | msg                                                  |
    |----------+---------+------------------------------------------------------|
    | OFF      | 2260000 | SURICATA Applayer Mismatch protocol both directions  |
    | OFF      | 2260001 | SURICATA Applayer Wrong direction first Data         |
    | OFF      | 2260002 | SURICATA Applayer Detect protocol only one direction |
    | OFF      | 2260003 | SURICATA Applayer Protocol detection skipped         |
    | OFF      | 2260004 | SURICATA Applayer No TLS after STARTTLS              |
    | OFF      | 2260005 | SURICATA Applayer Unexpected protocol                |
    +----------+---------+------------------------------------------------------+
```

# Troublshooting

* If you encounter installation issue on SaltStack "Unable to locate package salt-master or Unable to locate package salt-minion. So in order to resolve this issue, you have to follow these steps.
  ```
  sudo nano /etc/apt/sources.list.d/salt.list
  ```
  Paste this text to the editor and save the file.
  ```
  deb http://repo.saltproject.io/py3/ubuntu/20.04/amd64/latest focal main
  ```
* If you encounter the "ModuleNotFoundError: No module named 'elasticsearch'" error, on the first installation of Afovos Threat Detection.
  ```
  Traceback (most recent call last):
    File "ATD.py", line 20, in <module>
      from elasticsearch import Elasticsearch
  ModuleNotFoundError: No module named 'elasticsearch'
  ```
  it means that the python package is not yet installed. To fix this issue, run the following command:
  ```
  ./asoc.py -ir || ./asoc.py --install_requirements
  ```
* If you encounter the "Failed to establish a new connection: [Errno 111] Connection refused". It means the SELKS port are not yet configure. Run this command:
  ```
  ./asoc.py -ir || ./asoc.py --install_requirements
  ```
* If you encounter the "No selk02 minion on ATD.conf please fill up user, site, parameter etc. first on conf file." error, but you are very sure that selk02 has some entries on ATD.conf.
  ```
  selk02:
    2023-03-15 16:58:16,560 [WARNING] [198853] [!] No all minion on ATD.conf please fill up user, site, parameter etc. first on conf file.
  ```
  Current working directory isn't the path of the script, it's where you are running the script from. And apparently, you're running your script from /opt directory If you schedule a job on minions. If you want the directory of the script replace os.cwd() with this:
  ```
  from os.path import dirname, abspath
  path = abspath(dirname(__file__))
  ```
* If you check the logs by running ./asoc.py -ll || .asoc.py --list_logging and some of the minions didn't display any logs, it means other minions logging are not yet configured.
  ```
  ./asoc.py -ll || .asoc.py --list_logging

  so1.localdomain:
      2023-03-15 06:36:23,845 [salt.minion      :1693][INFO    ][1978700] User root Executing command cmd.run with jid 20230315063549560356
      2023-03-15 06:36:23,896 [salt.minion      :1890][INFO    ][1979051] Starting a new job 20230315063549560356 with PID 1979051
      2023-03-15 06:36:23,901 [salt.loaded.int.module.cmdmod:417 ][INFO    ][1979051] Executing command 'tail' in directory '/opt'
  selk02:
  selk03:
  selk01:
  ```
  This will open the SaltStack configuration file, usually located at /etc/salt/minion on the minion or /etc/salt/master on the master. Will look for the Logging settings section, and enable salt logging by uncommenting log modules.
  ```
  ./asoc.py -lm || ./asoc.py --logging_minion
  ```
  Restart the SaltStack minion service to apply the new logging configuration:
  ```
  ./asoc.py -ri || ./asoc.py --restart_minion
  ```
* If you encounter the "Minions did not return. [No response]" error if you run salt '*' cmd.run 'tail /var/log/salt/minion' command.
  ```
  ./asoc.py -ll || .asoc.py --list_logging

  selk02:
      Minion did not return. [Not connected]
  ERROR: Minions returned with non-zero exit code ...
  ```
  Give minions some time maybe it is possible a network error or minions still processing, rerun the command again and check if error still exists, If not successful check the status of minion:
  ```
  ./asoc.py -si || ./asoc.py --status_minion
  ```
  If it was not running, start it and try your test again.
  ```
  ./asoc.py -ri || ./asoc.py --restart_minion
  ```
  Depending on your installation method, the salt-minion may not have been registered to start upon system boot, and you may run into this issue again after a reboot.

  Now, if your salt-minion was in fact running, and you are still getting No response, I would stop the process and restart the minion in debug so you can watch.
  ```
  sudo systemctl stop salt-minion
  sudo salt-minion -l debug
  ```
  Another quick test you can run to test communication between your minion and master is to execute your test from the minion:
  ```
  sudo selk02 test.ping
  ```
  If the error still exists, you can also reboot the machine or reinstall minions:
  ```
  sudo reboot
  ```

* If you notice SALT scheduled job is not working or lagging delete scheduled job and created new one with different job name.
  ```
  ./asoc.py -rs afovos-selk job_boileau-selk || ./asoc.py --remove_schedule afovos-selk job_boileau-selk
  ./asoc.py -as afovos-selk job2_boileau-selk 120 2000 60 elastic ||  ./asoc.py --add_schedule afovos-selk job2_boileau-selk 120 2000 60 elastic
  ```
# References
  
  * Saltstack: Guide
  
    http://10.254.10.1:8080/articles/CM-A-82/Saltstack:-Guide
  * ATD: Installation of Asoc Threat Detection on Minions
  
    http://10.254.10.1:8080/articles/CM-A-86/Evebox:-Installation-of-Evebox-Parser-on-Minions
  * ATD: Schedule Asoc Threat Detection Job and Logging for SaltStack Minions
  
    http://10.254.10.1:8080/articles/CM-A-89/Evebox:-Schedule-Evebox-Parser-Job-and-Logging-for-SaltStack-Minions
  * ATD: Monitor Scheduled Asoc Threat Detection Job from Salt Logging
  
    http://10.254.10.1:8080/articles/CM-A-90/Evebox:-Monitor-Scheduled-Evebox-Parser-Job-from-Salt-Logging
  * ATD: Troubleshooting Asoc Threat Detection and SaltStack
  
    http://10.254.10.1:8080/articles/CM-A-91/Evebox:-Troubleshooting-Evebox-Parser-and-SaltStack
  * Generating Alerts using PCAPS in SELKS
  
    http://10.254.10.1:8080/articles/CM-A-77/Generating-Alerts-using-PCAPS-in-SELKS---EveBox-API
  * ATD: ASOC Command Operations

    http://10.254.10.1:8080/articles/CM-A-99/ASOC:-Command-Operations
  * ATD: Quick Start Guide

    http://10.254.10.1:8080/articles/CM-A-126/ATD:-Quick-Start-Guide
  * ATD: Test Process

    http://10.254.10.1:8080/articles/AM-A-16/ATD:-Test-Process