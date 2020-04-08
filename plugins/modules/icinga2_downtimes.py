#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# (c) 2019, Thilo Wening <thilo.wening@netways.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '0.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
module: icinga2_downtimes
short_description: A module to deploy downtimes using the Icinga 2 API
description: The module to schedule and remove downtimes at hosts and their services.
author: Thilo Wening (@mkayontour)
options:
  host:
    description: The address and URI to the icinga2 API UI.
    required: true
    type: string
  port:
    description: The port of the Icinga 2 API.
    required: False
    type: string
    default: 5665
  username:
    description: Api Username which is allowed to login to the API and schedule/remove downtimes.
    required: true
    type: string
  password:
    description: Password for the Api User to login.
    required: true
    type: string
  state:
    description: Choose between present and absent.
    required: false
    type: string
    default: present
  hostname:
    description: Name or glob as a string to match any host in the Icinga 2 setup.
    required: false
    type: string
  hostnames:
    description: Names or glob matches in an array to match any host in the Icinga 2 setup.
    required: false
    type: list
  hostgroups:
    description: Hostgroups Names (not aliases) to match hosts within the given list of hostgroups.
    required: false
    type: list
  all_services:
    description: Set to True if all services of the matched hosts should be in downtimes too.
    required: false
    type: bool
    default: false
  author:
    description: Set the name of the author for the downtime. (Must not exist in Icinga Web 2 or Icinga 2)
    required: true
    type: string
  comment:
    description: A comment to show in the Icinga Web 2 interface.
    required: true
    type: string
  starttime:
    description: | 
      When the applied downtime should start, per default it is set to 'Now' 
      which matches the current date in the given timezone.
      
      Date and time need to be in the following format:
        DD/MM/YYYY HH:MM:SS or DD-MM-YYYY HH:MM:SS
    required: false
    default: 'now'
    type: string
  endtime:
    description: |
      The date when the fixed downtime should end. If not set, the parameter duration need to be set. 
      
      Date and time need to be in the following format:
        DD/MM/YYYY HH:MM:SS or DD-MM-YYYY HH:MM:SS
    required: false
    type: string
  duration:
    description: How long the fixed downtime should last in seconds. Will be added onto the starttime.
    required: false
    type: int
  timezone:
    description: | 
      Set the timezone in which the downtime should be active. Lookup timezone names on the TZ database:
      https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
    required: false
    default: Europe/Berlin
    type: string
  ssl_cert:
    description: Set the path to an SSL Certificate to verify the ssl connection to the Icinga 2 API (recommended) 
    required: false
    type: string
    default: None
requirements:
  - requests
  - pytz
  - json
  - python-dateutil

'''

EXAMPLES = r'''
# Schedule Downtime for Host matching the name "agent.localdomain"
---
- name: Set downtime for host 'agent.localdomain' 
  icinga2.icinga2_collection.icinga2_downtimes:
    host: 'https://localhost'
    username: 'icinga'
    password: 'icinga'
    author: "admin"
    comment: "Downtime for Updates"
    duration: "300"
    state: 'present'
    ssl_cert: '/var/lib/icinga2/certs/icinga2-master.localdomain.crt'
    hostname: "agent.localdomain"
    
- name: Set downtime for hosts 
  icinga2.icinga2_collection.icinga2_downtimes:
    host: 'https://localhost'
    username: 'icinga'
    password: 'icinga'
    author: "admin"
    comment: "Downtime for Updates"
    duration: "300"
    state: 'present'
    ssl_cert: '/var/lib/icinga2/certs/icinga2-master.localdomain.crt'
    hostnames: ["agent1.localdomain","agent2.localdomain","win*"]
    
- name: remove downtime for host 'agent.localdomain' 
  icinga2.icinga2_collection.icinga2_downtimes:
    host: 'https://localhost'
    username: 'icinga'
    password: 'icinga'
    state: 'absent'
    ssl_cert: '/var/lib/icinga2/certs/icinga2-master.localdomain.crt'
    hostname: "agent.localdomain"
'''

RETURN = r'''
result:
  results: List of all matched hosts and services each with "code" and "status" key. 
  status_code: "return value of the http request"
'''

import json
import time
from pytz import timezone
import pytz
import requests
from dateutil.parser import parse
from datetime import datetime
from ansible.module_utils.basic import AnsibleModule


class Icinga2Downtimes(object):

    def __init__(self):
        self.host = module.params.get('host')
        self.port = module.params.get('port')
        self.state = module.params.get('state')
        self.username = module.params.get('username')
        self.password = module.params.get('password')
        self.author = module.params.get('author')
        self.start = module.params.get('starttime')
        self.end = module.params.get('endtime')
        self.tz = module.params.get('timezone')
        self.duration = module.params.get('duration')
        self.comment = module.params.get('comment')
        self.hostgroups = module.params.get('hostgroups')
        self.hostnames = module.params.get('hostnames')
        self.hostname = module.params.get('hostname')
        self.service = module.params.get('services')
        self.all_services = module.params.get('all_services')
        self.ssl_cert = module.params.get('ssl_cert')
        self.headers = {'Accept': 'application/json'}


    def run(self):

        url = self.host + ':' + self.port + '/v1'
        if self.state == 'present':
            res = Icinga2Downtimes().set_downtime(url, action='schedule')
        if self.state == 'absent':
            res = Icinga2Downtimes().set_downtime(url, action='remove')

        return res

    def set_downtime(self, url, action):
        if self.state == 'present':
            if self.start and self.end:
                self.start = Icinga2Downtimes().get_unix_time(time_string=self.start, tz_name=self.tz)
                self.end = Icinga2Downtimes().get_unix_time(time_string=self.end, tz_name=self.tz)
            elif self.start and self.duration and self.start != 'now':
                self.start = Icinga2Downtimes().get_unix_time(time_string=self.start, tz_name=self.tz)
                self.end = int(self.start) + self.duration
            elif self.start == 'now' and self.end:
                self.start = Icinga2Downtimes().get_timestamp_now(tz_name=self.tz)
                self.end = Icinga2Downtimes().get_unix_time(time_string=self.end, tz_name=self.tz)
            elif self.start == 'now' and self.duration:
                self.start = Icinga2Downtimes().get_timestamp_now(tz_name=self.tz)
                self.end = int(self.start) + self.duration

        if self.ssl_cert == 'None':
            self.ssl_cert = False

        if self.hostgroups and self.hostnames:
            module.fail_json(msg=('Please choose whether to set downtimes for'
                                  ' hosts or for hostgroups. '
                                  'Both at the same time is not supported.'))

        filters = ""
        data = dict()

        # When remove we don't need author/comment and times
        if action == 'schedule':
          data.update(author=self.author,
                      comment=self.comment,
                      start_time=self.start,
                      end_time=self.end
                      )

          # TODO: Rewrite filter and make second request for single services or multiple
          # if self.services and self.hostgroups:
          #      data = dict(type='Service',
          #                  author=self.author,
          #                  comment=self.comment,
          #                  start_time=self.start,
          #                  end_time=self.end
          #                  )
          # else:
          #     if iter(self.services):
          #         for item in self.services[:-1]:
          #             filters += '&& match(\"' + item + '\" , service.name)'


        if action == 'remove' or action == 'schedule':
          if self.hostname and not self.hostnames and not self.hostgroups:
              data.update(type='Host')
              filters = 'match(\"' + self.hostname + '\" ,host.name)'
              if self.all_services:
                  data.update(all_services=True)

          elif self.hostgroups and not self.hostnames and not self.hostname:
              data.update(type='Host')
              if iter(self.hostgroups):
                  for item in self.hostgroups[:-1]:
                      filters += '\"' + item + '\" in host.groups || '
                  filters += '\"' + self.hostgroups[-1] + '\" in host.groups'
              if self.all_services:
                  data.update(all_services=True)

              # TODO: Rewrite filter and make second request for single services or multiple
              #elif self.service:
              #    filters += ' && match(\"' + self.service + '\" , service.name)'

              data.update(filter=filters)
          
          elif self.hostnames and not self.hostgroups and not self.hostname:
              data.update(type='Host')
              if iter(self.hostnames):
                  for item in self.hostnames[:-1]:
                      filters += 'match(\"' + item + '\" ,host.name) || '
                  filters += 'match(\"' + self.hostnames[-1] + '\" ,host.name)'
              if self.all_services:
                  data.update(all_services=True)
              # TODO: Rewrite filter and make second request for single services or multiple
              # elif self.service:
              #      filters += ' && match(\"' + self.service + '\" , service.name)'
          
              data.update(filter=filters)
          else:
              module.fail_json(msg='Error: Please choose only one param of hostgroups, hostnames or hostname')


        #print(json.dumps(data))
        #print(url)

        try:
            req = requests.post(url + '/actions/' + action + '-downtime',
                                headers=self.headers,
                                auth=(self.username, self.password),
                                data=json.dumps(data),
                                verify=self.ssl_cert)

            if req.status_code == 200 and action == 'schedule':
                res = dict(changed=True,
                           ansible_module_results="Downtimes applied",
                           result=dict(req.json(), status_code=req.status_code))
            elif req.status_code == 200 and action == 'remove':
                res = dict(changed=True,
                           ansible_module_results="Downtimes removed",
                           result=dict(req.json(), status_code=req.status_code))
            else:
                module.fail_json(msg='Error: ' + str(req.text),
                                 status_code=req.status_code)

        except requests.exceptions.RequestException as e:
            module.fail_json(msg='Error: ' + str(e))

        return res

    def get_unix_time(self, time_string, tz_name):
        # parse the time input (without timezone)
        ts = parse(time_string)

        # localize to the specified timezone
        tz = timezone(tz_name)
        ts = tz.localize(ts)

        return int(ts.timestamp())

    def get_timestamp_now(self, tz_name):
        tz = timezone(tz_name)
        ts = datetime.now(tz)

        return int(ts.timestamp())


def main():
    global module
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            username=dict(required=True, no_log=False),
            password=dict(required=True, no_log=True),
            port=dict(required=False, default='5665'),
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            author=dict(required=False),
            starttime=dict(required=False, default='now'),
            endtime=dict(required=False),
            timezone=dict(required=False, default='Europe/Berlin'),
            duration=dict(required=False, type='int'),
            comment=dict(required=False),
            hostgroups=dict(required=False, type='list'),
            hostnames=dict(required=False, type='list'),
            hostname=dict(required=False),
            all_services=dict(required=False, type='bool'),
            service=dict(required=False, type='string'),
            ssl_cert=dict(required=False, default='None')
        ),
        supports_check_mode=False,
    )

    result = Icinga2Downtimes().run()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
