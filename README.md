# Ansible Collection - icinga2.icinga2_collection

Documentation for the collection.


# Ansible Modules

## Description

This is the first go for this Ansible Module Collection. For the parameter documentation check the ansible-doc

```
ansible-doc icinga2_director_host
ansible-doc icinga2_director_deploy
ansible-doc icinga2_downtimes
```

## Installation

First two things to mention:

I will try to officially push this to Ansible, but this needs much more testing than a smoketest.

I could try to put everything into a collection, then it could be easier to install for ansible. (maybe?)

Otherwise

Clone this repository onto your Ansible Host, and provide the folder in your **ANSIBLE_MODULE_PATH** variable.

You can also set it as environment variable.

```
export ANSIBLE_LIBRARY=$ANSIBLE_LIBRARY:/path/to/local/repository/plugins/modules
```

The required python libraries are documented in each module.

Afterwards you should be getting the documentation for the module!

```
ansible-doc icinga2_director_host
ansible-doc icinga2_director_deploy
ansible-doc icinga2_downtimes
```



And then use it as every plugin in your playbooks or roles.

If you install it as a collection, use the collection syntax to use the module.
Otherwise if the modules are included directly into the modules path then only the module name does it.


```yaml
- name: create simple Host
  icinga2.icinga2_collection.icinga2_director_host:
    name: simple.plan.localdomain
    host: http://icingaweb2.local/icingaweb2
    username: icinga
    password: secret
    update_if_exists: true
    host_vars:
      address: "127.0.0.1"
      check_command: "hostalive"
    custom_vars:
      os: "Linux"
    templates:
      - "basic-host"
  notify: "deploy config"

handlers:
  - name: deploy config
    icinga2.icinga2_collection.icinga2_director_deploy:
      host: http://icingaweb2.local/icingaweb2
      username: 'icinga'
      password: secret

- name: set downtime
  icinga2.icinga2_collection.icinga2_downtimes:
    host: 'https://localhost'
    username: 'icinga'
    password: 'icinga'
    author: "admin"
    comment: "Downtime for Updates"
    duration: "300"
    state: 'present'
    ssl_cert: '/var/lib/icinga2/certs/icinga2-master.localdomain.crt'
    hostnames: ["agent.localdomain"]

```

## Todos

Create as much objects as possible within these modules or this module.

It should be able to create anything ad-hoc with Ansible on the director and Icinga 2.


## Contributing

Feel free to ask questions and open issues. Feedback is always welcome and appreciated.

## License

    Copyright (C) 2019 Thilo Wening <mkayontour@gmail.com>


    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.