#!/usr/bin/python3

#
# Copyright (C) 2023 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Library that handles the DPI rules.
"""

import ipaddress
import json
import subprocess
from fnmatch import fnmatch

import math
from euci import EUci

from nethsec import utils, firewall, objects
from nethsec.utils import ValidationError


def __load_applications() -> dict[int, str]:
    """
    Reads the applications from the netify-apps.conf file.

    Returns:
        dict of applications, each dict contains the property "id" and "name"
    """
    applications = dict[int, str]()
    with open('/etc/netifyd/netify-apps.conf', 'r') as file:
        for line in file.readlines():
            if line.startswith('app'):
                line_split = line.strip().removesuffix('\n').removeprefix('app:').split(":")
                applications[int(line_split[0])] = line_split[1]
    return applications


def __load_application_categories() -> dict[int, dict[str]]:
    """
    Reads the application categories from the netify-categories.json file.

    Returns:
        dict of application categories, each dict contains the property "id" and "name"
    """
    categories = dict[int, dict[str]]()
    with open('/etc/netifyd/netify-categories.json', 'r') as file:
        categories_file = json.load(file)

        categories_names = dict[int, str]()
        if 'application_tag_index' not in categories_file:
            for category_name, applications in categories_file['application_index'].items():
                for application in applications:
                    categories[application] = {
                        'name': category_name
                    }
        else:
            categories_application_tag_index: dict[str, int] = categories_file['application_tag_index']
            for category_name, category_id in categories_application_tag_index.items():
                categories_names[category_id] = category_name

            categories_application_index: list[int, list[int]] = categories_file['application_index']
            for category_id, applications_id in categories_application_index:
                for application_id in applications_id:
                    categories[application_id] = {
                        'name': categories_names[category_id]
                    }

    return categories


def load_protocols() -> dict[int, str]:
    """
    Reads the protocols from the netifyd --dump-protos command.

    Returns:
        dict of protocols, each dict contains the property "id" and "name"
    """
    result = subprocess.run(['netifyd', '--dump-protos'], check=True, capture_output=True)
    protocols = dict[int, str]()
    for line in result.stdout.decode().splitlines():
        # lines can be empty
        if len(line) < 1:
            continue
        line_split = line.split(":", 1)
        try:
            protocols[int(line_split[0].strip())] = line_split[1].strip()
        except (ValueError, IndexError):
            # not a protocol line (header or unexpected format)
            continue

    return protocols


def __load_protocol_categories() -> dict[int, dict[str]]:
    """
    Reads the protocol categories from the netify-categories.json file.

    Returns:
        dict of protocol categories, each dict contains the property "id" and "name"
    """
    categories = dict[int, dict[str]]()
    with open('/etc/netifyd/netify-categories.json', 'r') as file:
        categories_file = json.load(file)

        categories_names = dict[int, str]()

        if 'protocol_tag_index' not in categories_file:
            for category_name, protocols in categories_file['protocol_index'].items():
                for protocol in protocols:
                    categories[protocol] = {
                        'name': category_name
                    }
        else:
            categories_protocol_tag_index: dict[str, int] = categories_file['protocol_tag_index']
            for category_name, category_id in categories_protocol_tag_index.items():
                categories_names[category_id] = category_name

            categories_protocol_index: list[int, list[int]] = categories_file['protocol_index']
            for category_id, protocol_ids in categories_protocol_index:
                for protocol_id in protocol_ids:
                    categories[protocol_id] = {
                        'name': categories_names[category_id]
                    }

    return categories


def __load_blocklist() -> list[dict[str]]:
    """
    Format the applications and protocols into a list of dicts.

    Returns:
        list of dicts, each dict contains the property "id", "name", "type" and "category"
    """
    result = list[dict[str]]()
    applications = __load_applications()
    application_categories = __load_application_categories()

    for application_id, application_name in applications.items():
        result_application = {
            'id': application_id,
            'name': application_name,
            'type': 'application'
        }
        if application_id in application_categories:
            result_application['category'] = application_categories[application_id]
        result.append(result_application)

    protocols = load_protocols()
    protocol_categories = __load_protocol_categories()

    for protocol_id, protocol_name in protocols.items():
        result_protocol = {
            'id': protocol_id,
            'name': protocol_name,
            'type': 'protocol'
        }
        if protocol_id in protocol_categories:
            result_protocol['category'] = protocol_categories[protocol_id]
        result.append(result_protocol)

    return result


def list_devices(e_uci: EUci):
    """
    List device-interface available for filtering.

    Returns:
        list of dicts, each dict contains the property "interface" and "device"
    """
    instance_name = list(e_uci.get('netifyd').keys())[0]
    devices = e_uci.get('netifyd', instance_name, 'internal_if', default=[], list=True)
    for zone in firewall.list_zones(e_uci).values():
        if zone['name'] == 'wan':
            continue
        network_devices = utils.get_all_devices_by_zone(e_uci, zone['name'])
        devices = list(set(list(devices) + network_devices))
    ret = []
    for item in devices:
        interface_name = utils.get_interface_from_device(e_uci, item)
        ret.append({
            'interface': interface_name if interface_name is not None else item,
            'device': item
        })
    return ret

def list_applications(search: str = None, limit: int = None, page: int = 1) -> dict:
    """
    List applications available for filtering.

    Args:
      - search: search string
      - limit: limit the number of results
      - page: page number

    Returns:
        list of dicts, each dict contains the property "code" and "name"
    """
    result = __load_blocklist()

    if search is not None:
        # lower string so we can do a case-insensitive search
        search = search.lower()
        # I'm aware it's far from a readable code, but list comprehension is the fastest way to filter.
        result = [item for item in result if
                  item.get('name', '').lower().find(search) != -1 or
                  item.get('category', {}).get('name', '').lower().find(search) != -1]

    total = len(result)

    if limit is not None:
        result = result[limit * (page - 1):limit * page]
        last_page = math.ceil(total / limit)
    else:
        last_page = 1

    return {
        'data': result,
        'meta': {
            'last_page': last_page,
            'total': total,
        }
    }


def list_popular(e_uci: EUci, limit: int = None, page: int = 1) -> dict:
    """
    List popular applications available for filtering.

    Args:
      - limit: limit the number of results
      - page: page number

    Returns:
        list of dicts, each dict contains the property "id", "name", "type" and "category"
    """
    popular_filters = e_uci.get('dpi', 'config', 'popular_filters', default=[], list=True)
    block_list = {block['name']: block for block in __load_blocklist()}
    result = []

    for popular_filter in popular_filters:
        if popular_filter in block_list.keys():
            result.append(block_list[popular_filter] | {'missing': False})
        else:
            result.append({
                'name': popular_filter,
                'missing': True
            })

    total = len(result)

    if limit is not None:
        result = result[limit * (page - 1):limit * page]
        last_page = math.ceil(total / limit)
    else:
        last_page = 1

    return {
        'data': result,
        'meta': {
            'last_page': last_page,
            'total': total,
        }
    }


def list_rules(e_uci: EUci) -> list[dict[str]]:
    """
    Index all rules

    Args:
      - e_uci: euci instance

    Returns:
        list of dicts, each dict contains the property "config-name", "description", "enabled", "interface" and "blocks"
    """
    rules = list[dict[str]]()
    fetch_rules = utils.get_all_by_type(e_uci, 'dpi', 'rule')

    if not fetch_rules:
        return rules

    for rule_name in fetch_rules.keys():
        # skipping rules with criteria, must be custom entries
        if e_uci.get('dpi', rule_name, 'criteria', default=None) is None:
            # load blocklist of applications and protocols
            blocklist = __load_blocklist()
            # get content of rule
            rule = fetch_rules[rule_name]
            # prepare the data to append to rules
            data_rule = dict[str]()
            data_rule['config-name'] = rule_name
            data_rule['enabled'] = rule.get('enabled', '1') == '1'
            data_rule['device'] = rule.get('device', '*')
            # from device, get the interface
            interface = None if is_any_device(data_rule['device']) else \
                utils.get_interface_from_device(e_uci, data_rule['device'])
            if interface is not None:
                data_rule['interface'] = interface
            data_rule['source'] = list(rule.get('source', []))
            data_rule['action'] = rule.get('action')
            # get the blocked applications/protocols
            data_rule['criteria'] = list[dict[str]]()

            # filter by application
            application_blocklist = [item for item in blocklist if item['type'] == 'application']
            for application in rule.get('application', []):
                found_app = [item for item in application_blocklist if item['name'] == application]
                # there's a possibility of not finding the application due to manual edit of the config
                if len(found_app) > 0:
                    data_rule['criteria'].append(found_app[0])

            # filter by protocol
            protocol_blocklist = [item for item in blocklist if item['type'] == 'protocol']
            for protocol in rule.get('protocol', []):
                found_protocol = [item for item in protocol_blocklist if item['name'] == protocol]
                # there's a possibility of not finding the protocol due to manual edit of the config
                if len(found_protocol) > 0:
                    data_rule['criteria'].append(found_protocol[0])

            # append rule
            rules.append(data_rule)

    return rules


ANY_DEVICE = ('', '*')


def is_any_device(device) -> bool:
    """True when a rule is not bound to a specific interface."""
    return device is None or device in ANY_DEVICE


def validate_source(e_uci: EUci, item: str) -> str:
    """
    Validate one rule source: an object id (objects/, dhcp/, users/) that exists, or an IP address / CIDR network.

    Returns:
        the source, normalized (CIDR as network address form is kept as typed, stripped)

    Raises:
        - ValidationError: if the source is neither an existing object nor a valid IP/CIDR
    """
    if not isinstance(item, str) or not item.strip():
        raise ValidationError('source', 'invalid', str(item))
    item = item.strip()
    if objects.is_object_id(item):
        if not objects.object_exists(e_uci, item):
            raise ValidationError('source', 'object_not_found', item)
        return item
    try:
        ipaddress.ip_network(item, strict=False)
    except ValueError:
        raise ValidationError('source', 'invalid', item)
    return item


def resolve_source(e_uci: EUci, item: str) -> list[str]:
    """
    Resolve one source to the IP/CIDR strings the DPI engine matches on. IP ranges (a-b) found in objects are
    converted to CIDR blocks. Entries that are not understood are dropped.
    """
    raw = objects.get_object_ips(e_uci, item) if objects.is_object_id(item) else [item]
    result = []
    for entry in raw:
        entry = str(entry).strip()
        if '-' in entry:
            try:
                first, last = (ipaddress.ip_address(x.strip()) for x in entry.split('-', 1))
                result.extend(str(n) for n in ipaddress.summarize_address_range(first, last))
            except ValueError:
                continue
            continue
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        result.append(entry)
    return result


def build_criteria(device, matches: list[str], matchers: list[str], vlan_id=None):
    """
    Build the flow-actions criteria of a rule.

    Args:
      - device: device the rule is bound to, empty or '*' for any device
      - matches: resolved IP/CIDR source list, empty for every host
      - matchers: expressions like "app == 'x'", "proto == 'y'" joined by 'or'
      - vlan_id: VLAN id when the device is a VLAN, the caller passes the base device

    Returns:
        the criteria string, or None when it would not restrict anything at all
    """
    parts = []
    if not is_any_device(device):
        parts.append(f"(iface_nfq_src == '{device}' or iface_nfq_dst == '{device}')")
    if matches:
        parts.append('(' + ' or '.join(f'local_ip == {m}' for m in matches) + ')')
    if not parts:
        return None
    if matchers:
        parts.append('(' + ' or '.join(matchers) + ')')
    criteria = ' && '.join(parts)
    if vlan_id is not None:
        criteria = f'vlan_id == {vlan_id} && {criteria}'
    return criteria + ' ;'


def __save_rule_data(e_uci: EUci, config_name: str, enabled: bool, device: str, action: str, applications: list[str],
                     protocols: list[str], sources: list[str] = None):
    sources = [validate_source(e_uci, x) for x in (sources or [])]
    if is_any_device(device) and not sources:
        # a rule bound to nothing would apply to every host on every interface
        raise ValidationError('device', 'required', device or '')
    e_uci.set('dpi', config_name, 'enabled', enabled)
    if is_any_device(device):
        e_uci.delete('dpi', config_name, 'device')
    else:
        e_uci.set('dpi', config_name, 'device', device)
    e_uci.set('dpi', config_name, 'action', action)
    e_uci.set('dpi', config_name, 'application', applications)
    e_uci.set('dpi', config_name, 'protocol', protocols)
    if sources:
        e_uci.set('dpi', config_name, 'source', sources)
    else:
        e_uci.delete('dpi', config_name, 'source')

def __save_exemption_data(e_uci: EUci, config_name: str, criteria: str, description: str, enabled: bool):
    e_uci.set('dpi', config_name, 'enabled', enabled)
    e_uci.set('dpi', config_name, 'criteria', criteria)
    e_uci.set('dpi', config_name, 'description', description)

def __toggle_engine(e_uci: EUci):
    count_enabled = 0
    for section in e_uci.get_all('dpi'):
        if e_uci.get('dpi', section, default="") == "rule" and e_uci.get('dpi', section, 'enabled', default="0") == "1":
            count_enabled = count_enabled + 1

    if count_enabled > 0:
        e_uci.set('dpi', 'config', 'enabled', '1')
    else:
        e_uci.set('dpi', 'config', 'enabled', '0')

def add_rule(e_uci: EUci, enabled: bool, device: str, action: str, applications: list[str],
             protocols: list[str], sources: list[str] = None) -> str:
    """
    Store a new rule

    Args:
      - e_uci: euci instance
      - description: description of the rule
      - enabled: enable the rule
      - action: apply specific action to rule, can be 'block', 'bulk', 'best_effort', 'video' or 'voice'
      - device: device to listen and apply the rule on
      - applications: list of applications to block
      - protocols: list of protocols to block
      - sources: optional networks/hosts/objects the rule applies to, every host when empty

    Raises:
        - ValidationError: if a source is invalid or neither device nor sources are given

    Returns:
        config name of the rule created
    """
    rule_name = utils.get_random_id()
    e_uci.set('dpi', rule_name, 'rule')
    __save_rule_data(e_uci, rule_name, enabled, device, action, applications, protocols, sources)
    __toggle_engine(e_uci)
    e_uci.save('dpi')
    return rule_name


def delete_rule(e_uci: EUci, config_name: str):
    """
    Delete a rule

    Args:
      - e_uci: euci instance
      - config_name: config name of the rule to delete
    """
    e_uci.delete('dpi', config_name)
    __toggle_engine(e_uci)
    e_uci.save('dpi')


def edit_rule(e_uci: EUci, config_name: str, enabled: bool, device: str, action: str, applications: list[str],
              protocols: list[str], sources: list[str] = None):
    """
    Edit a rule

    Args:
      - e_uci: euci instance
      - config_name: rule to change
      - enabled: enable the rule
      - device: device to listen and apply the rule on
      - action: apply specific action to rule, can be 'block', 'bulk', 'best_effort', 'video' or 'voice'
      - applications: array of applications to block
      - protocols: array of protocols to block
      - sources: optional networks/hosts/objects the rule applies to, every host when empty

    Raises
        - ValidationError: if the config name is invalid
    """
    if e_uci.get('dpi', config_name, default=None) is None:
        raise ValidationError('config-name', 'invalid', config_name)

    __save_rule_data(e_uci, config_name, enabled, device, action, applications, protocols, sources)
    __toggle_engine(e_uci)

    e_uci.save('dpi')

def list_exemptions(e_uci: EUci) -> list[dict[str]]:
    """
    Index all global exemptions

    Args:
      - e_uci: euci instance

    Returns:
        list of dicts, each dict contains the property "config-name", "description", "enabled", "criteria"
    """
    exemptions = list[dict[str]]()
    fetch_ex = utils.get_all_by_type(e_uci, 'dpi', 'exemption')

    if not fetch_ex:
        return exemptions
    for ex_name in fetch_ex.keys():
        # get content of exemption
        ex = fetch_ex[ex_name]
        # prepare the data to append to rules
        data_ex = dict[str]()
        data_ex['config-name'] = ex_name
        data_ex['enabled'] = ex.get('enabled', '1') == '1'
        data_ex['criteria'] = ex.get('criteria', '')
        data_ex['description'] = ex.get('description', '')
        # append exemption
        exemptions.append(data_ex)

    return exemptions


def add_exemption(e_uci: EUci, criteria: str, description: str, enabled: bool):
    """
    Store a new global exemption

    Args:
      - e_uci: euci instance
      - criteria: exemption criteria, usually it's an IP address
      - description: description of the rule
      - enabled: enable the exemption

    Returns:
        config name of the exemption created
    """
    ex_list = utils.get_all_by_type(e_uci, 'dpi', 'exemption')
    for ex_name in ex_list:
        ex = ex_list[ex_name]
        if ex.get('criteria', '') == criteria:
            raise ValidationError('criteria', 'criteria_already_exists', criteria)

    ex_name = utils.get_random_id()
    e_uci.set('dpi', ex_name, 'exemption')
    __save_exemption_data(e_uci, ex_name, criteria, description, enabled)
    e_uci.save('dpi')
    return ex_name


def delete_exemption(e_uci: EUci, config_name: str):
    """
    Delete a global exemption

    Args:
      - e_uci: euci instance
      - config_name: config name of the rule to delete
    """
    e_uci.delete('dpi', config_name)
    e_uci.save('dpi')


def edit_exemption(e_uci: EUci, config_name: str, criteria: str, description: str, enabled: bool):
    """
    Edit a global exemption

    Args:
      - e_uci: euci instance
      - config_name: rule to change
      - criteria: exemption criteria, usually it's an IP address
      - description: description of the rule
      - enabled: enable the exemption

    Raises
        - ValidationError: if the config name is invalid
    """
    if e_uci.get('dpi', config_name, default=None) is None:
        raise ValidationError('config-name', 'invalid', config_name)

    __save_exemption_data(e_uci, config_name, criteria, description, enabled)
    e_uci.save('dpi')


# --- application catalog (see nexwall-dpi-catalog) -----------------------------------------------------------------

CATALOG_CLIENT = '/usr/sbin/nexwall-dpi-catalog'
CATALOG_INTERVAL_RANGE = (1, 168)


def get_catalog_settings(e_uci: EUci) -> dict:
    """
    Settings of the automatic catalog update.

    Returns:
        dict with "auto_update" (bool) and "interval" (hours between checks)
    """
    try:
        interval = int(e_uci.get('dpi', 'catalog', 'interval', default='24'))
    except ValueError:
        interval = 24
    low, high = CATALOG_INTERVAL_RANGE
    return {
        'auto_update': e_uci.get('dpi', 'catalog', 'auto_update', default='1') != '0',
        'interval': min(max(interval, low), high),
    }


def set_catalog_settings(e_uci: EUci, auto_update: bool, interval: int):
    """
    Store the settings of the automatic catalog update.

    Raises:
        - ValidationError: if the interval is not a whole number of hours between 1 and 168
    """
    low, high = CATALOG_INTERVAL_RANGE
    if isinstance(interval, bool) or not isinstance(interval, int) or not low <= interval <= high:
        raise ValidationError('interval', 'invalid', str(interval))
    if e_uci.get('dpi', 'catalog', default=None) is None:
        e_uci.set('dpi', 'catalog', 'catalog')
    e_uci.set('dpi', 'catalog', 'auto_update', '1' if auto_update else '0')
    e_uci.set('dpi', 'catalog', 'interval', str(interval))
    e_uci.save('dpi')


def _run_catalog_client(args: list[str], timeout: int) -> dict:
    try:
        proc = subprocess.run([CATALOG_CLIENT] + args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ValueError(f'catalog client failed: {e}')
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise ValueError(proc.stderr.strip() or proc.stdout.strip() or 'catalog client returned no data')


def get_catalog_status() -> dict:
    """
    State of the application catalog: license state, where the catalog in use comes from ("nexwall" or "open"),
    version, number of applications/domains, last check and result, next check.
    """
    return _run_catalog_client(['status', '--json'], 30)


def update_catalog() -> dict:
    """
    Fetch and install the current catalog now (only possible while the unit is licensed, otherwise the open list
    stays in use). Returns the status afterwards.
    """
    subprocess.run([CATALOG_CLIENT, 'update'], capture_output=True, text=True, timeout=180, check=False)
    return get_catalog_status()
