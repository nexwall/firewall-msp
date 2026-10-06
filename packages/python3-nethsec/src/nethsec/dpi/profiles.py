#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Application Control profiles: ready-made sets of rules, chosen in one click.

A profile is a list of groups; a group becomes one blocking rule per LAN device. The rules match whole application and
protocol categories (the engine's ``app_category`` and ``proto_category``), so they follow the application catalog: a new
application added to a blocked category is blocked without touching the rules. The rules carry the option ``ns_profile``,
which is how they are told apart from the administrator's own rules (those are never touched here).

    standard    blocks what does not belong in a school or a workplace (adult content, malware, VPN and proxy
                anonymizers, peer-to-peer, encrypted DNS that bypasses the DNS filtering); social networks, streaming
                and the normal use of a home stay allowed. This is what a firewall has before anything is configured.
    school      standard, plus social networks, video and streaming, games and entertainment.
    restricted  school, plus online shopping, recreation and sports, remote-desktop tools, cloud file sharing and
                advertising: a strict profile for companies.

With Web Protection installed (``nethsec.webprotection.profiles``) choosing a profile also creates one website rule with the
categories of that profile, so applications and websites follow the same choice.
"""

from nethsec import dpi, utils

# one group = one rule; the title is the rule description (English: the web interface translates the profile names, the
# rule list shows these titles)
GROUPS = {
    'adult': {'title': 'Adult content', 'app_category': ['adult']},
    'malware': {'title': 'Malware', 'app_category': ['malware']},
    'anonymizers': {'title': 'VPN, proxies and anonymizers', 'app_category': ['vpn-and-proxy'], 'proto_category': ['proxy']},
    'p2p': {'title': 'Peer-to-peer file sharing', 'protocol': ['bittorrent', 'gnutella']},
    'dns_bypass': {'title': 'Encrypted DNS that bypasses the DNS filtering', 'protocol': ['doh', 'dot']},
    'social': {'title': 'Social networks', 'app_category': ['social-media']},
    'video': {'title': 'Video hosting and streaming', 'app_category': ['streaming-media']},
    'games': {'title': 'Games', 'app_category': ['games'], 'proto_category': ['games']},
    'entertainment': {'title': 'Entertainment', 'app_category': ['entertainment']},
    'shopping': {'title': 'Online shopping', 'app_category': ['shopping']},
    'recreation': {'title': 'Recreation and sports', 'app_category': ['recreation', 'sports']},
    'remote': {'title': 'Remote-desktop tools', 'app_category': ['remote-desktop'], 'proto_category': ['remote-desktop']},
    'cloud_files': {'title': 'Cloud file sharing', 'app_category': ['file-sharing']},
    'ads': {'title': 'Advertising', 'app_category': ['advertiser']},
}

_STANDARD = ['adult', 'malware', 'anonymizers', 'p2p', 'dns_bypass']
_SCHOOL = _STANDARD + ['social', 'video', 'games', 'entertainment']
_RESTRICTED = _SCHOOL + ['shopping', 'recreation', 'remote', 'cloud_files', 'ads']

PROFILES = {
    'standard': {'title': 'Standard', 'groups': _STANDARD},
    'school': {'title': 'School', 'groups': _SCHOOL},
    'restricted': {'title': 'Restricted', 'groups': _RESTRICTED},
}

DEFAULT_PROFILE = 'standard'


def _web_profiles():
    """The Web Protection side of the profiles (package nexwall-webprotection, proprietary, from the vendor feed), None without it."""
    try:
        from nethsec.webprotection import profiles as web_profiles
        return web_profiles
    except ImportError:
        return None


def list_profiles() -> list:
    """The profiles and what they block, for the web interface. With Web Protection installed each profile also lists the website
    categories it blocks (``web_blocks``)."""
    web = _web_profiles()
    out = []
    for pid, p in PROFILES.items():
        item = {'id': pid, 'title': p['title'], 'blocks': [{'id': g, 'title': GROUPS[g]['title']} for g in p['groups']]}
        if web:
            try:
                item['web_blocks'] = web.list_categories(pid)
                item['web'] = web.describe(pid)
            except Exception:
                pass
        out.append(item)
    return out


def active_profile(e_uci) -> str:
    """The profile applied last, or '' when none (the administrator's own rules do not count)."""
    return e_uci.get('dpi', 'config', 'profile', default='')


def _lan_devices(e_uci) -> list:
    devices = utils.get_all_devices_by_zone(e_uci, 'lan', exclude_aliases=True)
    return sorted(set(devices))


def remove_profile_rules(e_uci) -> int:
    """Delete every rule that a profile created. Returns how many."""
    removed = 0
    for name, rule in utils.get_all_by_type(e_uci, 'dpi', 'rule').items():
        if rule.get('ns_profile'):
            e_uci.delete('dpi', name)
            removed += 1
    return removed


def apply_profile(e_uci, profile: str) -> dict:
    """Replace the rules of the previous profile with the rules of this one and make Application Control strict:
    the inspection is on and new connections are blocked when the engine cannot keep up.

    Raises ValidationError('profile', 'invalid', ...) for an unknown profile.
    """
    if profile not in PROFILES:
        raise utils.ValidationError('profile', 'invalid', str(profile))
    remove_profile_rules(e_uci)
    web = _web_profiles()
    web_result = None
    if web:
        try:
            web_result = web.apply(e_uci, profile)       # one rule with the website categories of the profile
        except Exception:                                # never let the website part break Application Control
            web_result = None
    devices = _lan_devices(e_uci)
    created = 0
    for group_id in PROFILES[profile]['groups']:
        group = GROUPS[group_id]
        for device in devices:
            name = dpi.add_rule(e_uci, True, device, 'block', [], list(group.get('protocol', [])), [],
                                '%s: %s' % (PROFILES[profile]['title'], group['title']), True)
            e_uci.set('dpi', name, 'ns_profile', profile)
            if group.get('app_category'):
                e_uci.set('dpi', name, 'app_category', list(group['app_category']))
            if group.get('proto_category'):
                e_uci.set('dpi', name, 'proto_category', list(group['proto_category']))
            created += 1
    e_uci.set('dpi', 'config', 'profile', profile)
    e_uci.set('dpi', 'config', 'enabled', '1' if created else '0')
    # blocked flows are logged (rate limited): the Log Viewer shows what Application Control blocked
    e_uci.set('dpi', 'config', 'log_blocked', '1')
    if not e_uci.get('dpi', 'engine', default=''):
        e_uci.set('dpi', 'engine', 'engine')
    e_uci.set('dpi', 'engine', 'overload_action', 'block')
    e_uci.save('dpi')
    result = {'profile': profile, 'rules': created, 'devices': devices}
    if web_result is not None:
        result['web'] = web_result
    return result
