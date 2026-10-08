#
# Copyright (C) 2026 Nexwall
# SPDX-License-Identifier: GPL-2.0-only
#

import json
from datetime import datetime

from nethsec import webcategories as wc

NOW = datetime(2026, 10, 8, 12, 0, 0).timestamp()


def setup_lists(tmp_path):
    d = tmp_path / 'categories.d'
    d.mkdir()
    (d / '50-ut1-malware.conf').write_text('dom:evil.example\ndom:bad.test\n')
    (d / '50-ut1-adult.conf').write_text('dom:evil.example\ndom:adult.test\n')
    (d / '50-ut1-social-networks.conf').write_text('dom:social.test\n')
    (d / 'other.conf').write_text('dom:ignored.test\n')
    return str(d)


def write_day(tmp_path, day, hosts):
    folder = tmp_path / 'report' / '2026' / '10' / ('%02d' % day) / '192.168.1.5'
    folder.mkdir(parents=True)
    (folder / '09.json').write_text(json.dumps({'total': sum(hosts.values()), 'host': hosts}))
    return str(tmp_path / 'report')


def test_suffixes():
    assert wc.suffixes('a.b.example.com') == ['a.b.example.com', 'b.example.com', 'example.com']
    assert wc.suffixes('localhost') == ['localhost']


def test_lists_are_ordered_security_first(tmp_path):
    names = [c for c, _ in wc.category_lists(setup_lists(tmp_path))]
    assert names == ['malware', 'adult', 'social-networks']


def test_lookup_uses_parent_domains_and_first_list_wins(tmp_path):
    lists = wc.category_lists(setup_lists(tmp_path))
    found = wc.lookup(['www.evil.example', 'x.social.test', 'nothing.org', '10.0.0.1', 'localhost'], lists)
    assert found == {'www.evil.example': 'malware', 'x.social.test': 'social-networks'}


def test_host_answers_are_remembered_and_dropped_when_lists_change(tmp_path):
    d = setup_lists(tmp_path)
    cache = str(tmp_path / 'cache')
    lists = wc.category_lists(d)
    assert wc.host_categories(['a.bad.test', 'zzz.org'], lists, cache) == {'a.bad.test': 'malware', 'zzz.org': 'uncategorized'}
    # remembered: an emptied list does not change the answer until its signature changes
    (tmp_path / 'categories.d' / '50-ut1-malware.conf').write_text('dom:other.test\n')
    assert wc.host_categories(['a.bad.test'], wc.category_lists(d), cache) == {'a.bad.test': 'uncategorized'}


def test_web_categories_sums_days_and_reports_coverage(tmp_path):
    d = setup_lists(tmp_path)
    report = write_day(tmp_path, 8, {'x.social.test': 600, 'evil.example': 100, 'unknown.org': 300, '8.8.8.8': 50})
    write_day(tmp_path, 7, {'x.social.test': 400})
    out = wc.web_categories(days=1, now=NOW, report_dir=report, cache_dir=str(tmp_path / 'c1'), directory=d)
    assert out['total'] == 1050 and out['categorized'] == 700 and out['uncategorized'] == 350
    assert out['categories'][0] == {'id': 'social-networks', 'traffic': 600}
    assert out['lists_installed'] == 3
    two = wc.web_categories(days=2, now=NOW, report_dir=report, cache_dir=str(tmp_path / 'c2'), directory=d)
    assert two['categories'][0] == {'id': 'social-networks', 'traffic': 1000}


def test_no_lists_means_everything_uncategorized(tmp_path):
    report = write_day(tmp_path, 8, {'a.com': 10})
    out = wc.web_categories(days=1, now=NOW, report_dir=report, cache_dir=str(tmp_path / 'c'), directory=str(tmp_path / 'none'))
    assert out['lists_installed'] == 0 and out['categories'] == [] and out['uncategorized'] == 10
