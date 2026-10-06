import sys
import types

from nethsec.dpi import profiles


def install_fake(monkeypatch, apply_result=None, boom=False):
    mod = types.ModuleType('nethsec.webprotection.profiles')
    calls = []

    def apply(e_uci, profile):
        calls.append(profile)
        if boom:
            raise RuntimeError('web side failed')
        return apply_result or {'rules': 1, 'enabled': True, 'categories': 3}
    mod.apply = apply
    mod.list_categories = lambda pid: [{'id': 'adult', 'title': 'Adult content'}]
    mod.describe = lambda pid: {'blocks': [], 'inspects': [], 'antivirus': True, 'safesearch': True, 'youtube': 'strict'}
    pkg = types.ModuleType('nethsec.webprotection')
    pkg.profiles = mod
    monkeypatch.setitem(sys.modules, 'nethsec.webprotection', pkg)
    monkeypatch.setitem(sys.modules, 'nethsec.webprotection.profiles', mod)
    return calls


def test_without_web_protection_the_profiles_are_what_they_were(monkeypatch):
    monkeypatch.setitem(sys.modules, 'nethsec.webprotection', None)      # import fails, like a community build
    assert profiles._web_profiles() is None
    assert all('web_blocks' not in p for p in profiles.list_profiles())


def test_with_web_protection_the_profiles_list_the_website_categories(monkeypatch):
    install_fake(monkeypatch)
    listed = profiles.list_profiles()
    assert [p['id'] for p in listed] == ['standard', 'school', 'restricted']
    assert all(p['web_blocks'] == [{'id': 'adult', 'title': 'Adult content'}] for p in listed)


def test_a_failing_web_side_never_breaks_the_list(monkeypatch):
    install_fake(monkeypatch)
    sys.modules['nethsec.webprotection.profiles'].list_categories = lambda pid: 1 / 0
    assert len(profiles.list_profiles()) == 3
