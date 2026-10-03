import os

import pytest

from nethsec import engine_metrics as em

STAT = 'cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 50 0 50 350 50 0 0 0 0 0\ncpu1 50 0 50 350 50 0 0 0 0 0\nintr 1\n'
QUEUES = (
    '   50 3729845622     0 2 65531     0     0      942  1\n'
    '   51 3914364063     5 2 65531    11     3      326  1\n'
    '    4      130808     0 2  1518     7     0     7526  1\n'
    '    5 4171931278     2 2  1518     0     9     3383  1\n'
)


def make_proc(tmp_path, pid=123, name='netifyd', ticks=(40, 10)):
    d = tmp_path / str(pid)
    (d / 'task' / str(pid)).mkdir(parents=True)
    (d / 'comm').write_text(name + '\n')
    (d / 'status').write_text('Name:\t%s\nVmRSS:\t   34100 kB\nThreads:\t18\n' % name)
    # the command name may contain spaces and a closing parenthesis
    stat = '%d (%s x)) S 1 1 1 0 -1 0 0 0 0 0 %d %d 0 0 20 0 18 0 1 1 1' % (pid, name, ticks[0], ticks[1])
    (d / 'task' / str(pid) / 'stat').write_text(stat)
    return d


def test_cpu_ticks():
    assert em.cpu_ticks(STAT) == (200, 1000)          # total minus idle and iowait
    assert em.cpu_ticks('') == (0, 0)


def test_process_ticks_with_awkward_name():
    assert em.process_ticks('5 (a b)) S 1 1 1 0 -1 0 0 0 0 0 7 3 0 0') == 10
    assert em.process_ticks('garbage') == 0


def test_find_pid_and_process_figures(tmp_path):
    make_proc(tmp_path, 123, 'netifyd')
    make_proc(tmp_path, 99, 'netifyd')                 # the lowest pid is the main process
    make_proc(tmp_path, 7, 'other')
    (tmp_path / 'self').mkdir()
    assert em.find_pid('netifyd', str(tmp_path)) == 99
    assert em.find_pid('snort3', str(tmp_path)) is None
    assert em.process_cpu_ticks(123, str(tmp_path)) == 50
    assert em.process_memory(123, str(tmp_path)) == (34100, 18)


def test_memory_uses_available():
    m = em.memory('MemTotal:  2000000 kB\nMemFree: 100 kB\nMemAvailable:  500000 kB\n')
    assert m == {'total_kib': 2000000, 'available_kib': 500000, 'used_kib': 1500000}
    assert em.memory('MemTotal: 10 kB\nMemFree: 4 kB\n')['used_kib'] == 6        # no MemAvailable: fall back
    assert em.memory('')['used_kib'] == 0


def test_queues_are_split_by_engine():
    q = em.queues(QUEUES)
    assert q['dpi'] == {'queues': 2, 'waiting': 5, 'dropped': 11, 'user_dropped': 3, 'handled': 1268}
    assert q['ips'] == {'queues': 2, 'waiting': 2, 'dropped': 7, 'user_dropped': 9, 'handled': 10909}
    assert em.queues('')['dpi']['queues'] == 0
    assert em.queues('junk line\n 1 2\n')['ips']['queues'] == 0


def test_conntrack(tmp_path):
    (tmp_path / 'sys/net/netfilter').mkdir(parents=True)
    (tmp_path / 'sys/net/netfilter/nf_conntrack_count').write_text('1234\n')
    (tmp_path / 'sys/net/netfilter/nf_conntrack_max').write_text('65536\n')
    assert em.conntrack(str(tmp_path)) == {'count': 1234, 'max': 65536}
    assert em.conntrack(str(tmp_path / 'none')) == {'count': 0, 'max': 0}


def test_collect_reads_a_fake_proc(tmp_path, monkeypatch):
    (tmp_path / 'stat').write_text(STAT)
    (tmp_path / 'meminfo').write_text('MemTotal:  2000000 kB\nMemAvailable:  500000 kB\n')
    (tmp_path / 'net/netfilter').mkdir(parents=True)
    (tmp_path / 'net/netfilter/nfnetlink_queue').write_text(QUEUES)
    make_proc(tmp_path, 123, 'netifyd')
    reads = iter([STAT, 'cpu  150 0 150 800 100 0 0 0 0 0\ncpu0 1 0 1 1 1 0 0 0 0 0\ncpu1 1 0 1 1 1 0 0 0 0 0\n'])
    real = em._read

    def fake_read(path):
        if path.endswith('/stat') and os.path.dirname(path) == str(tmp_path):
            return next(reads, STAT)
        return real(path)

    monkeypatch.setattr(em, '_read', fake_read)
    monkeypatch.setattr(em.time, 'sleep', lambda s: None)
    r = em.collect(str(tmp_path), sample=0.5, clock_ticks=100)
    assert r['cpu']['system_pct'] == pytest.approx(100.0 * 100 / 200, abs=0.1)
    assert r['memory']['used_pct'] == 75.0
    assert r['engines']['dpi']['running'] is True and r['engines']['dpi']['rss_kib'] == 34100
    assert r['engines']['ips'] == {'running': False, 'cpu_pct': 0.0, 'rss_kib': 0, 'threads': 0}
    assert r['queues']['dpi']['dropped'] == 11
