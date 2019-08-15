#!/usr/bin/env python3
# Description:
#   Simulate suricata generating alerts in EVE format.
# Copyright: me but not u

import sys
from random import random, choice, gauss
from time import sleep
import json

import arrow
import requests

from os import environ
SCIRIUS_BASE_URL = environ.get('SCIRIUS_HOST', 'http://alertsgen-scirius:8000')
print('USING HOST', SCIRIUS_BASE_URL)

#HOSTNAMES = ['suricata', 'testhost1', 'testhost2', 'testhost3']

HOSTNAMES = ['taro', 'raro', 'suri', 'suricata']
#HOSTNAMES = []

#HOSTNAMES += [f'host {x}' for x in range(40)]

#HOSTNAMES = ['suri']
#HOSTNAMES = ['"WHAT ABOUT THIS"']
#HOSTNAMES = ['" or in(host, [test, test1, test2, test3, test4])']


def parse_ruleset(ruleset: str) -> list:
    """
    Parse a ruleset file. Assumes that the first after '(' is 'msg' and
    there are NO other parenthesies other than that one.
    :return list of {'sid': <sid>, 'msg': <msg>, 'classtype': <classtype>}:
    """
    offs = 0
    rules = []
    # NOTE: this assumption may not hold.
    while True:
        start = ruleset.find('(', offs)
        if start == -1:
            break
        end = ruleset.find('\n', start)
        if end == -1:
            # Malformed input
            print('MALFORMED INPUT, QUITTING!', flush=True)
            break
        offs = end

        def extract_field(name, start, end, default='', unquote=False):
            nonlocal ruleset

            field_start = ruleset.find(name + ':', start, end)
            if field_start == -1:
                return default  # not found

            field_end = ruleset.find(';', field_start, end)
            if field_end == -1:
                return default  # not found

            field = ruleset[field_start + len(name + ':'):field_end]
            if unquote:
                field = field[1:-1]
            return field

        keep_fields = ['msg', 'sid', 'rev',
                       'classtype', 'reference', 'metadata']
        str_fields = set(['msg'])
        #keep_fields = ['msg', 'sid', 'rev']
        rule = {kf: extract_field(kf, start, end, unquote=(
            kf in str_fields)) for kf in keep_fields}
        #rule = {sf: rule[sf][1:-1] if sf in str_fields else rule[sf] for sf in keep_fields}
        rules.append(rule)
    return rules


def rand_ipv4() -> str:
    _bytes = [int(random()*256) for x in range(4)]
    return '.'.join(str(b) for b in _bytes)


def timestamp_now() -> str:
    return str(arrow.now())


def get_status() -> str:
    d = {
        "timestamp": timestamp_now(),
        "event_type": "stats",
        "host": "suricata",
        "stats": {
            "uptime": 32,
            "decoder": {
                "pkts": 985280,
                "bytes": 235274018,
                "invalid": int(abs(gauss(8000, 7000))),
                "ipv4": 973215,
                "ipv6": 276,
                "ethernet": 985280,
                "raw": 0,
                "null": 0,
                "sll": 0,
                "tcp": 960563,
                "udp": 5743,
                "sctp": 0,
                "icmpv4": 2611,
                "icmpv6": 134,
                "ppp": 0,
                "pppoe": 0,
                "gre": 0,
                "vlan": 984478,
                "vlan_qinq": 0,
                "ieee8021ah": 0,
                "teredo": 0,
                "ipv4_in_ipv6": 0,
                "ipv6_in_ipv6": 0,
                "mpls": 0,
                "avg_pkt_size": 238,
                "max_pkt_size": 1518,
                "erspan": 0,
                "event": {
                    "ipv4": {
                        "pkt_too_small": 0,
                        "hlen_too_small": 0,
                        "iplen_smaller_than_hlen": 0,
                        "trunc_pkt": 0,
                        "opt_invalid": 0,
                        "opt_invalid_len": 0,
                        "opt_malformed": 0,
                        "opt_pad_required": 29,
                        "opt_eol_required": 0,
                        "opt_duplicate": 0,
                        "opt_unknown": 0,
                        "wrong_ip_version": 0,
                        "icmpv6": 0,
                        "frag_pkt_too_large": 0,
                        "frag_overlap": 0,
                        "frag_ignored": 0
                    },
                    "icmpv4": {
                        "pkt_too_small": 0,
                        "unknown_type": 0,
                        "unknown_code": 41,
                        "ipv4_trunc_pkt": 0,
                        "ipv4_unknown_ver": 0
                    },
                    "icmpv6": {
                        "unknown_type": 0,
                        "unknown_code": 0,
                        "pkt_too_small": 0,
                        "ipv6_unknown_version": 0,
                        "ipv6_trunc_pkt": 0,
                        "mld_message_with_invalid_hl": 0,
                        "unassigned_type": 0,
                        "experimentation_type": 0
                    },
                    "ipv6": {
                        "pkt_too_small": 0,
                        "trunc_pkt": 0,
                        "trunc_exthdr": 0,
                        "exthdr_dupl_fh": 0,
                        "exthdr_useless_fh": 0,
                        "exthdr_dupl_rh": 0,
                        "exthdr_dupl_hh": 0,
                        "exthdr_dupl_dh": 0,
                        "exthdr_dupl_ah": 0,
                        "exthdr_dupl_eh": 0,
                        "exthdr_invalid_optlen": 0,
                        "wrong_ip_version": 0,
                        "exthdr_ah_res_not_null": 0,
                        "hopopts_unknown_opt": 0,
                        "hopopts_only_padding": 0,
                        "dstopts_unknown_opt": 0,
                        "dstopts_only_padding": 0,
                        "rh_type_0": 0,
                        "zero_len_padn": 12,
                        "fh_non_zero_reserved_field": 0,
                        "data_after_none_header": 0,
                        "unknown_next_header": 0,
                        "icmpv4": 0,
                        "frag_pkt_too_large": 0,
                        "frag_overlap": 0,
                        "frag_ignored": 0,
                        "ipv4_in_ipv6_too_small": 0,
                        "ipv4_in_ipv6_wrong_version": 0,
                        "ipv6_in_ipv6_too_small": 0,
                        "ipv6_in_ipv6_wrong_version": 0
                    },
                    "tcp": {
                        "pkt_too_small": 0,
                        "hlen_too_small": 0,
                        "invalid_optlen": 0,
                        "opt_invalid_len": 0,
                        "opt_duplicate": 0
                    },
                    "udp": {
                        "pkt_too_small": 0,
                        "hlen_too_small": 0,
                        "hlen_invalid": 0
                    },
                    "sll": {
                        "pkt_too_small": 0
                    },
                    "ethernet": {
                        "pkt_too_small": 0
                    },
                    "ppp": {
                        "pkt_too_small": 0,
                        "vju_pkt_too_small": 0,
                        "ip4_pkt_too_small": 0,
                        "ip6_pkt_too_small": 0,
                        "wrong_type": 0,
                        "unsup_proto": 0
                    },
                    "pppoe": {
                        "pkt_too_small": 0,
                        "wrong_code": 0,
                        "malformed_tags": 0
                    },
                    "gre": {
                        "pkt_too_small": 0,
                        "wrong_version": 0,
                        "version0_recur": 0,
                        "version0_flags": 0,
                        "version0_hdr_too_big": 0,
                        "version0_malformed_sre_hdr": 0,
                        "version1_chksum": 0,
                        "version1_route": 0,
                        "version1_ssr": 0,
                        "version1_recur": 0,
                        "version1_flags": 0,
                        "version1_no_key": 0,
                        "version1_wrong_protocol": 0,
                        "version1_malformed_sre_hdr": 0,
                        "version1_hdr_too_big": 0
                    },
                    "vlan": {
                        "header_too_small": 0,
                        "unknown_type": 10182,
                        "too_many_layers": 0
                    },
                    "ieee8021ah": {
                        "header_too_small": 0
                    },
                    "ipraw": {
                        "invalid_ip_version": 0
                    },
                    "ltnull": {
                        "pkt_too_small": 0,
                        "unsupported_type": 0
                    },
                    "sctp": {
                        "pkt_too_small": 0
                    },
                    "mpls": {
                        "header_too_small": 0,
                        "pkt_too_small": 0,
                        "bad_label_router_alert": 0,
                        "bad_label_implicit_null": 0,
                        "bad_label_reserved": 0,
                        "unknown_payload_type": 0
                    },
                    "erspan": {
                        "header_too_small": 0,
                        "unsupported_version": 0,
                        "too_many_vlan_layers": 0
                    }
                },
                "dce": {
                    "pkt_too_small": 0
                }
            },
            "flow": {
                "memcap": 0,
                "tcp": 94734,
                "udp": 2009,
                "icmpv4": 513,
                "icmpv6": 89,
                "spare": 10004,
                "emerg_mode_entered": 0,
                "emerg_mode_over": 0,
                "tcp_reuse": 1562,
                "memuse": int(abs(gauss(10000000, 5000000)))
            },
            "defrag": {
                "ipv4": {
                    "fragments": 0,
                    "reassembled": 0,
                    "timeouts": 0
                },
                "ipv6": {
                    "fragments": 0,
                    "reassembled": 0,
                    "timeouts": 0
                },
                "max_frag_hits": 0
            },
            "tcp": {
                "sessions": 93969,
                "ssn_memcap_drop": 0,
                "pseudo": 0,
                "pseudo_failed": 0,
                "invalid_checksum": 0,
                "no_flow": 0,
                "syn": 100102,
                "synack": 4023,
                "rst": 80696,
                "midstream_pickups": 0,
                "pkt_on_wrong_thread": 0,
                "segment_memcap_drop": 0,
                "stream_depth_reached": 1,
                "reassembly_gap": 0,
                "overlap": 26803,
                "overlap_diff_data": 0,
                "insert_data_normal_fail": 0,
                "insert_data_overlap_fail": 0,
                "insert_list_fail": 0,
                "memuse": int(abs(gauss(10000000, 5000000))),
                "reassembly_memuse": int(abs(gauss(10000000, 5000000)))
            },
            "detect": {
                "engines": [
                    {
                        "id": 0,
                        "last_reload": "2019-08-02T13:05:20.544996+0000",
                        "rules_loaded": 21536,
                        "rules_failed": 11
                    }
                ],
                "alert": 295
            },
            "app_layer": {
                "flow": {
                    "http": 1450,
                    "ftp": 73,
                    "smtp": 6,
                    "tls": 160,
                    "ssh": 47,
                    "imap": 0,
                    "msn": 0,
                    "smb": 65,
                    "dcerpc_tcp": 1,
                    "dns_tcp": 3,
                    "nfs_tcp": 0,
                    "ntp": 11,
                    "ftp-data": 0,
                    "tftp": 0,
                    "ikev2": 0,
                    "krb5_tcp": 0,
                    "dhcp": 24,
                    "failed_tcp": 42,
                    "dcerpc_udp": 0,
                    "dns_udp": 1552,
                    "nfs_udp": 0,
                    "krb5_udp": 0,
                    "failed_udp": 422
                },
                "tx": {
                    "http": 2271,
                    "ftp": 0,
                    "smtp": 6,
                    "tls": 0,
                    "ssh": 0,
                    "imap": 0,
                    "msn": 0,
                    "smb": 237,
                    "dcerpc_tcp": 0,
                    "dns_tcp": 6,
                    "nfs_tcp": 0,
                    "ntp": 25,
                    "ftp-data": 0,
                    "tftp": 0,
                    "ikev2": 0,
                    "krb5_tcp": 0,
                    "dhcp": 135,
                    "dcerpc_udp": 0,
                    "dns_udp": 3445,
                    "nfs_udp": 0,
                    "krb5_udp": 0
                },
                "expectations": 386
            },
            "flow_mgr": {
                "closed_pruned": 53946,
                "new_pruned": 6214,
                "est_pruned": 1047,
                "bypassed_pruned": 0,
                "flows_checked": 486,
                "flows_notimeout": 390,
                "flows_timeout": 96,
                "flows_timeout_inuse": 91,
                "flows_removed": 5,
                "rows_checked": 65536,
                "rows_skipped": 65220,
                "rows_empty": 3,
                "rows_busy": 0,
                "rows_maxlen": 5
            },
            "http": {
                "memuse": int(abs(gauss(10000000, 5000000))),
                "memcap": 0
            },
            "ftp": {
                "memuse": 46159,
                "memcap": 0
            }
        }
    }

    return json.dumps(d)


def rand_alert(rules: list) -> dict:
    rule = rules[abs(int(gauss(len(rules)/2, 60)))]
    timestamp = timestamp_now()
    flow_id = int(random()*10**12)
    pcap_cnt = int(random()*20000)
    event_type = 'alert'
    return {
        "host": choice(HOSTNAMES),
        "alert": {
            "action": "allowed",
            "category": "category: " + str(int(gauss(30, 15))),
            "gid": 1,
            "rev": 0,
            "severity": int(random() * 5),
            "signature": rule['msg'],
            "signature_id": int(rule['sid']),
            "metadata": {
                "updated_at": [
                    "2013_01_29"
                ],
                "created_at": [
                    "2013_01_29"
                ]
            }
        },
        "app_proto": "http",
        "dest_ip": rand_ipv4(),
        "dest_port": int(random() * 64000),
        "event_type": "alert",
        "flow": {
            "bytes_toclient": 436,
            "bytes_toserver": 454,
            "pkts_toclient": 3,
            "pkts_toserver": 4,
            "start": timestamp
        },
        "flow_id": flow_id,
        "http": {
            "hostname": "192.168.229.251",
            "http_content_type": "text/html",
            "http_method": "HEAD",
            "http_user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)",
            "length": 0,
            "protocol": "HTTP/1.1",
            "status": int(random() * 500),
            "url": "/DEASLog04.nsf"
        },
        "pcap_cnt": pcap_cnt,
        "proto": "006",
        # "src_ip": "192.168.229.251",
        "src_ip": rand_ipv4(),
        "src_port": 80,
        "timestamp": timestamp,
        "tx_id": 0,
        "vlan": [
            int(random() * 256)
        ],
        "tls": {
            "subject": "CN=192.168.22.254",
            "issuerdn": "CN=192.168.22.254",
            "serial": "EE:7C:5B:4F",
            "fingerprint": "91:dd:db:96:0e:18:5f:93:7b:3b:12:fb:17:55:25:61:3d:7d:5e:32",
            "version": "TLSv1",
            "notbefore": "2012-03-10T16:10:25",
            "notafter": "2022-03-08T16:10:25",
            "ja3": {},
            "ja3s": {},
            "sni": "sni-test"
        },
        "dns": {
            "type": "query",
            "id": 40722,
            "query": {
                "rrname": "www.dokuwiki.org",
                "rrtype": "AAAA",
            },
            "tx_id": 0
        }
    }


def get_some_event():
    d = {
        "timestamp": timestamp_now(),
        "flow_id": 1678349884219456,
        "event_type": "flow",
        "vlan": [
            120
        ],
        "src_ip": "192.168.202.83",
        "src_port": 34976,
        "dest_ip": "192.168.206.44",
        "dest_port": 1097,
        "proto": "006",
        "flow": {
            "pkts_toserver": 1,
            "pkts_toclient": 1,
            "bytes_toserver": 78,
            "bytes_toclient": 64,
            "start": "2012-03-16T14:05:28.680000+0000",
            "end": "2012-03-16T14:05:28.680000+0000",
            "age": 0,
            "state": "closed",
            "reason": "timeout",
            "alerted": false
        },
        "tcp": {
            "tcp_flags": "16",
            "tcp_flags_ts": "02",
            "tcp_flags_tc": "14",
            "syn": true,
            "rst": true,
            "ack": true,
            "state": "closed"
        }
    }


def scirius_get_rule(sid, token):
    headers = {'Authorization': f'Token {token}'}
    r = requests.get(f'{SCIRIUS_BASE_URL}/rest/rules/rule/{sid}',
                     headers=headers, verify=False)
    #print('SCIRIUS OK?', r.ok)
    #print('SCIRIUS RESPONSE', r.text)
    return r.json()


def get(dict_, keys):
    d = dict_
    for k in keys:
        if k in d:
            d = d[k]
        else:
            return None
    return d


def main(args, name='alerts_gen.py'):
    print(f'[{arrow.now()}] Starting alertsgen', flush=True)
    token = args[0]
    print(f'[{arrow.now()}] Using token {token}', flush=True)

    rules_path = 'rules/scirius.rules'
    rules = []
    with open(rules_path) as f:
        rules = parse_ruleset(f.read())
    print(f'[{arrow.now()}] Read {len(rules)} rules <= %s' % rules_path, flush=True)

    eve_path = 'alerts/eve.json'
    out_file = open(eve_path, "w")

    while True:
        per_min = max(int(abs(gauss(30, 16))), 1)
        print("[%s] Generating at speed %d alerts/min => %s" % (arrow.now(), per_min, eve_path), flush=True)
        sleep_ = 60.0 / per_min

        print(get_status(), file=out_file, flush=True)

        for i in range(0, per_min // 2):
            sleep(sleep_)
            #try:
            alert = rand_alert(rules)
            sid = alert['alert']['signature_id']
            rule = scirius_get_rule(sid, token)
            name = get(rule, ['category', 'name'])
            if name:
                alert['alert']['category'] = name
                print(json.dumps(alert), file=out_file, flush=True)
            #except Exception as e:
            #    print(f'FAILED TO GENERATE ALERT: {e}', flush=True)


if __name__ == '__main__':
    main(sys.argv[1:], sys.argv[0])
