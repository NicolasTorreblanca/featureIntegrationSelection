"""
Smoke test for TonIoT-Part1-integrator-PCAP.py
Must be run as __main__ — the if-guard prevents nfstream subprocess re-entry.
"""
import os
import sys

if __name__ == '__main__':
    import importlib.util
    import pandas as pd

    # Load the Part1 module
    _here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        'p1', os.path.join(_here, 'TonIoT-Part1-integrator-PCAP.py')
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Process exactly one small PCAP -- BackDoor has only one file
    # Use short (8.3) path to avoid nfstream subprocess encoding issue with
    # accented characters in the username path (NicolásTorreblanca -> NICOLS~1)
    pcap_long = os.path.abspath(os.path.join(_here, '../../PCAP/Attacks/BackDoor/normal_backdoor.pcap'))
    assert os.path.exists(pcap_long), f'PCAP not found: {pcap_long}'
    # Convert to short path so nfstream worker processes receive a clean ASCII path
    import ctypes
    buf = ctypes.create_unicode_buffer(260)
    ctypes.windll.kernel32.GetShortPathNameW(pcap_long, buf, 260)
    pcap = buf.value if buf.value else pcap_long
    print(f'Using path: {pcap}')

    flows = mod.process_pcap(pcap, 'backdoor')
    df = pd.DataFrame(flows)

    expected = {
        'src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto', 'stime',
        'dns_query', 'dns_rejected', 'dns_RD', 'conn_state', 'service',
        'http_status_code', 'src_ip_bytes', 'dst_ip_bytes',
        'src_pkts', 'dst_pkts', 'label'
    }
    missing = expected - set(df.columns)
    assert not missing, f'Missing columns: {missing}'

    assert df['proto'].dropna().isin(['tcp', 'udp', 'Other', 'None']).all(), \
        f'Bad proto values: {df["proto"].unique()}'
    assert df['dns_rejected'].dropna().isin(['T', 'F', '-']).all(), \
        f'Bad dns_rejected values: {df["dns_rejected"].unique()}'
    assert df['conn_state'].dropna().isin(['S0', 'SF', 'REJ', 'OTH', 'Other', 'None']).all(), \
        f'Bad conn_state values: {df["conn_state"].unique()}'
    assert df['service'].dropna().isin(['-', 'dns', 'http', 'Other', 'None']).all(), \
        f'Bad service values: {df["service"].unique()}'
    assert (df['label'] == 'backdoor').all()

    print(f'Part1 OK -- {len(df)} flows extracted from BackDoor PCAP')
    print(f'  proto distribution: {df["proto"].value_counts().to_dict()}')
    print(f'  conn_state distribution: {df["conn_state"].value_counts().to_dict()}')
    print(f'  service distribution: {df["service"].value_counts().to_dict()}')
