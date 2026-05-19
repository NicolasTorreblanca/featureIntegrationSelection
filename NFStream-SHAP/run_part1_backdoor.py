"""
run_part1_backdoor.py -- helper to generate DATASETS/normal_backdoor_base.csv
Uses the short-path workaround required on Windows when the user profile path
contains accented characters (NicolásTorreblanca -> NICOLS~1).
Must be run as __main__ so that nfstream's multiprocessing workers can bootstrap.
"""
import ctypes
import os
import sys
from pathlib import Path

if __name__ == '__main__':
    import importlib.util
    import pandas as pd

    _here = Path(__file__).resolve().parent

    # Load Part1 module
    spec = importlib.util.spec_from_file_location(
        'p1', str(_here / 'TonIoT-Part1-integrator-PCAP.py')
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # PCAP path (long) -> short 8.3 path to avoid NFStream subprocess encoding issue
    pcap_long = str((_here.parent.parent / 'PCAP' / 'Attacks' / 'BackDoor' / 'normal_backdoor.pcap').resolve())
    buf = ctypes.create_unicode_buffer(260)
    ctypes.windll.kernel32.GetShortPathNameW(pcap_long, buf, 260)
    pcap_short = buf.value if buf.value else pcap_long
    print(f'PCAP path (short): {pcap_short}')

    flows = mod.process_pcap(pcap_short, 'backdoor')
    df = pd.DataFrame(flows)
    print(f'Flows extracted: {len(df)}')
    print(f'conn_state distribution: {df["conn_state"].value_counts().to_dict()}')

    out_dir = _here / 'DATASETS'
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / 'normal_backdoor_base.csv'
    df.to_csv(out_path, index=False)
    print(f'Saved: {out_path}')
