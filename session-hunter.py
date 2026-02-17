import sys
import argparse
import logging
import struct
import time
import os
import socket
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from impacket.dcerpc.v5 import transport, rrp, samr, scmr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1

logging.getLogger("impacket").setLevel(logging.CRITICAL)

CACHE_FILE = "session_cache.json"

class ADEnumerator:
    def __init__(self, username, password, domain, dc_ip, custom_base=None, hashes=None):
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_ip = dc_ip
        if custom_base: self.base_dn = custom_base
        else: self.base_dn = ','.join([f"dc={x}" for x in self.domain.split('.')])
        self.lmhash = ''
        self.nthash = ''
        if hashes: self.lmhash, self.nthash = hashes.split(':')
        self.ldap_connection = None

    def connect(self):
        if self.ldap_connection: return True
        try:
            ldap_url = f"ldap://{self.dc_ip}"
            self.ldap_connection = ldap_impacket.LDAPConnection(ldap_url, self.base_dn, self.dc_ip)
            self.ldap_connection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            return True
        except: return False

    def binary_sid_to_string(self, sid_bytes):
        try:
            revision = sid_bytes[0]
            identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder='big')
            sub_authorities = []
            for i in range((len(sid_bytes) - 8) // 4):
                start = 8 + (i * 4)
                val = int.from_bytes(sid_bytes[start:start+4], byteorder='little')
                sub_authorities.append(str(val))
            return f"S-{revision}-{identifier_authority}-{'-'.join(sub_authorities)}"
        except: return None

    def prefetch_all_users(self):
        cache_update = {}
        if not self.connect(): return {}
        print("[*] LDAP: Prefetching all users...")
        try:
            resp = self.ldap_connection.search(searchBase=self.base_dn, searchFilter="(&(objectClass=user)(objectCategory=person))", attributes=['sAMAccountName', 'objectSid'])
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    username = None; sid_str = None
                    for attr in item['attributes']:
                        if str(attr['type']) == 'sAMAccountName': username = str(attr['vals'][0])
                        elif str(attr['type']) == 'objectSid': sid_str = self.binary_sid_to_string(attr['vals'][0])
                    if username and sid_str: cache_update[sid_str] = f"{self.domain}\\{username}"
            return cache_update
        except: return {}

    def get_domain_computers(self):
        if not self.connect(): return []
        computers = []
        print("[*] LDAP: Downloading computer list...")
        try:
            resp = self.ldap_connection.search(searchFilter="(&(objectCategory=computer))", attributes=['dNSHostName'])
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    for attr in item['attributes']:
                        if str(attr['type']) == 'dNSHostName': val = str(attr['vals'][0]); computers.append(val)
        except: pass
        return computers

def simple_dns_query(hostname, dns_server):
    try:
        query = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        for part in hostname.split('.'): query += bytes([len(part)]) + part.encode()
        query += b'\x00\x00\x01\x00\x01'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(query, (dns_server, 53))
        data, _ = sock.recvfrom(512); sock.close()
        if len(data) > 12: return socket.inet_ntoa(data[-4:])
    except: return None
    return None

def resolve_target(target, dc_ip):
    try: socket.inet_aton(target); return target
    except: pass
    if dc_ip: return simple_dns_query(target, dc_ip)
    try: return socket.gethostbyname(target)
    except: return None


class PersistentSessionHunter:
    def __init__(self, username, password, domain, target_ip, target_name, cache_sids, hashes=None):
        self.username = username
        self.password = password
        self.domain = domain
        self.target = target_ip
        self.target_name = target_name
        self.cache_sids = cache_sids
        self.lmhash = ''
        self.nthash = ''
        if hashes: self.lmhash, self.nthash = hashes.split(':')

        self.dce = None
        self.connected = False
        self.is_admin = False 

    def check_admin_status(self):
        """ Vérifie UNE FOIS si on est admin via Service Manager """
        try:
            binding = f'ncacn_np:{self.target}[\\pipe\\svcctl]'
            rpctransport = transport.DCERPCTransportFactory(binding)
            rpctransport.set_connect_timeout(2)
            if hasattr(rpctransport, 'set_credentials'):
                rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)

            dce_admin = rpctransport.get_dce_rpc()
            dce_admin.connect()
            dce_admin.bind(scmr.MSRPC_UUID_SCMR)

            ans = scmr.hROpenSCManagerW(dce_admin, lpMachineName=self.target, dwDesiredAccess=0x0002)
            scmr.hRCloseServiceHandle(dce_admin, ans['lpScHandle'])

            dce_admin.disconnect()
            return True
        except:
            return False

    def connect_rpc(self):
        """Établit la connexion SMB/RPC pour WINREG."""
        try:
            self.is_admin = self.check_admin_status()
            binding = f'ncacn_np:{self.target}[\\pipe\\winreg]'
            rpctransport = transport.DCERPCTransportFactory(binding)
            rpctransport.set_connect_timeout(2)
            if hasattr(rpctransport, 'set_credentials'):
                rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)

            self.dce = rpctransport.get_dce_rpc()
            self.dce.connect()
            self.dce.bind(rrp.MSRPC_UUID_RRP)
            self.connected = True
            return True
        except:
            self.connected = False
            return False

    def hunt(self):
        if not self.connected:
            if not self.connect_rpc():
                return None

        sessions = []
        try:
            ans = rrp.hOpenUsers(self.dce)
            hRootKey = ans['phKey']

            index = 0
            while True:
                try:
                    enum_ans = rrp.hBaseRegEnumKey(self.dce, hRootKey, index)
                    sid = enum_ans['lpNameOut'].strip('\x00')
                    if sid.startswith('S-1-5-21-') and not sid.endswith('_Classes'):
                        if sid in self.cache_sids:
                            sessions.append(self.cache_sids[sid])
                        else:
                            sessions.append(f"{sid} (Unknown)")
                    index += 1
                except: break

            rrp.hBaseRegCloseKey(self.dce, hRootKey)
            return sessions

        except (DCERPCException, Exception) as e:
            self.connected = False
            return None

# --- Main Logic ---

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f: return json.load(f)
        except: pass
    return {'sids': {}, 'targets': []}

def save_cache(full_cache):
    try:
        with open(CACHE_FILE, 'w') as f: json.dump(full_cache, f, indent=4)
    except: pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs='?')
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-H", "--hashes")
    parser.add_argument("-dc-ip")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("-r", "--refresh", action="store_true")
    args = parser.parse_args()

    if not args.password and not args.hashes:
        from getpass import getpass; args.password = getpass("Password: ")

    FULL_CACHE = load_cache()
    if 'sids' not in FULL_CACHE: FULL_CACHE = {'sids': FULL_CACHE, 'targets': []}
    CACHE_SIDS = FULL_CACHE['sids']
    CACHE_TARGETS = FULL_CACHE['targets']

    ad_enum = None
    if args.dc_ip and (not CACHE_SIDS or args.refresh):
        ad_enum = ADEnumerator(args.username, args.password, args.domain, args.dc_ip, hashes=args.hashes)
        fetched = ad_enum.prefetch_all_users()
        if fetched: CACHE_SIDS.update(fetched); save_cache(FULL_CACHE)

    target_list = []
    if args.target: target_list = [args.target]
    elif args.dc_ip:
        if not CACHE_TARGETS or args.refresh:
            if not ad_enum: ad_enum = ADEnumerator(args.username, args.password, args.domain, args.dc_ip, hashes=args.hashes)
            target_list = ad_enum.get_domain_computers()
            if target_list: FULL_CACHE['targets'] = target_list; save_cache(FULL_CACHE)
        else: target_list = CACHE_TARGETS

    if not target_list: print("[-] Aucune cible."); sys.exit(1)

    print(f"[*] Initialisation des connexions persistantes vers {len(target_list)} cibles...")
    hunters = []

    for host in target_list:
        ip = resolve_target(host, args.dc_ip)
        if ip:
            hunter = PersistentSessionHunter(args.username, args.password, args.domain, ip, host, CACHE_SIDS, args.hashes)
            hunters.append(hunter)

    try:
        while True:
            all_rows = []

            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = {executor.submit(h.hunt): h for h in hunters}

                for future in futures:
                    h = futures[future]
                    sessions = future.result()

                    if h.is_admin:
                        admin_str = "\033[1;32mYEP\033[0m" #
                    else:
                        admin_str = "\033[1;31mNOP\033[0m" 

                    if sessions:
                        for s in sessions:
                            all_rows.append((h.target_name, admin_str, f"\033[1;36m{s}\033[0m"))
                    elif sessions is None:
                        pass

            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"--- SESSION HUNTER --- {datetime.now().strftime('%H:%M:%S')} (Ctrl+C to stop)")
            print(f"Cache: {len(CACHE_SIDS)} Users | Monitors: {len(hunters)} Hosts")
            print(f"{'HOST':<30} | {'ADMIN':<10} | {'SESSION(S)':<50}")
            print("-" * 95)

            if not all_rows: print("No active sessions found.")
            else:
                for row in all_rows:
                    host, admin, user = row
                    print(f"{host:<30} | {admin:<10} | {user:<50}")

            time.sleep(5)

    except KeyboardInterrupt:
        print("\n[!] Closing connections...")
        sys.exit(0)

if __name__ == "__main__":
    main()
