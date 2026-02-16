import sys
import argparse
import logging
import struct
import time
import os
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Ajout de lsat et lsad pour la résolution via LSA
from impacket.dcerpc.v5 import transport, rrp, samr, scmr, lsat, lsad
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1
from impacket.dcerpc.v5.samr import USER_INFORMATION_CLASS

logging.getLogger("impacket").setLevel(logging.CRITICAL)

class ADEnumerator:
    def __init__(self, username, password, domain, dc_ip, custom_base=None, hashes=None):
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_ip = dc_ip
        if custom_base:
            self.base_dn = custom_base
        else:
            self.base_dn = ','.join([f"dc={x}" for x in self.domain.split('.')])
        self.lmhash = ''
        self.nthash = ''
        if hashes:
            self.lmhash, self.nthash = hashes.split(':')
        self.ldap_connection = None

    def connect(self):
        try:
            ldap_url = f"ldap://{self.dc_ip}"
            self.ldap_connection = ldap_impacket.LDAPConnection(ldap_url, self.base_dn, self.dc_ip)
            self.ldap_connection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            return True
        except:
            return False

    def sid_to_ldap_filter(self, sid_str):
        try:
            parts = sid_str.split('-')
            revision = int(parts[1])
            identifier_authority = int(parts[2])
            sub_authorities = [int(x) for x in parts[3:]]
            binary = bytearray()
            binary.append(revision)
            binary.append(len(sub_authorities))
            id_auth_bytes = struct.pack('>Q', identifier_authority)[2:]
            binary.extend(id_auth_bytes)
            for sub in sub_authorities:
                binary.extend(struct.pack('<I', sub))
            escaped_sid = "".join([f"\\{b:02x}" for b in binary])
            return f"(objectSid={escaped_sid})"
        except:
            return None

    def resolve_sid_via_ldap(self, sid_str):
        if not self.ldap_connection and not self.connect(): return None
        try:
            search_filter = self.sid_to_ldap_filter(sid_str)
            if not search_filter: return None
            resp = self.ldap_connection.search(searchBase=self.base_dn, searchFilter=search_filter, attributes=['sAMAccountName'])
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    for attribute in item['attributes']:
                        if str(attribute['type']) == 'sAMAccountName':
                            return f"{self.domain}\\{str(attribute['vals'][0])} (LDAP)"
        except: pass
        return None

    def get_domain_computers(self):
        if not self.ldap_connection and not self.connect(): return []
        computers = []
        try:
            resp = self.ldap_connection.search(searchFilter="(&(objectCategory=computer))", attributes=['dNSHostName'])
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    for attr in item['attributes']:
                        if str(attr['type']) == 'dNSHostName':
                            val = str(attr['vals'][0])
                            if val: computers.append(val)
        except: pass
        return computers

class SessionHunter:
    def __init__(self, username, password, domain, target_ip, hashes=None, ad_enumerator=None):
        self.username = username
        self.password = password
        self.domain = domain
        self.target = target_ip
        self.lmhash = ''
        self.nthash = ''
        self.ad_enumerator = ad_enumerator
        if hashes:
            self.lmhash, self.nthash = hashes.split(':')
        self.is_admin = False

    def _get_dce(self, pipe_name, uuid):
        binding = f'ncacn_np:{self.target}[\\pipe\\{pipe_name}]'
        rpctransport = transport.DCERPCTransportFactory(binding)
        rpctransport.set_connect_timeout(2)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(uuid)
        return dce

    def check_admin(self):
        try:
            dce = self._get_dce('svcctl', scmr.MSRPC_UUID_SCMR)
            ans = scmr.hROpenSCManagerW(dce, lpMachineName=self.target, dwDesiredAccess=0x0002)
            scmr.hRCloseServiceHandle(dce, ans['lpScHandle'])
            self.is_admin = True
            return True
        except:
            self.is_admin = False
            return False

    def resolve_sid_via_samr(self, sid_str):
        try:
            sid_parts = sid_str.split('-')
            rid = int(sid_parts[-1])
            domain_sid_str = '-'.join(sid_parts[:-1])
            dce = self._get_dce('samr', samr.MSRPC_UUID_SAMR)
            ans = samr.hSamrConnect(dce)
            serverHandle = ans['ServerHandle']
            try:
                ans = samr.hSamrOpenDomain(dce, serverHandle, domainId=domain_sid_str)
                domainHandle = ans['DomainHandle']
            except: return None
            ans = samr.hSamrOpenUser(dce, domainHandle, userId=rid)
            userHandle = ans['UserHandle']
            ans = samr.hSamrQueryInformationUser(dce, userHandle, USER_INFORMATION_CLASS.UserGeneralInformation)
            user_name = str(ans['Buffer']['General']['UserName'])
            dce.disconnect()
            return f"{user_name} (SAMR)"
        except: return None

    def resolve_sid_via_lsa(self, sid_str):
        """ Nouvelle méthode : Résolution via LSA (lsarpc) """
        try:
            dce = self._get_dce('lsarpc', lsat.MSRPC_UUID_LSAT)
            ans = lsad.hLsarOpenPolicy2(dce)
            policyHandle = ans['PolicyHandle']
            
            ans = lsat.hLsarLookupSids(dce, policyHandle, [sid_str])
            name = str(ans['TranslatedNames']['Names'][0]['Name'])
            
            lsad.hLsarClose(dce, policyHandle)
            dce.disconnect()
            return f"{name} (LSA)"
        except:
            return None

    def resolve_sid_name(self, sid_str):
        # 1. Tentative LDAP (C'est le plus propre pour l'AD)
        if self.ad_enumerator:
            name = self.ad_enumerator.resolve_sid_via_ldap(sid_str)
            if name: return name
            
        # 2. Tentative SAMR (Comptes locaux)
        name = self.resolve_sid_via_samr(sid_str)
        if name: return name
        
        # 3. Tentative LSA (Fallback testé et validé)
        name = self.resolve_sid_via_lsa(sid_str)
        if name: return name
        
        return f"{sid_str} (Unknown)"

    def hunt(self):
        self.check_admin()
        sessions = []
        try:
            dce = self._get_dce('winreg', rrp.MSRPC_UUID_RRP)
            ans = rrp.hOpenUsers(dce)
            hRootKey = ans['phKey']
            index = 0
            while True:
                try:
                    enum_ans = rrp.hBaseRegEnumKey(dce, hRootKey, index)
                    sid = enum_ans['lpNameOut'].strip('\x00')
                    if sid.startswith('S-1-5-21-') and not sid.endswith('_Classes'):
                        username = self.resolve_sid_name(sid)
                        sessions.append(username)
                    index += 1
                except rrp.DCERPCSessionError: break
                except Exception: break
            rrp.hBaseRegCloseKey(dce, hRootKey)
            dce.disconnect()
            return sessions
        except Exception:
            return None

# --- [Le reste du code reste identique (DNS fix, scan_host, main)] ---

def simple_dns_query(hostname, dns_server):
    try:
        transaction_id = b'\xaa\xaa'
        flags = b'\x01\x00'
        questions = b'\x00\x01'
        answer_rrs = b'\x00\x00'
        authority_rrs = b'\x00\x00'
        additional_rrs = b'\x00\x00'
        query = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs
        for part in hostname.split('.'):
            query += bytes([len(part)]) + part.encode()
        query += b'\x00'
        query += b'\x00\x01' + b'\x00\x01'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(query, (dns_server, 53))
        data, _ = sock.recvfrom(512)
        sock.close()
        if len(data) > 12:
            ip_bytes = data[-4:]
            return socket.inet_ntoa(ip_bytes)
    except: return None
    return None

def resolve_target(target, dc_ip):
    try:
        socket.inet_aton(target)
        return target
    except socket.error: pass
    try:
        return socket.gethostbyname(target)
    except socket.error: pass
    if dc_ip:
        ip = simple_dns_query(target, dc_ip)
        if ip: return ip
    return None

def scan_host(target_name, args, ad_enum):
    target_ip = resolve_target(target_name, args.dc_ip)
    if not target_ip:
         return [(target_name, "\033[90m-\033[0m", "\033[90mDNS Failed\033[0m")]
    hunter = SessionHunter(args.username, args.password, args.domain, target_ip, args.hashes, ad_enum)
    sessions = hunter.hunt()
    results = []
    admin_str = "\033[1;32mOUI\033[0m" if hunter.is_admin else "\033[1;31mNON\033[0m"
    if sessions is None:
        results.append((target_name, "\033[90m-\033[0m", "\033[90mUnreachable\033[0m"))
    elif not sessions:
        pass
    else:
        for s in sessions:
            results.append((target_name, admin_str, f"\033[1;36m{s}\033[0m"))
    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs='?')
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-H", "--hashes")
    parser.add_argument("-dc-ip")
    parser.add_argument("-ldap-base")
    parser.add_argument("-t", "--threads", type=int, default=10)
    args = parser.parse_args()

    if not args.password and not args.hashes:
        from getpass import getpass
        args.password = getpass("Password: ")

    ad_enum = None
    if args.dc_ip:
        ad_enum = ADEnumerator(args.username, args.password, args.domain, args.dc_ip, args.ldap_base, args.hashes)

    targets = []
    if args.dc_ip and not args.target:
        print("[*] Récupération des machines via LDAP...")
        targets = ad_enum.get_domain_computers()
    elif args.target:
        targets = [args.target]

    if not targets:
        print("[-] Aucune cible.")
        sys.exit(1)

    try:
        while True:
            all_rows = []
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = [executor.submit(scan_host, t, args, ad_enum) for t in targets]
                for future in futures:
                    res = future.result()
                    if res: all_rows.extend(res)

            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"--- SESSION HUNTER --- {datetime.now().strftime('%H:%M:%S')} (Ctrl+C to stop)")
            print(f"{'HOST':<30} | {'ADMIN':<10} | {'SESSION(S)':<50}")
            print("-" * 95)

            if not all_rows:
                print("No active sessions found.")
            else:
                for row in all_rows:
                    host, admin, user = row
                    print(f"{host:<30} | {admin:<10} | {user:<50}")

            time.sleep(1800)
    except KeyboardInterrupt:
        print("\n[!] Arrêt demandé.")
        sys.exit(0)

if __name__ == "__main__":
    main()
