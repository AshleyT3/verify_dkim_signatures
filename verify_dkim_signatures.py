#!/usr/bin/env python3
"""
Verify DKIM signatures in extracted email files.

Usage: python verify_dkim_signatures.py <directory> [--verbose] [--output report.txt]

Requirements:
    pip install dkimpy dnspython
"""

import sys
import email
import argparse
import time
import dns.resolver
from pathlib import Path
import re
import dkim
import dkim.dnsplug
from dkim.canonicalization import Relaxed, Simple
import hashlib
import base64
import quopri
import json
from datetime import datetime, timezone

try:
    DKIM_AVAILABLE = True
except ImportError:
    DKIM_AVAILABLE = False

class OurDKIM(dkim.DKIM):
    def __init__(self, message=None, logger=None, signature_algorithm=b'rsa-sha256', minkey=1024, linesep=b'\r\n', debug_content=False, timeout=5, tlsrpt=False, ignore_exp=False):
        self.ignore_exp = ignore_exp
        super().__init__(message, logger, signature_algorithm, minkey, linesep, debug_content, timeout, tlsrpt)

    def validate_signature_fields(self, sig, mandatory_fields=[b'v', b'a', b'b', b'bh', b'd', b'h', b's'], arc=False):
        """Validate DKIM or ARC Signature fields.
        Basic checks for presence and correct formatting of mandatory fields.
        Raises a ValidationError if checks fail, otherwise returns None.
        @param sig: A dict mapping field keys to values.
        @param mandatory_fields: A list of non-optional fields
        @param arc: flag to differentiate between dkim & arc
        """
        if arc:
            hashes = dkim.ARC_HASH_ALGORITHMS
        else:
            hashes = dkim.HASH_ALGORITHMS
        for field in mandatory_fields:
            if field not in sig:
                raise dkim.ValidationError("missing %s=" % field)

        if b'a' in sig and not sig[b'a'] in hashes:
            raise dkim.ValidationError("unknown signature algorithm: %s" % sig[b'a'])

        if b'b' in sig:
            if re.match(br"[\s0-9A-Za-z+/]+[\s=]*$", sig[b'b']) is None:
                raise dkim.ValidationError("b= value is not valid base64 (%s)" % sig[b'b'])
            if len(re.sub(br"\s+", b"", sig[b'b'])) % 4 != 0:
                raise dkim.ValidationError("b= value is not valid base64 (%s)" % sig[b'b'])

        if b'bh' in sig:
            if re.match(br"[\s0-9A-Za-z+/]+[\s=]*$", sig[b'b']) is None:
                raise dkim.ValidationError("bh= value is not valid base64 (%s)" % sig[b'bh'])
            if len(re.sub(br"\s+", b"", sig[b'bh'])) % 4 != 0:
                raise dkim.ValidationError("bh= value is not valid base64 (%s)" % sig[b'bh'])

        if b'cv' in sig and sig[b'cv'] not in (dkim.CV_Pass, dkim.CV_Fail, dkim.CV_None):
            raise dkim.ValidationError("cv= value is not valid (%s)" % sig[b'cv'])

        # Limit domain validation to ASCII domains because too hard
        try:
            str(sig[b'd'], 'ascii')
            # No specials, which is close enough
            if re.findall(rb"[\(\)<>\[\]:;@\\,]", sig[b'd']):
                raise dkim.ValidationError("d= value is not valid (%s)" % sig[b'd'])
        except UnicodeDecodeError as e:
            # Not an ASCII domain
            pass

        # Nasty hack to support both str and bytes... check for both the
        # character and integer values.
        if not arc and b'i' in sig and (
            not sig[b'i'].lower().endswith(sig[b'd'].lower()) or
            sig[b'i'][-len(sig[b'd'])-1] not in ('@', '.', 64, 46)):
            raise dkim.ValidationError(
                "i= domain is not a subdomain of d= (i=%s d=%s)" %
                (sig[b'i'], sig[b'd']))
        if b'l' in sig and re.match(br"\d{,76}$", sig[b'l']) is None:
            raise dkim.ValidationError(
                "l= value is not a decimal integer (%s)" % sig[b'l'])
        if b'q' in sig and sig[b'q'] != b"dns/txt":
            raise dkim.ValidationError("q= value is not dns/txt (%s)" % sig[b'q'])

        if b't' in sig:
            if re.match(br"\d+$", sig[b't']) is None:
                raise dkim.ValidationError(
                    "t= value is not a decimal integer (%s)" % sig[b't'])
            now = int(time.time())
            slop = 36000 # 10H leeway for mailers with inaccurate clocks
            t_sign = int(sig[b't'])
            if t_sign > now + slop:
                raise dkim.ValidationError("t= value is in the future (%s)" % sig[b't'])
        else:
            t_sign = None

        if b'v' in sig and sig[b'v'] != b"1":
            raise dkim.ValidationError("v= value is not 1 (%s)" % sig[b'v'])

        if not self.ignore_exp and b'x' in sig:
            if re.match(br"\d+$", sig[b'x']) is None:
                raise dkim.ValidationError(
                "x= value is not a decimal integer (%s)" % sig[b'x'])
            x_sign = int(sig[b'x'])
            now = int(time.time())
            slop = 36000 # 10H leeway for mailers with inaccurate clocks
            if x_sign < now - slop:
                raise dkim.ValidationError(
                    "x= value is past (%s)" % sig[b'x'])
            if t_sign and x_sign < t_sign:
                raise dkim.ValidationError(
                    "x= value is less than t= value (x=%s t=%s)" %
                    (sig[b'x'], sig[b't']))

    def verify_headerprep(self, idx=0):
        """Non-DNS verify parts to minimize asyncio code duplication."""

        sigheaders = [(x,y) for x,y in self.headers if x.lower() == b"dkim-signature"]
        if len(sigheaders) <= idx:
            return False

        # By default, we validate the first DKIM-Signature line found.
        try:
            sig = dkim.parse_tag_value(sigheaders[idx][1])
            self.signature_fields = sig
        except dkim.InvalidTagValueList as e:
            raise dkim.MessageFormatError(e)

        self.logger.debug("sig: %r" % sig)

        self.validate_signature_fields(sig)
        self.domain = sig[b'd']
        self.selector = sig[b's']

        include_headers = [x.lower() for x in re.split(br"\s*:\s*", sig[b'h'])]
        self.include_headers = tuple(include_headers)
        return sig, include_headers, sigheaders

    #: Verify a DKIM signature.
    #: @type idx: int
    #: @param idx: which signature to verify.  The first (topmost) signature is 0.
    #: @type dnsfunc: callable
    #: @param dnsfunc: an option function to lookup TXT resource records
    #: for a DNS domain.  The default uses dnspython or pydns.
    #: @return: True if signature verifies or False otherwise
    #: @raise DKIMException: when the message, signature, or key are badly formed
    def verify(self,idx=0,dnsfunc=dkim.dnsplug.get_txt):
        prep = self.verify_headerprep(idx)
        if prep:
            sig, include_headers, sigheaders = prep
            return self.verify_sig(sig, include_headers, sigheaders[idx], dnsfunc)
        return False # No signature


def our_dkim_verify(message, logger=None, dnsfunc=dkim.dnsplug.get_txt, minkey=1024,
        timeout=5, tlsrpt=False, ignore_exp=False):
    """Verify the first (topmost) DKIM signature on an RFC822 formatted message.
    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param logger: a logger to which debug info will be written (default None)
    @param timeout: number of seconds for DNS lookup timeout (default = 5)
    @param tlsrpt: message is an RFC 8460 TLS report (default False)
     False: Not a tlsrpt, True: Is a tlsrpt, 'strict': tlsrpt, invalid if
     service type is missing. For signing, if True, length is never used.
    @return: True if signature verifies or False otherwise
    """
    # type: (bytes, any, function, int) -> bool
    d = OurDKIM(message,logger=logger,minkey=minkey,timeout=timeout,tlsrpt=tlsrpt,ignore_exp=ignore_exp)
    try:
        return d.verify(dnsfunc=dnsfunc)
    except dkim.DKIMException as x:
        if logger is not None:
            logger.error("%s" % x)
        return False


class DKIMVerifier:
    def __init__(self, verbose=False, key_database_file='./key-database.json',
                 attempt_fix=False, replace_original=False,
                 offline_only=False, overwrite_keys=False):
        self.verbose = verbose
        self.key_database_file = key_database_file
        self.attempt_fix = attempt_fix
        self.replace_original = replace_original
        self.offline_only = offline_only
        self.overwrite_keys = overwrite_keys

        # Key caching
        self.key_cache = {}  # Runtime cache: domain:selector -> key_data
        self.key_database = {}  # Persistent database loaded from JSON

        # Per-file lookup outcomes, cleared at the top of verify_email_file.
        # Maps (domain, selector) -> outcome string. Used to attribute offline
        # failures (no-domain / no-key / key-matched-verify-failed).
        self._lookup_outcomes = {}

        self.stats = {
            'total_files': 0,
            'emails_with_dkim': 0,
            'valid_dkim': 0,
            'invalid_dkim': 0,
            'no_dkim': 0,
            'verification_errors': 0,
            'dns_errors': 0,
            'multiple_signatures': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'keys_loaded': 0,
            'keys_saved': 0,
            'keys_overwritten': 0,
            'offline_no_domain': 0,
            'offline_no_key': 0,
            'offline_key_matched_verify_failed': 0,
            'arc_pass': 0,
            'arc_partial': 0,
            'arc_fail': 0,
            'arc_none': 0,
            'arc_error': 0,
            'arc_seals_valid_ams_invalid': 0,
            'msoft_fix_succeeded_phase1': 0,
            'msoft_fix_succeeded_phase2': 0,
            'msoft_fix_failed': 0,
            'msoft_fix_skipped_no_msoft': 0,
            'msoft_fix_skipped_no_meta': 0,
        }
        self.results = []
        
        # DNS resolver with timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 10
        self.resolver.lifetime = 30
        
        # Load existing key database. The file is always active (default path
        # ./key-database.json if user didn't override); load_key_database
        # handles the not-yet-exists case by leaving self.key_database empty.
        self.load_key_database()
    
    def log(self, message):
        if self.verbose:
            print(message)
    
    def load_key_database(self):
        """Load existing key database from JSON file."""
        try:
            if Path(self.key_database_file).exists():
                with open(self.key_database_file, 'r') as f:
                    self.key_database = json.load(f)
                    self.stats['keys_loaded'] = len(self.key_database)
                    self.log(f"Loaded {len(self.key_database)} keys from {self.key_database_file}")
            else:
                self.log(f"Key database file {self.key_database_file} not found, starting fresh")
        except Exception as e:
            self.log(f"Error loading key database: {e}")
            self.key_database = {}
    
    def save_key_database(self):
        """Save key database to JSON file.

        Before writing, rotates any existing file to <path>.bak (overwriting
        any prior .bak). This preserves the immediately-prior state so the
        user can revert or diff if a save introduces something unexpected.
        """
        try:
            db_path = Path(self.key_database_file)
            if db_path.exists():
                bak_path = db_path.with_suffix(db_path.suffix + '.bak')
                db_path.replace(bak_path)
            with open(self.key_database_file, 'w') as f:
                json.dump(self.key_database, f, indent=2, sort_keys=True)
                self.log(f"Saved {len(self.key_database)} keys to {self.key_database_file}")
        except Exception as e:
            self.log(f"Error saving key database: {e}")
    
    def parse_dkim_key_data(self, key_data):
        """Parse DKIM key data into structured format."""
        if not key_data:
            return {}
            
        try:
            # Parse key=value pairs from DKIM key record
            parsed = {}
            pairs = re.findall(r'(\w+)=([^;]+)', key_data)
            for key, value in pairs:
                parsed[key.strip()] = value.strip().strip('"')
            return parsed
        except Exception as e:
            self.log(f"Error parsing DKIM key data: {e}")
            return {}
    
    def add_key_to_database(self, domain, selector, dns_query, key_data, filename, status="success", role="dkim"):
        """Add or update a key in the database.

        Key data is precious: once a non-blank ``key_data`` is stored for a
        ``(domain, selector)``, it is never overwritten or blanked except
        when ``self.overwrite_keys`` is explicitly enabled and the incoming
        ``key_data`` is non-blank. This protects against losing a known-good
        key that may no longer be retrievable.

        A blank/missing entry can always be filled by an incoming non-blank
        key (this is not an overwrite, it's filling an empty slot).

        Metadata fields (``used_by_files``, ``roles``) are always updated.

        @param role: one of "dkim" or "arc" — recorded in the entry's roles list
            so the same key can be marked as serving both contexts if observed.
        """
        cache_key = f"{domain}:{selector}"
        existing = self.key_database.get(cache_key)
        existing_has_real_key = bool(existing and existing.get('key_data'))
        incoming_has_key = bool(key_data)

        def _write_entry_fields(target, overwriting=False):
            target['domain'] = domain
            target['selector'] = selector
            target['dns_query'] = dns_query
            target['key_data'] = key_data
            target['parsed_key'] = self.parse_dkim_key_data(key_data) if key_data else {}
            target['retrieved'] = datetime.now(timezone.utc).isoformat()
            target['status'] = status
            if overwriting:
                self.stats['keys_overwritten'] += 1
            elif incoming_has_key:
                self.stats['keys_saved'] += 1

        if existing is None:
            # No entry yet — create one regardless of whether key_data is blank.
            # A blank entry records that we tried this (domain, selector) and
            # got nothing back; it can be filled by a later successful fetch.
            self.key_database[cache_key] = {
                "domain": domain,
                "selector": selector,
                "dns_query": dns_query,
                "key_data": key_data,
                "parsed_key": self.parse_dkim_key_data(key_data) if key_data else {},
                "retrieved": datetime.now(timezone.utc).isoformat(),
                "used_by_files": [],
                "roles": [],
                "status": status
            }
            if incoming_has_key:
                self.stats['keys_saved'] += 1
        elif not existing_has_real_key and incoming_has_key:
            # Existing slot is blank/placeholder; filling it is allowed.
            _write_entry_fields(existing, overwriting=False)
            existing['used_by_files'] = existing.get('used_by_files', [])
            existing['roles'] = existing.get('roles', [])
        elif existing_has_real_key and incoming_has_key and self.overwrite_keys:
            # Explicit user opt-in to replace a known-good key with a fresh
            # one. This is the only path that overwrites real key data.
            _write_entry_fields(existing, overwriting=True)
        # else: existing has real key and either (a) incoming is blank or
        # (b) --overwrite-keys not set — leave key_data alone.

        # Metadata fields (always allowed)
        entry = self.key_database[cache_key]
        if "roles" not in entry:
            entry["roles"] = ["dkim"]
        if role and role not in entry["roles"]:
            entry["roles"].append(role)
        if filename and filename not in entry["used_by_files"]:
            entry["used_by_files"].append(filename)
    
    def create_cached_dns_function(self, current_filename=None, role="dkim"):
        """Create DNS function that checks the key database first.

        Behavior depends on the verifier's mode flags:

        - Default (online): use cached key if present and non-blank;
          otherwise live DNS lookup, store result. Existing non-blank keys
          are never overwritten by failed/empty fetches.
        - ``--overwrite-keys``: ignore the cache for retrieval, do a fresh
          DNS lookup, overwrite the cached entry with the new result. Only
          path that overwrites real key data.
        - ``--offline-only``: never call DNS. Use cached key if present;
          on miss, return b'' and record the reason for later attribution
          (no candidate for domain, or no key for this selector).

        @param role: "dkim" or "arc" — tagged onto any key entry that this
            lookup touches, so the database records which contexts each key
            has actually been used in.
        """
        def cached_dns_lookup(domain_bytes, timeout=5):
            # Convert bytes to string if necessary
            if isinstance(domain_bytes, bytes):
                domain_str = domain_bytes.decode('utf-8')
            else:
                domain_str = domain_bytes

            # Extract domain and selector from DNS query like "selector._domainkey.domain.com"
            if '._domainkey.' in domain_str:
                selector = domain_str.split('._domainkey.')[0]
                domain = domain_str.split('._domainkey.')[1]
            else:
                # Fallback parsing
                parts = domain_str.split('.')
                if len(parts) >= 3:
                    selector = parts[0]
                    domain = '.'.join(parts[2:])
                else:
                    selector = 'unknown'
                    domain = domain_str

            cache_key = f"{domain}:{selector}"
            # _lookup_outcomes is consumed by verify_email_file using the
            # DKIM-Signature d=/s= values, which omit the trailing dot that
            # the DNS query form carries. Normalize on the storage side so
            # the consumer can use the d= value directly.
            outcome_key = (domain.rstrip('.'), selector)
            entry = self.key_database.get(cache_key)
            has_real_cached_key = bool(entry and entry.get('key_data'))

            # Path 1: usable cached key + not in overwrite mode → return cache,
            # do not touch the network. (Also applies in --offline-only.)
            if has_real_cached_key and not self.overwrite_keys:
                self.stats['cache_hits'] += 1
                self._lookup_outcomes[outcome_key] = 'hit'

                # Update used_by_files and roles for this cached entry
                if current_filename and current_filename not in entry['used_by_files']:
                    entry['used_by_files'].append(current_filename)
                if "roles" not in entry:
                    entry["roles"] = ["dkim"]
                if role and role not in entry["roles"]:
                    entry["roles"].append(role)

                key_data = entry['key_data']
                return key_data.encode('utf-8') if isinstance(key_data, str) else key_data

            # Path 2: --offline-only — never call DNS. Categorize the miss.
            if self.offline_only:
                self.stats['cache_misses'] += 1
                miss_kind = self._classify_offline_miss(domain, selector)
                self._lookup_outcomes[outcome_key] = miss_kind
                if miss_kind == 'OFFLINE-NO-DOMAIN':
                    self.stats['offline_no_domain'] += 1
                else:
                    self.stats['offline_no_key'] += 1
                return b''

            # Path 3: online lookup. Either no usable cache OR --overwrite-keys
            # is set and we're forcing a refresh.
            self.stats['cache_misses'] += 1
            try:
                result = dkim.dnsplug.get_txt(domain_bytes, timeout=timeout)

                if result:
                    key_data = result.decode('utf-8') if isinstance(result, bytes) else result
                    self.add_key_to_database(domain, selector, domain_str, key_data, current_filename, role=role)
                    self._lookup_outcomes[outcome_key] = 'dns-fresh'
                else:
                    self.add_key_to_database(domain, selector, domain_str, "", current_filename, "no_key", role=role)
                    self._lookup_outcomes[outcome_key] = 'dns-empty'

                return result

            except Exception as e:
                self.log(f"DNS lookup failed for {domain_str}: {e}")
                self.add_key_to_database(domain, selector, domain_str, "", current_filename, "dns_error", role=role)
                self.stats['dns_errors'] += 1
                self._lookup_outcomes[outcome_key] = 'dns-error'
                return b''

        return cached_dns_lookup

    def _classify_offline_miss(self, domain, selector):
        """In offline-only mode, classify why we have no key for this lookup.

        Returns one of:
        - 'OFFLINE-NO-DOMAIN': no entry in the database has a non-blank key for
          ``domain`` at any selector — we have nothing from this sender.
        - 'OFFLINE-NO-KEY': the database has at least one entry for ``domain``
          at some other selector, but not for this ``(domain, selector)``.
          Typical when the sender has rotated selectors since the cache was
          built.
        """
        for v in self.key_database.values():
            if v.get('domain') == domain and v.get('key_data'):
                return 'OFFLINE-NO-KEY'
        return 'OFFLINE-NO-DOMAIN'
    
    def extract_dkim_headers(self, message):
        """Extract all DKIM-Signature headers from the email."""
        dkim_headers = []
        
        # Get all DKIM-Signature headers (there can be multiple)
        for header_name, header_value in message.items():
            if header_name.lower() == 'dkim-signature':
                dkim_headers.append(header_value)
        
        return dkim_headers
    
    def parse_dkim_signature(self, dkim_header):
        """Parse a DKIM-Signature header into its components."""
        # Remove line breaks and normalize whitespace
        dkim_header = re.sub(r'\s+', ' ', dkim_header.strip())
        
        # Parse key=value pairs
        params = {}
        pairs = re.findall(r'(\w+)=([^;]+)', dkim_header)
        
        for key, value in pairs:
            params[key.strip()] = value.strip().strip('"')
        
        return params
    
    
    def verify_dkim_with_library(self, message_bytes, current_filename=None):
        """Verify DKIM using the dkimpy library (full verification)."""
        try:
            # Create cached DNS function for this verification
            cached_dns_func = self.create_cached_dns_function(current_filename)
            
            # Verify DKIM signature with cached DNS and detailed error reporting
            result = our_dkim_verify(message_bytes, 
                                   logger=self._get_debug_logger() if self.verbose else None, 
                                   dnsfunc=cached_dns_func,
                                   ignore_exp=True)
            
            if result:
                return True, "DKIM signature verified successfully"
            else:
                # Try to get more detailed error information
                try:
                    # Re-verify with debug info
                    import logging
                    import io
                    
                    log_capture = io.StringIO()
                    handler = logging.StreamHandler(log_capture)
                    logger = logging.getLogger('dkim')
                    logger.addHandler(handler)
                    logger.setLevel(logging.DEBUG)
                    
                    our_dkim_verify(message_bytes, logger=logger, ignore_exp=True)
                    
                    debug_output = log_capture.getvalue()
                    logger.removeHandler(handler)
                    
                    if debug_output:
                        return False, f"DKIM verification failed - Debug: {debug_output[:200]}..."
                    else:
                        return False, "DKIM signature verification failed (no debug info available)"
                        
                except Exception:
                    return False, "DKIM signature verification failed"
                
        except dkim.ValidationError as e:
            return False, f"DKIM validation error: {str(e)}"
        except Exception as e:
            return False, f"DKIM library error: {str(e)}"

    def verify_arc_with_library(self, message_bytes, current_filename=None):
        """Verify the ARC chain using dkimpy's arc_verify.

        Returns a dict:
            {
              'present': bool,                       # ARC headers found at all
              'cv': 'pass'|'fail'|'none'|'error',    # overall chain validation
              'reason': str,                         # human-readable detail
              'instances': [                         # per-hop detail
                  {'instance': int, 'ams_domain': str, 'ams_selector': str,
                   'ams_valid': bool, 'as_domain': str, 'as_selector': str,
                   'as_valid': bool, 'cv': str, 'aar': str},
                  ...
              ],
              'seals_valid_ams_invalid': bool,       # diagnostic for "body
                                                     # mutated after AMS"
            }
        """
        out = {
            'present': False,
            'cv': 'error',
            'effective_status': 'error',
            'reason': '',
            'instances': [],
            'seals_valid_ams_invalid': False,
            'trusted_assertions': [],
        }
        try:
            cached_dns_func = self.create_cached_dns_function(current_filename, role="arc")
            cv, results, reason = dkim.arc_verify(
                message_bytes,
                logger=self._get_debug_logger() if self.verbose else None,
                dnsfunc=cached_dns_func,
            )

            def _s(v):
                return v.decode('utf-8', 'ignore') if isinstance(v, (bytes, bytearray)) else (v or '')

            instances = []
            for r in results or []:
                instances.append({
                    'instance': r.get('instance'),
                    'ams_domain': _s(r.get('ams-domain', b'')),
                    'ams_selector': _s(r.get('ams-selector', b'')),
                    'ams_valid': bool(r.get('ams-valid', False)),
                    'as_domain': _s(r.get('as-domain', b'')),
                    'as_selector': _s(r.get('as-selector', b'')),
                    'as_valid': bool(r.get('as-valid', False)),
                    'cv': _s(r.get('cv', b'')),
                    'aar': _s(r.get('aar-value', b'')).strip(),
                })

            cv_str = _s(cv).lower() if cv else 'none'
            out['present'] = bool(instances)
            out['cv'] = cv_str if cv_str in ('pass', 'fail', 'none') else 'error'
            out['reason'] = _s(reason)
            out['instances'] = instances

            # Diagnostic: every seal verified, but the most recent AMS did not.
            # Strong signal that the body was mutated after ARC was applied.
            all_seals_valid = bool(instances) and all(i['as_valid'] for i in instances)
            any_ams_invalid = any(not i['ams_valid'] for i in instances)
            out['seals_valid_ams_invalid'] = bool(all_seals_valid and any_ams_invalid and cv_str == 'fail')

            # Effective status — a friendlier rollup than the RFC cv value.
            # PASS    : full chain validates (cv=pass)
            # PARTIAL : seals all valid (chain provably intact + AAR contents
            #           are signed and trustworthy) but body hash failed.
            #           This is the "Outlook download" case — meaningful
            #           cryptographic signal even though cv=fail.
            # FAIL    : chain itself broken (a seal failed)
            # NONE    : no ARC headers
            # ERROR   : verification hit an exception
            if not instances:
                out['effective_status'] = 'none' if cv_str == 'none' else 'error'
            elif cv_str == 'pass':
                out['effective_status'] = 'pass'
            elif cv_str == 'fail' and all_seals_valid:
                out['effective_status'] = 'partial'
            elif cv_str in ('fail', 'none'):
                out['effective_status'] = 'fail'
            else:
                out['effective_status'] = 'error'

            # When seals are valid, the AAR contents are themselves signed,
            # so each intermediary's "this is what I observed" statement is
            # a cryptographically trustworthy assertion *by that intermediary*.
            # Surface DKIM-related sub-claims for the user's benefit.
            if all_seals_valid:
                for inst in instances:
                    if not inst.get('as_valid'):
                        continue
                    aar = inst.get('aar') or ''
                    signer = inst.get('as_domain') or 'unknown'
                    for claim in re.findall(r'(?i)dkim=[a-z]+[^;]*', aar):
                        out['trusted_assertions'].append({
                            'instance': inst.get('instance'),
                            'signer': signer,
                            'claim': claim.strip(),
                        })

            return out
        except Exception as e:
            out['reason'] = f"ARC library error: {e}"
            return out

    # The exact byte sequence Microsoft Exchange Online injects at the start
    # of every HTML body part during delivery. Verified consistent across
    # outlook.com and hotmail.com on multiple sender accounts.
    MSOFT_META_INJECTION = b'<meta http-equiv="Content-Type" content="text/html; charset=utf-8">'

    def _arc_has_microsoft(self, arc_result):
        """True if microsoft.com appears as any ARC signer in the chain."""
        for inst in arc_result.get('instances', []) or []:
            if 'microsoft.com' in (inst.get('as_domain') or '').lower():
                return True
            if 'microsoft.com' in (inst.get('ams_domain') or '').lower():
                return True
        return False

    def _body_hash_matches(self, body, target_bh, canon_name):
        """True if the canonicalized body hashes to the given bh= value."""
        canon_cls = Relaxed if canon_name == 'relaxed' else Simple
        try:
            canonicalized = canon_cls.canonicalize_body(body)
        except Exception:
            return False
        computed = base64.b64encode(hashlib.sha256(canonicalized).digest()).decode()
        return computed == target_bh

    def _collect_multipart_boundaries(self, body_bytes):
        """Return all MIME boundary tokens declared in body_bytes.

        Includes the body's opening boundary (if any) plus every nested
        boundary declared via a Content-Type: multipart/*; boundary= header
        anywhere in the body. Boundaries inside attached message/rfc822
        parts are picked up too, which is what makes nested-multipart
        handling work for both the QP-part scanner and the body-level fix
        post-processors.
        """
        boundaries = []
        opening = re.match(rb"--([A-Za-z0-9'()+_,./:=?-]+)\r\n", body_bytes)
        if opening:
            boundaries.append(opening.group(1))
        for m in re.finditer(
            rb'(?i)Content-Type:\s*multipart/[^\r\n;]+;\s*boundary=("([^"]+)"|([^\s;\r\n]+))',
            body_bytes,
        ):
            tok = m.group(2) or m.group(3)
            if tok and tok not in boundaries:
                boundaries.append(tok)
        return boundaries

    def _collect_mixed_boundaries(self, body_bytes):
        """Return boundary tokens declared as multipart/mixed in body_bytes,
        plus the body's opening boundary (which is declared at the message
        header level, not in the body — included defensively since for
        attachment-bearing emails it is virtually always multipart/mixed).

        Used by the body-level boundary-CRLF-collapse fix, which only needs
        to act on mixed boundaries because Microsoft empirically inserts
        blank lines before mixed-boundary occurrences but not before
        multipart/alternative ones.
        """
        boundaries = []
        opening = re.match(rb"--([A-Za-z0-9'()+_,./:=?-]+)\r\n", body_bytes)
        if opening:
            boundaries.append(opening.group(1))
        for m in re.finditer(
            rb'(?i)Content-Type:\s*multipart/mixed;\s*boundary=("([^"]+)"|([^\s;\r\n]+))',
            body_bytes,
        ):
            tok = m.group(2) or m.group(3)
            if tok and tok not in boundaries:
                boundaries.append(tok)
        return boundaries

    def _collect_alternative_boundaries(self, body_bytes):
        """Return boundary tokens declared as multipart/alternative in body.

        Used by the context-aware boundary-CRLF-collapse fix to distinguish
        the closing line of a nested ALT (which gmail emits with single
        CRLF before the next outer-mixed boundary) from the closing of a
        nested MIXED (which gmail emits with double CRLF).
        """
        boundaries = []
        for m in re.finditer(
            rb'(?i)Content-Type:\s*multipart/alternative;\s*boundary=("([^"]+)"|([^\s;\r\n]+))',
            body_bytes,
        ):
            tok = m.group(2) or m.group(3)
            if tok and tok not in boundaries:
                boundaries.append(tok)
        return boundaries

    def _find_qp_html_part_ranges(self, body_bytes):
        """Find byte ranges of each QP-encoded text/html part body.

        Returns list of (start, end) offsets into body_bytes pointing at the
        QP payload of each matching part (excluding part headers and the
        trailing \\r\\n that precedes the next MIME boundary).

        Uses the actual MIME boundaries collected from any multipart
        Content-Type declarations in the body — necessary because:
        (a) QP content can contain byte sequences like "---------- Forwarded
            message --=" that a permissive regex would mis-match, and
        (b) multipart bodies can be NESTED (outer multipart/mixed containing
            inner multipart/alternative containing text/html). The smallest
            enclosing boundary must terminate the part, not the outermost.
        """
        boundaries = self._collect_multipart_boundaries(body_bytes)
        if not boundaries:
            return []
        boundary_line_re = re.compile(
            rb'\r\n--(?:' + rb'|'.join(re.escape(b) for b in boundaries) + rb')(?:--)?\r\n'
        )

        # Header block of a part: Content-Type: text/html..., possibly other
        # headers, must include Content-Transfer-Encoding: quoted-printable,
        # then a blank line. Order within the block isn't fixed, so allow
        # CTE either before or after the CT header.
        part_header_re = re.compile(
            rb'(?:(?<=\r\n)|^)'
            rb'(?:[A-Za-z-]+:[^\r\n]*\r\n)*?'
            rb'Content-Type:\s*text/html[^\r\n]*\r\n'
            rb'(?:[A-Za-z-]+:[^\r\n]*\r\n)*?'
            rb'\r\n',
            re.IGNORECASE,
        )

        results = []
        for m in part_header_re.finditer(body_bytes):
            header_block = body_bytes[m.start():m.end()]
            if not re.search(rb'(?i)Content-Transfer-Encoding:\s*quoted-printable', header_block):
                continue
            body_start = m.end()
            tail = boundary_line_re.search(body_bytes, body_start)
            body_end = (tail.start() + 2) if tail else len(body_bytes)  # +2 keeps the CRLF
            results.append((body_start, body_end))
        return results

    # HTML entity normalizations Microsoft Exchange applies to body content.
    # Each tuple: (bytes_found_in_outlook, bytes_to_restore_for_gmail). Reversing
    # these in the decoded HTML before re-encoding produces bytes that match
    # Gmail's signed bh=.
    #
    # Empirically observed Microsoft transformations:
    #   raw → entity:  U+00A0 (\xc2\xa0)  →  "&nbsp;"
    #   entity → raw:  "&#39;"             →  "'"   (numeric apostrophe entity decoded)
    #
    # Add more tuples here as new conversions are discovered (em-dash, smart
    # quotes, etc.). The reversal of "&#39;" → "'" is structurally identical:
    # find Microsoft's form in the body, replace with Gmail's form.
    MSOFT_ENTITY_REVERSALS = [
        (b'&nbsp;', b'\xc2\xa0'),   # U+00A0 non-breaking space
    ]

    # Microsoft Defender for Office 365 "Safe Links": rewrites every external
    # <a href="X"> in incoming HTML to
    #   <a href="https://<region>.safelinks.protection.outlook.com/?url=ENC&..."
    #      originalsrc="X" originalattributes="...">...
    # The originalsrc attribute preserves the pristine URL, so the reversal is
    # mechanical: find the safelinks-href + originalsrc pair, replace with a
    # simple href=originalsrc-value, drop the originalsrc attribute (and any
    # paired originalattributes).
    _SAFELINKS_HREF_RE = re.compile(
        rb'href="https://[^"]*safelinks\.protection\.outlook\.com[^"]*"'
        rb'\s+originalsrc="([^"]*)"'
        rb'(?:\s+originalattributes="[^"]*")?'
    )

    # Microsoft Exchange Online decodes numeric apostrophe entities (&#39;) in
    # HTML body content to literal apostrophes. Reversing requires substituting
    # all literal apostrophes back to &#39; — safe in practice because Gmail's
    # composer encodes apostrophes in body text as &#39; and rarely emits raw
    # apostrophes elsewhere. The bh= oracle catches any false-positive case.
    _APOS_DECODE_RE = re.compile(rb"'")

    def _attempt_phase2_qp_fix(self, body_bytes, target_bh, canon_name):
        """Phase 2: decode each QP HTML part, strip the meta tag, optionally
        reverse Microsoft's body mutations, then re-encode.

        Variants tried, in order (first bh= match wins):
        - 'meta-strip only': handles the common case where Microsoft's only
          mutation is the <meta> injection
        - 'meta-strip + entity-reverse': also reverses HTML entity
          normalizations (e.g. &nbsp; → U+00A0)
        - '+ safelinks-unwrap': also reverses Microsoft Defender Safe Links
          URL rewrapping (uses Microsoft's own originalsrc attribute as the
          authoritative source for the pre-wrap URL)
        - '+ apostrophe-encode': also restores Microsoft's decoded numeric
          apostrophe entities (&#39; → ' reversed)

        Each variant is a strict superset of the previous, so we try them in
        order of increasing aggressiveness.

        Returns (fixed_body_or_None, variant_label).
        """
        qp_ranges = self._find_qp_html_part_ranges(body_bytes)
        if not qp_ranges:
            return None, 'no QP HTML parts'

        # Python's stdlib quopri with CRLF normalization was confirmed
        # byte-exact to Gmail's encoder via paired-sample roundtrip on
        # a ~9KB HTML body.
        def python_stdlib(raw):
            out = quopri.encodestring(raw, quotetabs=False)
            return out.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')

        def no_entity_reverse(html):
            return html

        def reverse_entities(html):
            for entity, raw in self.MSOFT_ENTITY_REVERSALS:
                html = html.replace(entity, raw)
            return html

        def reverse_safelinks(html):
            html = reverse_entities(html)
            return self._SAFELINKS_HREF_RE.sub(rb'href="\1"', html)

        def reverse_safelinks_and_apos(html):
            html = reverse_safelinks(html)
            return html.replace(b"'", b'&#39;')

        # Body-level post-processing: collapse Microsoft's stray empty-line
        # insertions that appear before each outer-multipart boundary line.
        # This isn't an HTML-part transform — it operates on the whole body
        # after splice-back — so it's a separate stage.
        def collapse_outer_boundary_crlfs(body):
            op = re.match(rb"--([A-Za-z0-9'()+_,./:=?-]+)\r\n", body)
            if not op:
                return body
            outer = op.group(1)
            return re.sub(
                rb'\r\n\r\n(--' + re.escape(outer) + rb'(?:--)?\r\n)',
                rb'\r\n\1',
                body,
            )

        # Same idea but for ALL multipart/mixed boundaries declared in body
        # (outermost plus mixed-boundaries inside attached message/rfc822
        # parts), with context-aware selection of which `\r\n\r\n--<bnd>`
        # occurrences to collapse.
        #
        # Empirical pattern (from paired ground-truth diff): gmail emits
        # double-CRLF before a mixed-boundary occurrence when preceded by
        # either:
        #   - the end of a header block (last header line: e.g. Bcc: …)
        #   - the closing of a NESTED multipart/mixed (--<innerMIXED>--\r\n)
        # and single-CRLF when preceded by:
        #   - the closing of a nested multipart/ALTERNATIVE
        #     (--<innerALT>--\r\n)
        #   - base64 binary content ending (==\r\n)
        # Microsoft normalizes all of these to double-CRLF; we collapse only
        # the ones that gmail emits as single.
        def collapse_mixed_boundary_crlfs(body):
            mixed_bnds = self._collect_mixed_boundaries(body)
            if not mixed_bnds:
                return body
            alt_bnds = set(self._collect_alternative_boundaries(body))
            # NOTE: m.start() in the pattern points at the first \r of
            # \r\n\r\n — so `preceding` is the bytes BEFORE that, ending at
            # the closing line's content (the line's trailing \r\n is part
            # of the match, NOT of preceding). We anchor closing/base64
            # tests on the raw content ending, without trailing CRLF.
            closing_re = re.compile(
                rb"--([A-Za-z0-9'()+_,./:=?-]+)--$"
            )
            for bnd in mixed_bnds:
                pat = re.compile(
                    rb'\r\n\r\n(--' + re.escape(bnd) + rb'(?:--)?\r\n)'
                )
                # Right-to-left so earlier offsets stay valid.
                for m in reversed(list(pat.finditer(body))):
                    preceding = body[max(0, m.start() - 48):m.start()]
                    should_collapse = False
                    cm = closing_re.search(preceding)
                    if cm:
                        # The line directly before \r\n\r\n is a closing
                        # boundary. Collapse iff that closing is for a
                        # multipart/alternative.
                        if cm.group(1) in alt_bnds:
                            should_collapse = True
                    elif preceding.endswith(b'=='):
                        # Base64 binary content end (== padding).
                        should_collapse = True
                    # Otherwise (header-block-ending, or inner-MIXED close
                    # not captured above, or other unknown content) leave
                    # the double in place. The bh= oracle catches any
                    # mis-classification by simply failing to produce a fix.
                    if should_collapse:
                        body = body[:m.start()] + b'\r\n' + m.group(1) + body[m.end():]
            return body

        # RESTORE Microsoft's stripped trailing space on the two attachment-
        # introducing header value lines. Each is a continuation-style header
        # where the next line is whitespace-indented (tab or spaces). The
        # signed form has a single trailing space between the ';' and the
        # CRLF on the first line; Microsoft strips it on receive. Re-adding
        # it is unconditional — false positives are caught by the bh= oracle.
        def restore_attachment_header_trailing_space(body):
            body = re.sub(
                rb'(\r\nContent-Type:\s*message/rfc822;)(\r\n)',
                rb'\1 \2',
                body,
            )
            body = re.sub(
                rb'(\r\nContent-Disposition:\s*attachment;)(\r\n)',
                rb'\1 \2',
                body,
            )
            return body

        def mixed_boundary_crlfs_and_restore_trailing_space(body):
            return restore_attachment_header_trailing_space(
                collapse_mixed_boundary_crlfs(body)
            )

        # Reverse Microsoft's rewrite of `Bcc:` headers inside attached
        # message/rfc822 parts. Microsoft uppercases the header name and
        # wraps the address in angle brackets:
        #   Bcc: user@example.com  →  BCC: <user@example.com>
        # The reversal is exact; bh= oracle catches any false positives.
        bcc_rewrite_re = re.compile(rb'\r\nBCC: <([^>\r\n]+)>\r\n')
        def reverse_bcc_rewrite(body):
            return bcc_rewrite_re.sub(rb'\r\nBcc: \1\r\n', body)

        # Reverse Microsoft's relocation of `MIME-Version: 1.0` inside an
        # attached message/rfc822's header block. Microsoft moves it to be
        # the LAST header (immediately before the blank line that separates
        # those attached headers from the attached body). Gmail's canonical
        # position is just before the EARLIEST content-class header in the
        # same block — empirically, the first of References / In-Reply-To /
        # From (whichever appears first in this attached eml's headers).
        #
        # Pattern: any occurrence of `\r\nMIME-Version: 1.0\r\n\r\n--<bnd>`
        # is by structure an attached eml's last header (because the blank
        # line + boundary follow). For each, remove the MIME-Version line
        # and re-insert it at the gmail-canonical position.
        mime_version_at_end_re = re.compile(
            rb'\r\nMIME-Version: 1\.0\r\n(\r\n--[A-Za-z0-9\'()+_,./:=?-]+\r\n)'
        )
        mime_anchor_re = re.compile(rb'\r\n(?:References|In-Reply-To|From): ')
        any_boundary_line_re = re.compile(
            rb'\r\n--[A-Za-z0-9\'()+_,./:=?-]+(?:--)?\r\n'
        )
        def reverse_mime_version_relocation(body):
            relocated = []  # track positions so we don't re-process them
            while True:
                m = mime_version_at_end_re.search(body)
                if not m or m.start() in relocated:
                    break
                mv_start = m.start()
                mv_end = mv_start + len(b'\r\nMIME-Version: 1.0')
                before = body[:mv_start]
                # The current attached eml's headers begin right after the
                # most-recent boundary line in `before`. (Attached eml header
                # blocks have no intermediate boundaries.) Anchors before
                # that block_start belong to an outer header block and must
                # be excluded.
                last_bnd = None
                for bm in any_boundary_line_re.finditer(before):
                    last_bnd = bm
                block_start = last_bnd.end() if last_bnd else 0
                in_block = [
                    am.start() for am in mime_anchor_re.finditer(before)
                    if am.start() >= block_start
                ]
                if not in_block:
                    # No suitable anchor in this block — skip this MV to
                    # avoid infinite loop, by marking position as processed.
                    relocated.append(mv_start)
                    continue
                insert_at = min(in_block)
                body = (
                    before[:insert_at]
                    + b'\r\nMIME-Version: 1.0'
                    + before[insert_at:]
                    + body[mv_end:]
                )
            return body

        def body_post_all(body):
            # Order matters: MIME-Version relocation uses the
            # `\r\nMIME-Version: 1.0\r\n\r\n--<bnd>\r\n` pattern to identify
            # the relocated header, so it must run BEFORE the boundary-CRLF
            # collapse (which would remove the blank line). BCC reverse is
            # independent and can go anywhere.
            body = reverse_bcc_rewrite(body)
            body = reverse_mime_version_relocation(body)
            body = collapse_mixed_boundary_crlfs(body)
            body = restore_attachment_header_trailing_space(body)
            return body

        def no_body_post(body):
            return body

        # SafeLinks unwrap variant that ALSO trims a trailing slash from
        # bare-host URLs. Microsoft's URL canonicalization appears to add
        # `/` to bare-host URLs (e.g., http://example.local → http://example.local/)
        # before storing in originalsrc. The plain href in the signed form
        # had no trailing slash; restoring that bare form is the reversal.
        bare_host_url_re = re.compile(rb'^https?://[^/?#]+/$')
        def reverse_safelinks_with_slash_trim(html):
            html = reverse_entities(html)
            def sub_fn(m):
                url = m.group(1)
                if bare_host_url_re.match(url):
                    url = url[:-1]
                return b'href="' + url + b'"'
            return self._SAFELINKS_HREF_RE.sub(sub_fn, html)

        def reverse_safelinks_trimmed_and_apos(html):
            html = reverse_safelinks_with_slash_trim(html)
            return html.replace(b"'", b'&#39;')

        # (label, post-strip-html, encoder, body-postprocess)
        variants = [
            ('meta-strip only',                                                    no_entity_reverse,          python_stdlib, no_body_post),
            ('meta-strip + entity-reverse',                                        reverse_entities,           python_stdlib, no_body_post),
            ('meta-strip + entity-reverse + safelinks-unwrap',                     reverse_safelinks,          python_stdlib, no_body_post),
            ('meta-strip + entity-reverse + safelinks-unwrap + apostrophe-encode', reverse_safelinks_and_apos, python_stdlib, no_body_post),
            ('+ outer-boundary-CRLF-collapse',                                     reverse_safelinks_and_apos, python_stdlib, collapse_outer_boundary_crlfs),
            ('+ mixed-boundary-CRLF-collapse + trailing-space-restore',            reverse_safelinks_and_apos, python_stdlib, mixed_boundary_crlfs_and_restore_trailing_space),
            ('+ slash-trim + BCC-reverse + MIME-Version-relocation',               reverse_safelinks_trimmed_and_apos, python_stdlib, body_post_all),
        ]

        for variant_label, post_strip, encoder, body_post in variants:
            fixed = body_bytes
            offset_delta = 0
            any_stripped = False
            ok = True
            for orig_start, orig_end in qp_ranges:
                start = orig_start + offset_delta
                end = orig_end + offset_delta
                part_qp = fixed[start:end]
                decoded = quopri.decodestring(part_qp)
                stripped = decoded.replace(self.MSOFT_META_INJECTION, b'')
                if stripped == decoded:
                    continue  # no meta in this part
                any_stripped = True
                transformed = post_strip(stripped)
                try:
                    re_encoded = encoder(transformed)
                except Exception:
                    ok = False
                    break
                fixed = fixed[:start] + re_encoded + fixed[end:]
                offset_delta += len(re_encoded) - (end - start)
            if not ok or not any_stripped:
                continue
            fixed = body_post(fixed)
            if self._body_hash_matches(fixed, target_bh, canon_name):
                return fixed, variant_label

        return None, f'tried {len(variants)} variant(s), no match'

    def attempt_microsoft_fix(self, message_bytes, file_path, dkim_params, arc_result):
        """Reverse Microsoft Exchange's HTML <meta> injection on DKIM-failing
        emails. Two phases tried in order:

        - Phase 1: raw-byte strip of the meta tag (handles non-QP bodies)
        - Phase 2: QP-aware decode → strip → re-encode (handles QP bodies)

        The DKIM bh= acts as the cryptographic oracle in both phases — we
        only declare success when the reconstructed body hashes to the exact
        signed value, and only write <name>.fixed.eml in that case. Phase 1
        is cheap and idempotent on QP bodies (meta-in-QP doesn't match the
        raw pattern), so a body with mixed QP and non-QP parts would have
        Phase 1 strip the non-QP occurrences first and then Phase 2 handle
        the QP ones.
        """
        out = {
            'attempted': True,
            'succeeded': False,
            'phase': None,
            'variant': None,
            'phases_attempted': [],
            'skipped_reason': None,
            'fixed_path': None,
            'transformations_applied': [],
            'message': '',
        }

        # Pre-check: Microsoft must be in the ARC chain. If not, the
        # meta-tag injection wouldn't have happened and there's nothing
        # to fix.
        if not self._arc_has_microsoft(arc_result):
            out['skipped_reason'] = 'no microsoft.com in ARC chain'
            out['message'] = out['skipped_reason']
            self.stats['msoft_fix_skipped_no_msoft'] += 1
            return out

        # Split into header and body.
        header_end = message_bytes.find(b'\r\n\r\n')
        if header_end == -1:
            out['skipped_reason'] = 'malformed message (no header/body boundary)'
            out['message'] = out['skipped_reason']
            self.stats['msoft_fix_failed'] += 1
            return out
        headers_bytes = message_bytes[:header_end]
        body_bytes = message_bytes[header_end + 4:]

        target_bh = dkim_params.get('bh', '')
        canon_spec = dkim_params.get('c', 'simple/simple')
        canon_name = canon_spec.split('/')[-1] if '/' in canon_spec else canon_spec

        candidate_body = None

        # Phase 1: raw-byte meta-strip
        phase1_occurrences = body_bytes.count(self.MSOFT_META_INJECTION)
        if phase1_occurrences > 0:
            out['phases_attempted'].append('Phase 1 (raw meta-strip)')
            stripped = body_bytes.replace(self.MSOFT_META_INJECTION, b'')
            if self._body_hash_matches(stripped, target_bh, canon_name):
                candidate_body = stripped
                out['phase'] = 'phase1'
                out['variant'] = 'meta-strip'
                out['transformations_applied'].append(
                    f'Phase 1: stripped {phase1_occurrences} raw <meta> injection(s)'
                )

        # Phase 2: QP-aware decode/strip/re-encode
        if candidate_body is None:
            qp_ranges = self._find_qp_html_part_ranges(body_bytes)
            if qp_ranges:
                out['phases_attempted'].append(f'Phase 2 (QP re-encode, {len(qp_ranges)} QP HTML part(s))')
                phase2_body, phase2_info = self._attempt_phase2_qp_fix(body_bytes, target_bh, canon_name)
                if phase2_body is not None:
                    candidate_body = phase2_body
                    out['phase'] = 'phase2'
                    out['variant'] = phase2_info
                    out['transformations_applied'].append(
                        f'Phase 2: QP decode → meta-strip → re-encode ({phase2_info})'
                    )

        if candidate_body is None:
            # Diagnose: did we even find a meta tag to strip?
            if not out['phases_attempted']:
                out['skipped_reason'] = 'no meta-tag injection found in body (raw or QP HTML)'
                out['message'] = out['skipped_reason']
                self.stats['msoft_fix_skipped_no_meta'] += 1
            else:
                phases_str = ' and '.join(out['phases_attempted'])
                out['message'] = (
                    f'tried {phases_str} — none produced bytes matching signed bh=. '
                    'Other Microsoft mutations may also be involved (e.g. BCC rewrite, '
                    'MIME-Version relocation, header whitespace stripping, extra CRLF '
                    'insertions near MIME boundaries).'
                )
                self.stats['msoft_fix_failed'] += 1
            return out

        # We have a body that hashes to bh=. Confirm with full DKIM verify
        # — free insurance, catches header mutation we might also need to
        # handle later.
        fixed_message = headers_bytes + b'\r\n\r\n' + candidate_body
        cached_dns_func = self.create_cached_dns_function(file_path.name, role='dkim')
        try:
            full_ok = our_dkim_verify(
                fixed_message,
                dnsfunc=cached_dns_func,
                ignore_exp=True,
            )
        except Exception as e:
            out['message'] = f'body hash matched ({out["phase"]}) but full DKIM verify raised: {e}'
            self.stats['msoft_fix_failed'] += 1
            return out

        if not full_ok:
            out['message'] = (
                f'body hash matched ({out["phase"]}) but full DKIM verify failed — '
                'header mutation likely also present'
            )
            self.stats['msoft_fix_failed'] += 1
            return out

        # Write the fixed bytes. With --replace, overwrite the original .eml
        # (destructive — replaces the Microsoft-mutated copy with the bit-exact
        # original signed body). Without --replace, write a side-by-side
        # <name>.fixed.eml and leave the original untouched.
        if self.replace_original:
            fixed_path = file_path
            action_label = 'replaced'
        else:
            fixed_path = file_path.parent / f'{file_path.stem}.fixed.eml'
            action_label = 'wrote'

        try:
            with open(fixed_path, 'wb') as f:
                f.write(fixed_message)
        except Exception as e:
            out['message'] = f'reconstruction verified but failed to write {fixed_path.name}: {e}'
            self.stats['msoft_fix_failed'] += 1
            return out

        out['succeeded'] = True
        out['fixed_path'] = str(fixed_path)
        phase_label = (
            'Phase 1: meta-strip' if out['phase'] == 'phase1'
            else f'Phase 2: QP re-encode (variant: {out["variant"]})'
        )
        out['message'] = (
            f'{action_label} {fixed_path.name} [{phase_label}] — body hash matches '
            f'signed bh=, full DKIM verification confirmed'
        )
        if out['phase'] == 'phase1':
            self.stats['msoft_fix_succeeded_phase1'] += 1
        else:
            self.stats['msoft_fix_succeeded_phase2'] += 1
        return out

    def _get_debug_logger(self):
        """Get a debug logger for DKIM verification."""
        import logging
        logger = logging.getLogger('dkim_debug')
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.DEBUG)
            logger.addHandler(handler)
            logger.setLevel(logging.DEBUG)
        return logger
    
    def analyze_authentication_results(self, message):
        """Analyze Authentication-Results headers for DKIM info."""
        auth_results = []
        
        for header_name, header_value in message.items():
            if header_name.lower() == 'authentication-results':
                auth_results.append(header_value)
        
        dkim_results = []
        for auth_header in auth_results:
            # Look for DKIM results in Authentication-Results
            if 'dkim=' in auth_header.lower():
                dkim_results.append(auth_header)
        
        return dkim_results
    
    def clean_gmail_export(self, message_bytes):
        """Remove Gmail export headers before Delivered-To to restore original email.

        Only searches within the actual header section (before the headers/body
        separator). A naive whole-file search can match a Delivered-To: line
        inside the message body — e.g. a forwarded or attached .eml — and would
        then strip the real headers (including DKIM-Signature), guaranteeing a
        verification failure.
        """
        try:
            # Convert to string for easier processing
            message_str = message_bytes.decode('utf-8', errors='ignore')

            # Locate the end of the header block. RFC 5322 says CRLF CRLF; in
            # practice files may use LF LF after extraction tools touch them.
            crlf_end = message_str.find('\r\n\r\n')
            lf_end = message_str.find('\n\n')
            candidates = [pos for pos in (crlf_end, lf_end) if pos != -1]
            header_end = min(candidates) if candidates else len(message_str)

            # Only search for Delivered-To within the header section.
            delivered_to_pattern = re.compile(r'^delivered-to:', re.MULTILINE | re.IGNORECASE)
            match = delivered_to_pattern.search(message_str, 0, header_end)

            if match and match.start() > 0:
                # Extract everything from Delivered-To onward
                cleaned_content = message_str[match.start():]
                self.log(f"Found Delivered-To at position {match.start()}, removing {match.start()} bytes of Gmail headers")

                # Convert back to bytes
                return cleaned_content.encode('utf-8'), True
            else:
                if match:
                    self.log("Delivered-To is already the first header; nothing to clean")
                else:
                    self.log("No Delivered-To header in header block, using original content")
                return message_bytes, False

        except Exception as e:
            self.log(f"Error cleaning Gmail export: {e}")
            return message_bytes, False

    def analyze_email_structure(self, original_bytes, cleaned_bytes, message):
        """Analyze email structure for potential DKIM issues."""
        analysis = {
            'line_endings': 'unknown',
            'has_extra_headers': False,
            'extra_headers': [],
            'gmail_headers_removed': False,
            'bytes_removed': 0
        }
        
        # Check if Gmail headers were removed
        if len(cleaned_bytes) < len(original_bytes):
            analysis['gmail_headers_removed'] = True
            analysis['bytes_removed'] = len(original_bytes) - len(cleaned_bytes)
        
        # Check line endings
        if b'\r\n' in cleaned_bytes and b'\n' in cleaned_bytes:
            analysis['line_endings'] = 'mixed'
        elif b'\r\n' in cleaned_bytes:
            analysis['line_endings'] = 'CRLF'
        elif b'\n' in cleaned_bytes:
            analysis['line_endings'] = 'LF'
        
        # Look for potentially problematic headers still remaining
        problematic_headers = [
            'x-mozilla-status', 'x-mozilla-status2', 'x-mozilla-keys',
            'x-uidl', 'x-evolution-source', 'x-gm-thrid', 'x-gmail-labels',
            'status', 'x-status', 'x-keywords', 'x-uid'
        ]
        
        for header_name, header_value in message.items():
            if header_name.lower() in problematic_headers:
                analysis['has_extra_headers'] = True
                analysis['extra_headers'].append(f"{header_name}: {header_value[:50]}...")
        
        return analysis

    def _record_arc_stats(self, arc):
        """Update aggregate ARC stats from a per-email arc result dict."""
        eff = arc.get('effective_status', 'error')
        if eff == 'pass':
            self.stats['arc_pass'] += 1
        elif eff == 'partial':
            self.stats['arc_partial'] += 1
        elif eff == 'fail':
            self.stats['arc_fail'] += 1
        elif eff == 'none':
            self.stats['arc_none'] += 1
        else:
            self.stats['arc_error'] += 1
        if arc.get('seals_valid_ams_invalid'):
            self.stats['arc_seals_valid_ams_invalid'] += 1

    def verify_email_file(self, file_path):
        """Verify DKIM signatures in a single email file."""
        result = {
            'file': file_path.name,
            'path': str(file_path),
            'dkim_signatures': [],
            'authentication_results': [],
            'overall_status': 'no_dkim',
            'verification_details': [],
            'structure_analysis': {},
            'arc': {},
            'offline_failure_reason': None,
        }

        # Reset per-file lookup outcome tracking before either DKIM or ARC
        # verification touches the cache. Used to attribute offline failures
        # to the specific signature that needed a key we didn't have.
        self._lookup_outcomes = {}

        try:
            # Read the email file
            with open(file_path, 'rb') as f:
                original_message_bytes = f.read()

            # Clean Gmail export headers
            cleaned_message_bytes, was_cleaned = self.clean_gmail_export(original_message_bytes)

            # Parse the cleaned message for header analysis
            message = email.message_from_string(cleaned_message_bytes.decode('utf-8', errors='ignore'))

            # Analyze email structure for potential issues
            result['structure_analysis'] = self.analyze_email_structure(
                original_message_bytes, cleaned_message_bytes, message
            )

            # ARC verification runs independently of DKIM and is recorded
            # regardless of DKIM outcome. It's the only meaningful signal we
            # have on messages that have been mutated by intermediaries
            # (e.g., Outlook's HTML normalization).
            arc_result = self.verify_arc_with_library(cleaned_message_bytes, file_path.name)
            result['arc'] = arc_result
            self._record_arc_stats(arc_result)

            # Extract DKIM signatures
            dkim_headers = self.extract_dkim_headers(message)
            if not dkim_headers:
                # Check Authentication-Results headers
                auth_results = self.analyze_authentication_results(message)
                if auth_results:
                    result['authentication_results'] = auth_results
                    result['overall_status'] = 'no_dkim_signature'
                self.stats['no_dkim'] += 1
                return result
            
            self.stats['emails_with_dkim'] += 1
            result['overall_status'] = 'has_dkim'
            
            if len(dkim_headers) > 1:
                self.stats['multiple_signatures'] += 1
            
            has_valid_signature = False
            
            # Verify each DKIM signature
            for i, dkim_header in enumerate(dkim_headers):
                self.log(f"Processing DKIM signature {i+1}/{len(dkim_headers)}")
                
                try:
                    # Parse DKIM signature
                    dkim_params = self.parse_dkim_signature(dkim_header)
                    result['dkim_signatures'].append({
                        'index': i + 1,
                        'domain': dkim_params.get('d', 'unknown'),
                        'selector': dkim_params.get('s', 'unknown'),
                        'algorithm': dkim_params.get('a', 'unknown'),
                        'headers': dkim_params.get('h', 'unknown'),
                        'raw_header': dkim_header[:100] + '...' if len(dkim_header) > 100 else dkim_header
                    })
                    
                    valid, message_text = self.verify_dkim_with_library(cleaned_message_bytes, file_path.name)
                    verification_method = "dkimpy library (full verification)"
                    if was_cleaned:
                        verification_method += " - Gmail headers cleaned"

                    # In offline-only mode, attribute a failure to the exact
                    # reason the key was missing (or that the key was present
                    # but verification still failed — the most informative
                    # case, e.g. body mutated by an intermediary).
                    offline_reason = None
                    if self.offline_only and not valid:
                        d = dkim_params.get('d', 'unknown')
                        s = dkim_params.get('s', 'unknown')
                        outcome = self._lookup_outcomes.get((d, s))
                        if outcome == 'hit':
                            offline_reason = 'OFFLINE-KEY-MATCHED-VERIFY-FAILED'
                            self.stats['offline_key_matched_verify_failed'] += 1
                            message_text = (f"key matched in database for {d}:{s} but DKIM "
                                            f"verification failed (body likely altered)")
                        elif outcome in ('OFFLINE-NO-DOMAIN', 'OFFLINE-NO-KEY'):
                            offline_reason = outcome
                            if outcome == 'OFFLINE-NO-DOMAIN':
                                message_text = (f"offline-only: no candidate key in database "
                                                f"for domain {d}")
                            else:
                                message_text = (f"offline-only: database has no key for "
                                                f"{d}:{s}")

                    detail = {
                        'signature_index': i + 1,
                        'domain': dkim_params.get('d', 'unknown'),
                        'valid': valid,
                        'message': message_text,
                        'method': verification_method
                    }
                    if offline_reason:
                        detail['offline_reason'] = offline_reason
                    result['verification_details'].append(detail)

                    if valid:
                        has_valid_signature = True
                        self.log(f"✓ Valid DKIM signature for domain: {dkim_params.get('d', 'unknown')}")
                    else:
                        self.log(f"✗ Invalid DKIM signature: {message_text}")
                        
                except Exception as e:
                    result['verification_details'].append({
                        'signature_index': i + 1,
                        'valid': False,
                        'message': f"Error processing signature: {str(e)}",
                        'method': 'error'
                    })
                    self.stats['verification_errors'] += 1
            
            # Set overall status
            if has_valid_signature:
                result['overall_status'] = 'valid_dkim'
                self.stats['valid_dkim'] += 1
            else:
                result['overall_status'] = 'invalid_dkim'
                self.stats['invalid_dkim'] += 1

                # File-level offline reason: pick the most informative across
                # per-signature reasons. KEY-MATCHED-VERIFY-FAILED beats
                # NO-KEY which beats NO-DOMAIN. (If any signature's key was
                # found and merely failed crypto, that's the headline.)
                if self.offline_only:
                    priority = {
                        'OFFLINE-KEY-MATCHED-VERIFY-FAILED': 3,
                        'OFFLINE-NO-KEY': 2,
                        'OFFLINE-NO-DOMAIN': 1,
                    }
                    best = None
                    best_rank = 0
                    for detail in result['verification_details']:
                        r = detail.get('offline_reason')
                        if r and priority.get(r, 0) > best_rank:
                            best = r
                            best_rank = priority[r]
                    result['offline_failure_reason'] = best

            # Microsoft fix attempt — only when DKIM failed and the user
            # opted in. Uses the first DKIM signature's bh= as the oracle.
            if (self.attempt_fix
                    and not has_valid_signature
                    and dkim_headers):
                first_sig_params = self.parse_dkim_signature(dkim_headers[0])
                result['msoft_fix'] = self.attempt_microsoft_fix(
                    cleaned_message_bytes, file_path, first_sig_params, arc_result
                )

        except Exception as e:
            result['overall_status'] = 'error'
            result['error'] = str(e)
            self.stats['verification_errors'] += 1
            self.log(f"Error processing {file_path}: {e}")

        return result
    
    def scan_directory(self, directory):
        """Scan directory for .eml files and verify DKIM signatures."""
        directory = Path(directory)
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")
        
        eml_files = list(directory.glob("*.eml"))
        if not eml_files:
            print(f"No .eml files found in {directory}")
            return
        
        self.stats['total_files'] = len(eml_files)
        print(f"Found {len(eml_files)} .eml files to process...")
        
        for i, file_path in enumerate(eml_files, 1):
            if i % 50 == 0 or self.verbose:
                print(f"Processing {i}/{len(eml_files)}: {file_path.name}")
            
            result = self.verify_email_file(file_path)
            self.results.append(result)
    
    def print_report(self, output_file=None):
        """Print DKIM verification report."""
        report_lines = []
        
        # Summary
        report_lines.append("=" * 60)
        report_lines.append("DKIM SIGNATURE VERIFICATION REPORT")
        report_lines.append("=" * 60)
        report_lines.append(f"Total emails read/checked: {self.stats['total_files']}")
        report_lines.append(f"Emails with valid DKIM signatures: {self.stats['valid_dkim']}")
        report_lines.append(f"Emails with invalid DKIM signatures: {self.stats['invalid_dkim']}")
        report_lines.append(f"Emails without DKIM signatures: {self.stats['no_dkim']}")
        report_lines.append(f"Emails with multiple signatures: {self.stats['multiple_signatures']}")
        report_lines.append(f"Verification errors: {self.stats['verification_errors']}")

        # ARC summary — separate axis from DKIM; reported on every email
        report_lines.append("")
        report_lines.append("ARC CHAIN VERIFICATION:")
        report_lines.append("-" * 30)
        report_lines.append(f"ARC pass (full chain validates): {self.stats['arc_pass']}")
        report_lines.append(
            f"ARC partial (seal chain valid, body not provable): {self.stats['arc_partial']}"
        )
        report_lines.append(f"ARC fail (chain broken): {self.stats['arc_fail']}")
        report_lines.append(f"ARC none (no ARC headers): {self.stats['arc_none']}")
        if self.stats['arc_error']:
            report_lines.append(f"ARC errors: {self.stats['arc_error']}")

        # Microsoft fix summary — only rendered when the flag was enabled
        if self.attempt_fix:
            report_lines.append("")
            mode_suffix = ' + --replace (in-place)' if self.replace_original else ''
            report_lines.append(f"MICROSOFT FIX ATTEMPTS (--attempt-fix{mode_suffix}):")
            report_lines.append("-" * 30)
            report_lines.append(f"Reconstructed via Phase 1 (raw meta-strip): {self.stats['msoft_fix_succeeded_phase1']}")
            report_lines.append(f"Reconstructed via Phase 2 (QP re-encode):   {self.stats['msoft_fix_succeeded_phase2']}")
            report_lines.append(f"Failed (no reconstruction matched bh=):     {self.stats['msoft_fix_failed']}")
            report_lines.append(f"Skipped — no Microsoft in ARC chain:        {self.stats['msoft_fix_skipped_no_msoft']}")
            report_lines.append(f"Skipped — no meta-tag injection found:      {self.stats['msoft_fix_skipped_no_meta']}")

        # Key caching statistics (always present — DB is always active)
        report_lines.append("")
        report_lines.append("KEY CACHING STATISTICS:")
        report_lines.append("-" * 30)
        report_lines.append(f"Key database file: {self.key_database_file}")
        report_lines.append(f"Keys loaded from database: {self.stats['keys_loaded']}")
        report_lines.append(f"New keys saved to database: {self.stats['keys_saved']}")
        report_lines.append(f"Cache hits: {self.stats['cache_hits']}")
        report_lines.append(f"Cache misses: {self.stats['cache_misses']}")
        total_lookups = self.stats['cache_hits'] + self.stats['cache_misses']
        if total_lookups > 0:
            hit_rate = (self.stats['cache_hits'] / total_lookups) * 100
            report_lines.append(f"Cache hit rate: {hit_rate:.1f}%")
        report_lines.append(f"Total keys in database: {len(self.key_database)}")
        if self.stats.get('keys_overwritten'):
            report_lines.append(f"Keys overwritten (--overwrite-keys): {self.stats['keys_overwritten']}")

        # Offline-only diagnostic breakdown (only meaningful in that mode).
        if self.offline_only:
            report_lines.append("")
            report_lines.append("OFFLINE-ONLY FAILURE BREAKDOWN:")
            report_lines.append("-" * 30)
            report_lines.append(f"Signatures with no candidate key for domain (NO-DOMAIN): {self.stats['offline_no_domain']}")
            report_lines.append(f"Signatures with no key for this selector (NO-KEY):       {self.stats['offline_no_key']}")
            report_lines.append(f"Signatures with key matched but verify failed:           {self.stats['offline_key_matched_verify_failed']}")
        
        if self.stats['total_files'] > 0:
            valid_rate = (self.stats['valid_dkim'] / self.stats['total_files']) * 100
            report_lines.append(f"Valid DKIM rate: {valid_rate:.1f}% of all emails")
        
        if self.stats['emails_with_dkim'] > 0:
            success_rate = (self.stats['valid_dkim'] / self.stats['emails_with_dkim']) * 100
            report_lines.append(f"DKIM success rate: {success_rate:.1f}% of emails with DKIM")
        
        report_lines.append("")
        
        # Key database details
        if (self.verbose or output_file) and self.key_database:
            report_lines.append("KEY DATABASE DETAILS:")
            report_lines.append("-" * 40)
            for cache_key, key_info in sorted(self.key_database.items()):
                report_lines.append(f"Key: {cache_key}")
                report_lines.append(f"  DNS Query: {key_info['dns_query']}")
                report_lines.append(f"  Status: {key_info['status']}")
                report_lines.append(f"  Retrieved: {key_info['retrieved'][:19]}")
                report_lines.append(f"  Used by {len(key_info['used_by_files'])} files")
                roles = key_info.get('roles') or ['dkim']
                report_lines.append(f"  Roles: {', '.join(roles)}")
                if key_info.get('parsed_key', {}).get('k'):
                    report_lines.append(f"  Key type: {key_info['parsed_key']['k']}")
                if key_info['status'] != 'success':
                    report_lines.append(f"  Issue: {key_info['status']}")
                report_lines.append("")
        
        # Detailed results
        if self.verbose or output_file:
            report_lines.append("DETAILED RESULTS:")
            report_lines.append("-" * 40)
            
            for result in self.results:
                report_lines.append(f"File: {result['file']}")
                report_lines.append(f"Status: {result['overall_status'].upper()}")
                
                if result['dkim_signatures']:
                    report_lines.append(f"DKIM signatures found: {len(result['dkim_signatures'])}")
                    
                    for sig in result['dkim_signatures']:
                        report_lines.append(f"  Signature {sig['index']}: domain={sig['domain']}, selector={sig['selector']}")
                    
                    for verification in result['verification_details']:
                        status = "✓ VALID" if verification['valid'] else "✗ INVALID"
                        report_lines.append(f"  Verification {verification['signature_index']}: {status}")
                        report_lines.append(f"    Domain: {verification.get('domain', 'unknown')}")
                        report_lines.append(f"    Method: {verification['method']}")
                        report_lines.append(f"    Result: {verification['message']}")
                
                # ARC detail — always rendered, since ARC runs on every email
                arc = result.get('arc') or {}
                if arc:
                    eff = arc.get('effective_status', 'error')
                    cv = arc.get('cv', 'error')
                    headline_tail = {
                        'pass':    'full chain validates',
                        'partial': 'seal chain valid, body integrity not provable',
                        'fail':    'chain broken',
                        'none':    'no ARC headers',
                        'error':   'verification error',
                    }.get(eff, '')
                    report_lines.append(f"ARC: {eff.upper()} — {headline_tail} (cv={cv})")
                    if arc.get('reason') and eff != 'pass':
                        report_lines.append(f"  Reason: {arc['reason']}")

                    for claim in arc.get('trusted_assertions', []):
                        report_lines.append(
                            f"  Trusted assertion (signed by {claim['signer']}, i={claim['instance']}): "
                            f"{claim['claim']}"
                        )

                    for inst in arc.get('instances', []):
                        report_lines.append(
                            f"  i={inst.get('instance')}: "
                            f"AS={inst.get('as_domain')}/{inst.get('as_selector')} "
                            f"valid={inst.get('as_valid')}, "
                            f"AMS={inst.get('ams_domain')}/{inst.get('ams_selector')} "
                            f"valid={inst.get('ams_valid')}, "
                            f"cv={inst.get('cv')}"
                        )

                # Microsoft fix detail
                msoft = result.get('msoft_fix')
                if msoft:
                    if msoft.get('succeeded'):
                        report_lines.append(f"Microsoft fix: SUCCESS — {msoft['message']}")
                    elif msoft.get('skipped_reason'):
                        report_lines.append(f"Microsoft fix: SKIPPED — {msoft['skipped_reason']}")
                    else:
                        report_lines.append(f"Microsoft fix: FAILED — {msoft['message']}")
                    if msoft.get('phases_attempted'):
                        report_lines.append(f"  Phases tried: {', '.join(msoft['phases_attempted'])}")
                    for t in msoft.get('transformations_applied', []):
                        report_lines.append(f"  Applied: {t}")

                if result['authentication_results']:
                    report_lines.append("Authentication-Results headers found:")
                    for auth in result['authentication_results']:
                        report_lines.append(f"  {auth[:100]}...")

                # Structure analysis
                if result['structure_analysis']:
                    analysis = result['structure_analysis']
                    report_lines.append("Email Structure Analysis:")
                    report_lines.append(f"  Line endings: {analysis['line_endings']}")
                    
                    if analysis.get('gmail_headers_removed'):
                        report_lines.append(f"  Gmail headers removed: {analysis['bytes_removed']} bytes")
                    
                    if analysis['has_extra_headers']:
                        report_lines.append(f"  Extra headers found: {len(analysis['extra_headers'])}")
                        for header in analysis['extra_headers'][:3]:  # Show first 3
                            report_lines.append(f"    {header}")
                        if len(analysis['extra_headers']) > 3:
                            report_lines.append(f"    ... and {len(analysis['extra_headers']) - 3} more")
                
                if 'error' in result:
                    report_lines.append(f"Error: {result['error']}")
                
                report_lines.append("")
        
        # Common issues analysis
        if self.results:
            line_ending_stats = {}
            extra_header_count = 0
            gmail_cleaned_count = 0
            total_bytes_removed = 0
            
            for result in self.results:
                analysis = result.get('structure_analysis', {})
                line_ending = analysis.get('line_endings', 'unknown')
                line_ending_stats[line_ending] = line_ending_stats.get(line_ending, 0) + 1
                
                if analysis.get('has_extra_headers'):
                    extra_header_count += 1
                    
                if analysis.get('gmail_headers_removed'):
                    gmail_cleaned_count += 1
                    total_bytes_removed += analysis.get('bytes_removed', 0)
            
            report_lines.append("COMMON ISSUES DETECTED:")
            report_lines.append("-" * 40)
            report_lines.append("Line ending distribution:")
            for ending, count in line_ending_stats.items():
                percentage = (count / len(self.results)) * 100
                report_lines.append(f"  {ending}: {count} files ({percentage:.1f}%)")
            
            if gmail_cleaned_count > 0:
                percentage = (gmail_cleaned_count / len(self.results)) * 100
                avg_bytes = total_bytes_removed / gmail_cleaned_count if gmail_cleaned_count > 0 else 0
                report_lines.append(f"Gmail headers cleaned: {gmail_cleaned_count} files ({percentage:.1f}%)")
                report_lines.append(f"  Average bytes removed: {avg_bytes:.0f}")
            
            if extra_header_count > 0:
                percentage = (extra_header_count / len(self.results)) * 100
                report_lines.append(f"Files with remaining extra headers: {extra_header_count} ({percentage:.1f}%)")
            
            report_lines.append("")
            
            # Recommendations
            report_lines.append("RECOMMENDATIONS:")
            report_lines.append("-" * 40)
            if gmail_cleaned_count > 0:
                report_lines.append("✓ Gmail export headers automatically cleaned")
            if line_ending_stats.get('mixed', 0) > 0 or line_ending_stats.get('CRLF', 0) > 0:
                report_lines.append("• Line ending issues detected - consider using 'dos2unix' or checking mbox extraction")
            if extra_header_count > 0:
                report_lines.append("• Extra headers still detected after cleaning")
            if self.stats['valid_dkim'] > self.stats['invalid_dkim']:
                report_lines.append("✓ Good DKIM verification rate - Gmail header cleaning appears successful")
            elif self.stats['invalid_dkim'] > self.stats['valid_dkim'] and gmail_cleaned_count > 0:
                report_lines.append("• DKIM failures persist after Gmail header cleaning - may be key expiration or other issues")
            report_lines.append("")
        
        # Statistics by domain
        if self.results:
            domain_stats = {}
            for result in self.results:
                for sig in result.get('dkim_signatures', []):
                    domain = sig['domain']
                    if domain not in domain_stats:
                        domain_stats[domain] = {'total': 0, 'valid': 0}
                    domain_stats[domain]['total'] += 1
                    
                    # Check if this signature was valid
                    for verification in result.get('verification_details', []):
                        if (verification['signature_index'] == sig['index'] and 
                            verification.get('domain') == domain and verification['valid']):
                            domain_stats[domain]['valid'] += 1
                            break
            
            # Enhance per-domain stats: count fix-recovered emails for the
            # signing domain so the percentages reflect *effective* DKIM
            # verifiability (natural + recovered).
            if self.attempt_fix:
                for result in self.results:
                    msoft = result.get('msoft_fix') or {}
                    if not msoft.get('succeeded'):
                        continue
                    for sig in result.get('dkim_signatures', []):
                        domain = sig['domain']
                        if domain in domain_stats:
                            domain_stats[domain].setdefault('fixed', 0)
                            domain_stats[domain]['fixed'] += 1

            if domain_stats:
                header = "DKIM STATISTICS BY DOMAIN"
                if self.attempt_fix:
                    header += " (includes fix recoveries)"
                header += ":"
                report_lines.append(header)
                report_lines.append("-" * 40)
                for domain, stats in sorted(domain_stats.items()):
                    fixed = stats.get('fixed', 0)
                    effective_valid = stats['valid'] + fixed
                    rate = (effective_valid / stats['total']) * 100 if stats['total'] > 0 else 0
                    suffix = f"  [{fixed} via fix]" if fixed else ""
                    report_lines.append(
                        f"{domain}: {effective_valid}/{stats['total']} ({rate:.1f}%){suffix}"
                    )
                report_lines.append("")

        # Final bottom-line summary — last thing the user sees so the headline
        # numbers are visible without sifting through the verbose detail above.
        total = self.stats['total_files']
        if total > 0:
            natural_valid = self.stats['valid_dkim']
            fix_recovered = (
                self.stats['msoft_fix_succeeded_phase1']
                + self.stats['msoft_fix_succeeded_phase2']
            )
            no_dkim = self.stats['no_dkim']

            def pct(n):
                return f"{(n / total) * 100:.1f}%"

            report_lines.append("=" * 60)
            report_lines.append("OVERALL VERIFICATION SUMMARY")
            report_lines.append("=" * 60)
            if self.attempt_fix:
                total_verifiable = natural_valid + fix_recovered
                remaining_failed = self.stats['invalid_dkim'] - fix_recovered
                report_lines.append(f"DKIM verified naturally (no fix needed): {natural_valid:>4} / {total} ({pct(natural_valid)})")
                report_lines.append(f"DKIM verified after fix:                 {fix_recovered:>4} / {total} ({pct(fix_recovered)})")
                if no_dkim:
                    report_lines.append(f"No DKIM signature present:               {no_dkim:>4} / {total} ({pct(no_dkim)})")
                report_lines.append("-" * 60)
                report_lines.append(f"Total DKIM-verifiable:                   {total_verifiable:>4} / {total} ({pct(total_verifiable)})")
                report_lines.append(f"Could not be verified or fixed:          {remaining_failed:>4} / {total} ({pct(remaining_failed)})")
            else:
                invalid = self.stats['invalid_dkim']
                report_lines.append(f"DKIM verified:                           {natural_valid:>4} / {total} ({pct(natural_valid)})")
                if no_dkim:
                    report_lines.append(f"No DKIM signature present:               {no_dkim:>4} / {total} ({pct(no_dkim)})")
                report_lines.append(f"DKIM failed:                             {invalid:>4} / {total} ({pct(invalid)})")
                if invalid:
                    report_lines.append("")
                    report_lines.append("(Tip: try --attempt-fix to reverse known intermediary body mutations.)")
            report_lines.append("")

        # Print to console
        for line in report_lines:
            print(line)
        
        # Write to file if specified
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(report_lines))
            print(f"Report saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Verify DKIM signatures in extracted .eml files')
    parser.add_argument('directory', help='Directory containing .eml files')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--output', '-o', help='Output report to file')
    parser.add_argument('--key-database', default='./key-database.json',
                        help='JSON file to cache DKIM keys. Always active; defaults to '
                             './key-database.json in the current directory. Created on '
                             'first save if it does not exist. On save, any existing file '
                             'is rotated to <path>.bak (overwriting any prior .bak).')
    parser.add_argument('--single-file', help='Verify single .eml file (for testing)')
    parser.add_argument('--attempt-fix', action='store_true',
                        help='When DKIM fails, try to reverse known intermediary body '
                             'mutations and write <name>.fixed.eml alongside the original '
                             'if the reconstructed body matches the signed bh=. Currently '
                             "reverses Microsoft Exchange Online's <meta> injection (Phase "
                             '1 raw-byte strip for non-QP HTML, Phase 2 QP-aware '
                             'decode/strip/re-encode for QP-encoded HTML, plus HTML entity '
                             "reversals like &nbsp; → U+00A0). A .fixed.eml is only ever "
                             'written when the body hashes byte-exactly to the signed bh=.')
    parser.add_argument('--replace', '-r', action='store_true',
                        help='With --attempt-fix: replace the original .eml file in place '
                             'with the reconstructed bytes instead of writing a separate '
                             '<name>.fixed.eml sidecar. Only acts when reconstruction '
                             'succeeds (DKIM bh= match + full DKIM verify). DESTRUCTIVE: '
                             'the Microsoft-mutated copy on disk is overwritten by the '
                             'bit-exact original signed body. Requires --attempt-fix.')
    parser.add_argument('--offline-only', action='store_true',
                        help='Never perform DNS lookups. Verify only against keys already '
                             'in --key-database. Per-signature failures are categorized as '
                             'NO-DOMAIN (no candidate key for the signing domain), NO-KEY '
                             '(have keys for the domain but not for this selector), or '
                             'KEY-MATCHED-VERIFY-FAILED (key in cache but signature failed; '
                             'usually indicates body was altered after signing).')
    parser.add_argument('--overwrite-keys', action='store_true',
                        help='Allow overwriting existing keys in --key-database with '
                             'fresh DNS results. Off by default (key data is preserved '
                             'once stored, since it may no longer be retrievable). With '
                             'this flag, DNS is queried even when a usable cached key '
                             'exists, and the cached entry is replaced. Incompatible '
                             'with --offline-only.')

    args = parser.parse_args()
    if args.replace and not args.attempt_fix:
        parser.error('--replace requires --attempt-fix')
    if args.offline_only and args.overwrite_keys:
        parser.error('--offline-only and --overwrite-keys are incompatible '
                     '(one says "no DNS", the other says "DNS and replace")')
    
    # Check dependencies
    if not DKIM_AVAILABLE:
        print("Warning: dkimpy library not available. Using simplified verification.")
        print("For full DKIM verification, install with: pip install dkimpy dnspython")
        print()
    
    # Run verification
    verifier = DKIMVerifier(
        verbose=args.verbose,
        key_database_file=args.key_database,
        attempt_fix=args.attempt_fix,
        replace_original=args.replace,
        offline_only=args.offline_only,
        overwrite_keys=args.overwrite_keys,
    )
    try:
        if args.single_file:
            # Verify single file for testing
            result = verifier.verify_email_file(Path(args.single_file))
            verifier.results = [result]
            verifier.stats['total_files'] = 1
            if result['overall_status'] == 'has_dkim' or result['overall_status'] == 'valid_dkim':
                verifier.stats['emails_with_dkim'] = 1
            if result['overall_status'] == 'valid_dkim':
                verifier.stats['valid_dkim'] = 1
            elif result['overall_status'] == 'invalid_dkim':
                verifier.stats['invalid_dkim'] = 1
        else:
            verifier.scan_directory(args.directory)
        
        verifier.print_report(args.output)
        
        # Save key database if specified
        if args.key_database:
            verifier.save_key_database()
        
        # If high failure rate, suggest manual extraction test
        if (verifier.stats['invalid_dkim'] > verifier.stats['valid_dkim'] and 
            verifier.stats['emails_with_dkim'] > 5):
            print("\n" + "="*60)
            print("HIGH DKIM FAILURE RATE DETECTED!")
            print("="*60)
            print("This likely indicates extraction issues. To test:")
            print("1. Manually extract one email from your original mbox:")
            print("   formail -1 < your.mbox > test_manual.eml")
            print("2. Test this single file:")
            print(f"   python {sys.argv[0]} --single-file test_manual.eml --verbose")
            print("3. Compare results to identify extraction issues")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()