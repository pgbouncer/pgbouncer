#! /usr/bin/env python3

"""Generate x509 keys and certs.
"""

from cryptography import x509

import ipaddress
import datetime
import uuid


#
# CA utilities
#

def set_string_mask(mask):
    """Set default string format in certs.

    utf8only - as name says
    default - anything: usually printable, t61, bmp or utf8 according to data.
    pkix - "default" without t61
    nombstr - "default" without bmp and utf8
    MASK:<int> - bitmask as integer
    """
    if isinstance(mask, str):
        mask = mask.encode('utf8')
    from cryptography.hazmat.backends.openssl import backend
    backend._lib.ASN1_STRING_set_default_mask_asc(mask)


def get_backend():
    from cryptography.hazmat.backends import default_backend
    return default_backend()


def new_key(keydesc):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    t, v = keydesc.split(':')
    if t == 'ec':
        curve = getattr(ec, v.upper())
        return ec.generate_private_key(curve=curve, backend=get_backend())
    elif t == 'rsa':
        return rsa.generate_private_key(key_size=int(v), public_exponent=65537, backend=get_backend())
    else:
        raise Exception('Bad key type')


def _load_name(vals):
    from cryptography.x509.oid import NameOID

    name_map = {
        'CN': NameOID.COMMON_NAME,
        'C': NameOID.COUNTRY_NAME,
        'L': NameOID.LOCALITY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'serial': NameOID.SERIAL_NUMBER,
        'SN': NameOID.SURNAME,
        'GN': NameOID.GIVEN_NAME,
        'T': NameOID.TITLE,
        'GQ': NameOID.GENERATION_QUALIFIER,
        'DQ': NameOID.DN_QUALIFIER,
        'P': NameOID.PSEUDONYM,
        'DC': NameOID.DOMAIN_COMPONENT,
        'E': NameOID.EMAIL_ADDRESS,
    }

    attlist = []
    for r in vals:
        k, v = r.split('=', 1)
        oid = name_map[k]
        n = x509.NameAttribute(oid, v)
        attlist.append(n)
    return x509.Name(attlist)


def _load_alt_names(alt_names):
    from cryptography.x509.general_name import RFC822Name, DNSName, IPAddress, UniformResourceIdentifier, RegisteredID

    gnames = []
    for alt in alt_names:
        t, val = alt.split(':', 1)
        if t == '822':
            gn = RFC822Name(val)
        elif t == 'dns':
            gn = DNSName(val)
        elif t == 'ip4':
            gn = IPAddress(ipaddress.IPv4Address(val))
        elif t == 'ip6':
            gn = IPAddress(ipaddress.IPv6Address(val))
        elif t == 'i4n':
            gn = IPAddress(ipaddress.IPv4Network(val))
        elif t == 'i6n':
            gn = IPAddress(ipaddress.IPv6Network(val))
        elif t == 'uri':
            gn = UniformResourceIdentifier(val)
        elif t == 'rid':
            gn = RegisteredID(val)
        else:
            raise Exception('Invalid altname: '+alt)
        gnames.append(gn)
    return x509.SubjectAlternativeName(gnames)


# why no defaults?
def _wrapKeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                  data_encipherment=False, key_agreement=False, key_cert_sign=False,
                  crl_sign=False, encipher_only=False,  decipher_only=False):
    return x509.KeyUsage(digital_signature=digital_signature,
                         content_commitment=content_commitment,
                         key_encipherment=key_encipherment,
                         data_encipherment=data_encipherment,
                         key_agreement=key_agreement,
                         key_cert_sign=key_cert_sign,
                         crl_sign=crl_sign,
                         encipher_only=encipher_only,
                         decipher_only=decipher_only)


def x509_sign(privkey, pubkey, subject, issuer, ca=False, alt_names=None, usage=None):
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID
    import hashlib

    dt_start = datetime.datetime(2010, 1, 1, 8, 5, 0)
    dt_end = datetime.datetime(2060, 12, 31, 23, 55)
    #serial = int(uuid.uuid4())
    serial = int(hashlib.sha1(subject[0].encode("utf8")).hexdigest(), 16) // 2

    builder = (x509.CertificateBuilder()
               .subject_name(_load_name(subject))
               .issuer_name(_load_name(issuer))
               .not_valid_before(dt_start)
               .not_valid_after(dt_end)
               .serial_number(serial)
               .public_key(pubkey))

    # BasicConstraints, critical
    if ca:
        ext = x509.BasicConstraints(ca=True, path_length=1)
    else:
        ext = x509.BasicConstraints(ca=False, path_length=None)
    builder = builder.add_extension(ext, critical=True)

    # KeyUsage, critical
    if ca:
        ext = _wrapKeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True)
    else:
        ext = _wrapKeyUsage(digital_signature=True, key_encipherment=True)
    builder = builder.add_extension(ext, critical=True)

    # ExtendedKeyUsage
    if not usage and ca:
        usage = ['client', 'server']
    if usage:
        usage_map = {
            'server': ExtendedKeyUsageOID.SERVER_AUTH,
            'client': ExtendedKeyUsageOID.CLIENT_AUTH,
            'code': ExtendedKeyUsageOID.CODE_SIGNING,
            'email': ExtendedKeyUsageOID.EMAIL_PROTECTION,
            'time': ExtendedKeyUsageOID.TIME_STAMPING,
            'ocsp': ExtendedKeyUsageOID.OCSP_SIGNING,
        }
        xlist = [usage_map[x] for x in usage]
        ext = x509.ExtendedKeyUsage(xlist)
        builder = builder.add_extension(ext, critical=False)

    # SubjectKeyIdentifier
    ext = x509.SubjectKeyIdentifier.from_public_key(pubkey)
    builder = builder.add_extension(ext, critical=False)

    # AuthorityKeyIdentifier
    ext = x509.AuthorityKeyIdentifier.from_issuer_public_key(privkey.public_key())
    builder = builder.add_extension(ext, critical=False)

    # SubjectAlternativeName
    if alt_names:
        ext = _load_alt_names(alt_names)
        builder = builder.add_extension(ext, critical=False)

    # final cert
    cert = builder.sign(private_key=privkey, algorithm=hashes.SHA256(), backend=get_backend())
    return cert


class Base:
    def write_key(self, fn):
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

        data = self.key.private_bytes(encoding=Encoding.PEM,
                                      format=PrivateFormat.TraditionalOpenSSL,
                                      encryption_algorithm=NoEncryption())
        with open(fn, 'wb') as f:
            f.write(data)

    def write_cert(self, fn):
        from cryptography.hazmat.primitives.serialization import Encoding

        data = self.cert.public_bytes(Encoding.PEM)
        with open(fn, 'wb') as f:
            f.write(data)

    def write_fp(self, pfx):
        from cryptography.hazmat.primitives import hashes

        h_sha1 = self.cert.fingerprint(hashes.SHA1())
        open(pfx+'.sha1', 'w').write(h_sha1.hex())

        h_sha256 = self.cert.fingerprint(hashes.SHA256())
        open(pfx+'.sha256', 'w').write(h_sha256.hex())

    def write(self, pfx):
        self.write_key(pfx+'.key')
        self.write_cert(pfx+'.crt')
        self.write_fp(pfx+'.crt')


class CA(Base):
    def __init__(self, keydesc, name, master_ca=None, usage=None):
        self.key = new_key(keydesc)
        self.name = name
        if master_ca:
            self.cert = master_ca.sign(self.key.public_key(), name, ca=True, usage=usage)
        else:
            self.cert = x509_sign(self.key, self.key.public_key(), name, name, ca=True, usage=usage)

    def sign(self, pubkey, subject_name, alt_names=None, ca=False, usage=None):
        return x509_sign(self.key, pubkey, subject_name, self.name, ca=ca, alt_names=alt_names, usage=usage)


class Leaf(Base):
    def __init__(self, master_ca, keydesc, name, alt_names=None, usage=None):
        self.key = new_key(keydesc)
        self.name = name
        self.cert = master_ca.sign(self.key.public_key(), name, alt_names=alt_names, usage=usage)


#
# CA1 - EC keys
#

set_string_mask("utf8only")

ca1 = CA('ec:secp384r1', ['CN=TestCA1', 'C=AA', 'L=City1', 'ST=State1', 'O=Org1'])
ca1.write('ca1_root')

server1 = Leaf(ca1, 'ec:secp384r1', ['CN=server1.com'], ['dns:server1.com', 'dns:www.server1.com'], usage=['server'])
server1.write('ca1_server1')

client1 = Leaf(ca1, 'ec:secp192r1', ['CN=client1'], ['822:client@company.com'], usage=['client'])
client1.write('ca1_client1')

complex1 = Leaf(ca1, 'ec:secp384r1',
                name=['CN=complex1.com', 'L=Kõzzä', 'ST=様々な論争を引き起こしてきた。'],
                #name=['CN=complex1.com', 'C=QQ', 'L=Loc1', 'ST=Foo', 'O=Aorg2', 'OU=Unit1'],
                alt_names=['dns:complex1.com', 'dns:www.complex1.com',
                           'ip4:127.0.0.1', 'ip6:fffe::1',
                           #'i4n:192.168.1.0/24', 'i6n:::1/128',
                           'uri:http://localhost/',
                           '822:fooxa@example.com'],
                usage=['server'])
complex1.write('ca1_complex1')

set_string_mask("utf8only")


#
# CA2 - RSA keys
#

ca2 = CA('rsa:2048', ['CN=TestCA2'])
ca2.write('ca2_root')

server2 = Leaf(ca2, 'rsa:2048', ['CN=server2.com'], ['dns:server2.com', 'dns:www.server2.com'], usage=['server'])
server2.write('ca2_server2')

client2 = Leaf(ca2, 'rsa:2048',
               name=['CN=client2', 'C=XX', 'L=City2', 'ST=State2', 'O=Org2'],
               alt_names=['822:client2@company.com'],
               usage=['client'])
client2.write('ca2_client2')

# create cert with old string types
set_string_mask("default")
complex2 = Leaf(ca2, 'rsa:4096',
                name=['CN=complex2.com', 'L=Kõzzä', 'ST=様々な論争を引き起こしてきた。'],
                alt_names=['dns:complex2.com', 'dns:www.complex2.com',
                           'ip4:127.0.0.1', 'ip6:fffe::1',
                           'uri:http://localhost/',
                           '822:fooxa@example.com'],
                usage=['server'])
complex2.write('ca2_complex2')
set_string_mask("utf8only")
