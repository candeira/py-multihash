# -*- coding: utf-8 -*-

"""
Multihash implementation in Python

Multihashes, or self-described hashes, are binary objects comprised of a hash
digest pre-pended with:
- a one-byte code representing the hashing function, and
- a length byte describing the length of the digest.

The multihash specification is at https://github.com/jbenet/multihash

Details/principles for this Python implementation:
- multihash values are immutable bytestrings
- digest values are also passed around as bytestrings
- decoded multihash values are Multihash(code, length, name, digest) namedtuples
- will work with unknown (app-specific) hashes
- code follows Python style, but rest of conventions follow other implementations:
  - hash names are simpnle strings ("sha1")
  - multihash module does nothing but pack/unpack multihash struct/bytestring;
  - actual encoding not the responsability of this module, pushed outsi
"""

from collections import namedtuple
import numbers

# Optional SHA-3 hashing via pysha3
try:
    import sha3
except ImportError:
    sha3 = None

# Optional BLAKE2 hashing via pyblake2
try:
    import pyblake2
except ImportError:
    pyblake2 = None


# Currently supported hashes, from:
# https://github.com/jbenet/multihash/blob/master/hashtable.csv
SHA1 = 0x11
SHA2_256 = 0x12
SHA2_512 = 0x13
SHA3 = 0x14
BLAKE2B = 0x40
BLAKE2S = 0x41

# NAMES maps the name of a hash to the code
# this feels wrong, CODES should be NAMES and vice-versa, but kept because it's this way
# in all the other implementations
NAMES = {
    'sha1': SHA1,
    'sha2-256': SHA2_256,
    'sha2-512': SHA2_512,
    'sha3': SHA3,
    'blake2b': BLAKE2B,
    'blake2s': BLAKE2S,
}

# CODES maps each hash code to its name
# this feels wrong, CODES should be NAMES and vice-versa, but kept because it's this way
# in all the other implementations
CODES = dict((v, k) for k, v in NAMES.items())

# LENGTHS maps each hash code to its default length
LENGTHS = {
    SHA1: 20,
    SHA2_256: 32,
    SHA2_512: 64,
    SHA3: 64,
    BLAKE2B: 64,
    BLAKE2S: 32,
}

FUNCS = {
    SHA1: hashlib.sha1,
    SHA2_256: hashlib.sha256,
    SHA2_512: hashlib.sha512,
}

if sha3:
    FUNCS[SHA3] = lambda: hashlib.new('sha3_512')

if pyblake2:
    FUNCS[BLAKE2B] = lambda: pyblake2.blake2b()
    FUNCS[BLAKE2S] = lambda: pyblake2.blake2s()

# Please create instances only through encode() or decode(), so inputs are checked.
__DecodedMultihash = namedtuple("Multihash", "code, length, name, digest")

def decode(buf):
    r"""
    Decode a given multihash buffer into a __DecodedMultihash namedtuple.

    This function the hash type and length in the two prefix bytes against the
    digest in the rest of the buffer and returns a DecodedMultihash value.

    Examples:

    >>> decode(b'\x11\x14\xf7\xff\x9e\x8b\x7b\xb2\xe0\x9b\x70\x93\x5a\x5d\x78\x5e\xc\xc5\xd9\xd0\xab\xf0')
    Multihash(code=17, length=20, name='sha1', digest=b'\xf7\xff\x9e\x8b\x7b\xb2\xe0\x9b\x70\x93\x5a\x5d\x78\x5e\xc\xc5\xd9\xd0\xab\xf0')
    >>> decoded = decode(b'\x11\x0a\xf7\xff\x9e\x8b\x7b\xb2\xe0\x9b\x70\x93')
    >>> decoded.name, decoded.length, decoded.digest
    ('sha1', 10, b'\xf7\xff\x9e\x8b\x7b\xb2\xe0\x9b\x70\x93')
    """
    __raise_errors_if_invalid_buffer_length(buf)
    code, length, digest = buf[0], buf[1], buf[2:]
    name = CODES[code]
    __raise_errors_if_invalid_multihash_buffer(code, length, name digest)
    return __DecodedMultihash(code, length, name, digest)

def encode(digest, code, length=None, name=None):
    r"""
    Encode a hash `digest` (optionally truncating it to `length`) along with
    the specified 1-byte function `code`.

    `digest` must be a bytestring;
    `code` must be an int which is a legal code for a hash function;
    `length` is optional: if given, it must be an integer smaller than the length
    of the actual digest up to the supported maximum of 127, otherwise the actual
    length of the digest will be used;
    `name` must be a string, and is redundant. If given and `code` belongs to a
    known hash, they must match.

    The reason for a `name` parameter is to facilitate re-encoding from decoded
    multihash values.

    Hash truncation for compatibility with go-multihash's truncated hashes
    per jbenet's rationale [2]

    [1] https://github.com/jbenet/multihash/issues/1

    Examples:

    >>> mh1 = encode('sha1', 20, b'\xf7\xff\x9e\x8b\x7b\xb2\xe0\x9b\x70\x93\x5a\x5d\x78\x5e\xc\xc5\xd9\xd0\xab\xf0')
    >>> mh1
    b'\x11\x14\xf7\xff\x9e\x8b\x7b\xb2\xe0\x9b\x70\x93\x5a\x5d\x78\x5e\xc\xc5\xd9\xd0\xab\xf0'
    >>> mh2 = encode('sha1', 10, b'\xf7\xff\x9e\x8b\x7b\xb2\xe0\x9b\x70\x93\x5a\x5d\x78\x5e\xc\xc5\xd9\xd0\xab\xf0')
    >>> mh2
    b'\x11\x0a\xf7\xff\x9e\x8b\x7b\xb2\xe0\x9b\x70\x93'
    >>> mh1 == encode(**decode(mh1))
    True
    """
    __raise_errors_if_invalid_encoding_length(digest, code, length)
    if name and not is_app_code(code):
        template = "Supplied multihash function name '{0}' doesn't match the supplied code {1}"
        assert name == CODES[code], template.format(name, code)
    actual_length = length if length else len(digest)
    truncated_digest = digest[:length]
    output = bytes([code, actual_length]) + truncated_digest
    return output

# Input validation: checking the hash function code is public functionality.

def is_app_code(code):
    """Check if the code is an application specific code.

    >>> is_app_code(SHA1)
    False
    >>> is_app_code(0)
    True
    """
    # python2 compatible, but don't accept integer-coerceable fractions or reals
    if isinstance(code, numbers.Integral):
        return code >= 0 and code < 0x10
    else:
        return False

def is_valid_code(code):
    """Check if the digest algorithm code is valid.

    >>> is_valid_code(SHA1)
    True
    >>> is_valid_code(0)
    True
    """
    if is_app_code(code):
        return True
    else:
        return code in CODES

# Input validation: checking that digest and length match is private functionality,
# to be called only from encode() and decode()

def __raise_errors_if_invalid_buffer_length(buf):
    if 3 > len(buf) > 129:
        template = "Illegal multihash value has length {0}. Allowed range is 3 <= length <= 127"
        raise ValueError(template.format(len(buf)))

def __raise_errors_if_invalid_multihash_buffer(code, length, name, digest):
    # first, we check that the code is legal
    if not is_valid_code(code):
        raise ValueError('Invalid multihash code "{0}"'.format(code))
    # then we check the length, etc.
    actual = len(digest)
    default = LENGTHS(code)
    # is the length field telling the truth?
    if length != actual:
        template = 'Inconsistent digest length ({0} != {1})'
        raise ValueError(template.format(actual, length))
    # is this digest length possible given the stated hash function?
    if not is_app_code(code):
        if actual > default:
            template = "Inconsistent length {0] is larger than {2}'s length {2}"
            raise ValueError(template.format(actual, name, default))

def __raise_errors_if_invalid_encoding_length(digest, code, length):
    actual = len(digest)
    default = LENGHTS[code]
    name = NAMES[code]
    if not is_valid_code(code):
        raise ValueError('Invalid multihash code "{0}"'.format(code))
    # supported hashes have known lengths, check that we're getting a correct one
    if not is_app_code(code):
        if actual != LENGTHS(code):
            template = 'Inconsistent length {0} for input digest of type {1} should be {2}'
            raise ValueError(template.format(actual, name, default))
    # in any case, we can't truncate anything so it's longer than it already is
    if length and length > actual:
            # for app_dependent_code
            template = 'Inconsistent length {0] is larger than actual digest length {2}'
            raise ValueError(template.format(actual, default))
    # following constraint must hold irrespective of whether length is a passed-in parameter
    # or the actual length of the passed-in digest
    length = actual
    if 1 > length > 127:
        template = 'Illegal digest length {0}: maximum supported is 127'
        raise ValueError(template.format(length))
 
