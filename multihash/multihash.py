import collections
import struct
import six
from . import exceptions as exc
from . import constants


def ensure_byteness(digest):
    # Note: py3's bytes type is basically py2's str type.
    if six.PY3 and not isinstance(digest, bytes):
        raise ValueError("Input must be of type bytes in Python 3.x")
    if six.PY2 and not isinstance(digest, str):
        raise ValueError("Input must be of type str in Python 2.x")

def ident_name_code(ident):
    'Coerce hash ident (name or code) to tuple (name, code)'
    if ident in constants.CODES:
        return constants.CODES[ident], ident
    if ident in constants.NAMES:
        return ident, constants.NAMES[ident]
    raise exc.UnknownCode("Unknown multihash code or name: {0}".format(ident))


_MultiHash = collections.namedtuple('MultiHash', 'name code length digest')
class MultiHash(_MultiHash):  # NOQA

    def __new__(cls, ident, digest, length=None):
        ensure_byteness(digest)
        len_digest = len(digest)
        if length and len_digest != length:
            raise exc.InconsistentLen('Digest length should be equal to '
                                      'specified length.')
        if not length:
            length = len_digest
        if length > 127:
            raise exc.LenNotSupported('Multihash does not yet support digests '
                                      'longer than 127 bytes')
        name, code = ident_name_code(ident)
        init_args = cls, name, code, length, digest
        return super(MultiHash, cls).__new__(*init_args)

    def __eq__(self, other):
        conditions = (
            self.name == other.name,
            self.code == other.code,
            self.length == other.length,
            self.digest == other.digest,
        )
        return all(conditions)

    def encode(self):
        struct_fmt = "BB{0}s".format(self.length)
        digest = self.digest
        struct_args = self.code, self.length, digest
        return struct.pack(struct_fmt, *struct_args)


def decode(mh_bytes):
    ensure_byteness(mh_bytes)
    len_mh_bytes = len(mh_bytes)
    if len_mh_bytes > 127:
        fmt_str = 'Multihash {0} bytes long. Must be < 129 bytes'
        raise exc.TooLong(fmt_str.format(len_mh_bytes))
    if len_mh_bytes < 3:
        fmt_str = 'Multihash {0} bytes long. Must be > 3 bytes'
        raise exc.TooShort(fmt_str.format(len_mh_bytes))
    len_digest = len(mh_bytes[2:])
    (code, length), digest = struct.unpack('BB', mh_bytes[:2]), mh_bytes[2:]
    if len_digest != length:
        raise exc.InconsistentLen('Digest length should be equal to specified '
                                  'length.')
    return MultiHash(code, digest, length)
