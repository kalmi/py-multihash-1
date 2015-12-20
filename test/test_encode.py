# coding: utf-8
import multihash


def test_encode_sha1():
    mh = multihash.MultiHash('sha1', b'a', 1)
    assert mh.encode() == b'\x11\x01a'


def test_encode_sha1_nolen():
    mh = multihash.MultiHash('sha1', b'a')
    assert mh.encode() == b'\x11\x01a'


def test_encode_sha1_utf8():
    digest = u'💻'.encode('utf-8')
    mh = multihash.MultiHash('sha1', digest)
    encoded = mh.encode()
    assert encoded == b'\x11\x04\xf0\x9f\x92\xbb'
    assert multihash.decode(encoded).digest == digest
