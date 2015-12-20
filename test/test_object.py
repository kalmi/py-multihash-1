import pytest
import multihash


@pytest.mark.parametrize('args,exception', (
    (('frob-35', b'a'), multihash.exceptions.UnknownCode),
    (('sha1', b'a', 100), multihash.exceptions.InconsistentLen),
    (('sha1', b'a' * 200, 200), multihash.exceptions.LenNotSupported),
    (('sha1', b'a' * 200), multihash.exceptions.LenNotSupported),
))
def test_decode_raises(args, exception):
    with pytest.raises(exception):
        multihash.MultiHash(*args)


def test_object_eq():
    a = multihash.MultiHash('sha1', b'a')
    b = multihash.MultiHash('sha1', b'a')
    assert a == b


def test_object_neq():
    a = multihash.MultiHash('sha1', b'a')
    b = multihash.MultiHash('sha1', b'b')
    assert a != b
