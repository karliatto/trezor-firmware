import gc
import math
from micropython import const
from typing import TYPE_CHECKING

from trezor import utils
from trezor.utils import memcpy as tmemcpy

from apps.monero.xmr import crypto, crypto_helpers
from apps.monero.xmr.serialize.int_serialize import dump_uvarint_b_into, uvarint_size

if TYPE_CHECKING:
    from typing import Iterator, TypeVar, Generic

    from .serialize_messages.tx_rsig_bulletproof import BulletproofPlus

    T = TypeVar("T")
    ScalarDst = TypeVar("ScalarDst", bytearray, crypto.Scalar)

else:
    Generic = (object,)
    T = 0  # type: ignore

# Constants
TBYTES = (bytes, bytearray, memoryview)
_BP_LOG_N = const(6)
_BP_N = const(64)  # 1 << _BP_LOG_N
_BP_M = const(16)  # maximal number of bulletproofs

_ZERO = b"\x00" * 32
_ONE = b"\x01" + b"\x00" * 31
_TWO = b"\x02" + b"\x00" * 31
_EIGHT = b"\x08" + b"\x00" * 31
_INV_EIGHT = crypto_helpers.INV_EIGHT
_MINUS_ONE = b"\xec\xd3\xf5\x5c\x1a\x63\x12\x58\xd6\x9c\xf7\xa2\xde\xf9\xde\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"

# Monero H point
_XMR_H = b"\x8b\x65\x59\x70\x15\x37\x99\xaf\x2a\xea\xdc\x9f\xf1\xad\xd0\xea\x6c\x72\x51\xd5\x41\x54\xcf\xa9\x2c\x17\x3a\x0d\xd3\x9c\x1f\x94"
_XMR_HP = crypto.xmr_H()
_XMR_G = b"\x58\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66"

_INITIAL_TRANSCRIPT = b"\x4a\x67\x7c\x90\xeb\x73\x05\x1e\x79\x0d\xa4\x55\x91\x10\x7f\x6e\xe1\x05\x90\x4d\x91\x87\xc5\xd3\x54\x71\x09\x6c\x44\x5a\x22\x75"
_TWO_SIXTY_FOUR_MINUS_ONE = b"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#
# Rct keys operations
# tmp_x are global working registers to minimize memory allocations / heap fragmentation.
# Caution has to be exercised when using the registers and operations using the registers
#

_tmp_bf_0 = bytearray(32)
_tmp_bf_1 = bytearray(32)
_tmp_bf_exp = bytearray(16 + 32 + 4)

_tmp_pt_1 = crypto.Point()
_tmp_pt_2 = crypto.Point()
_tmp_pt_3 = crypto.Point()
_tmp_pt_4 = crypto.Point()

_tmp_sc_1 = crypto.Scalar()
_tmp_sc_2 = crypto.Scalar()
_tmp_sc_3 = crypto.Scalar()
_tmp_sc_4 = crypto.Scalar()
_tmp_sc_5 = crypto.Scalar()


def _ensure_dst_key(dst: bytearray | None = None) -> bytearray:
    if dst is None:
        dst = bytearray(32)
    return dst


def memcpy(
    dst: bytearray, dst_off: int, src: bytes, src_off: int, len: int
) -> bytearray:
    if dst is not None:
        tmemcpy(dst, dst_off, src, src_off, len)
    return dst


def _copy_key(dst: bytearray | None, src: bytes) -> bytearray:
    dst = _ensure_dst_key(dst)
    for i in range(32):
        dst[i] = src[i]
    return dst


def _init_key(val: bytes, dst: bytearray | None = None) -> bytearray:
    dst = _ensure_dst_key(dst)
    return _copy_key(dst, val)


def _load_scalar(dst: crypto.Scalar | None, a: ScalarDst) -> crypto.Scalar:
    return (
        crypto.sc_copy(dst, a)
        if isinstance(a, crypto.Scalar)
        else crypto.decodeint_into_noreduce(dst, a)
    )


def _gc_iter(i: int) -> None:
    if i & 127 == 0:
        gc.collect()


def _invert(dst: bytearray | None, x: bytes) -> bytearray:
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, x)
    crypto.sc_inv_into(_tmp_sc_2, _tmp_sc_1)
    crypto.encodeint_into(dst, _tmp_sc_2)
    return dst


def _scalarmult_key(
    dst: bytearray,
    P,
    s: bytes | None,
    s_raw: int | None = None,
    tmp_pt: crypto.Point = _tmp_pt_1,
):
    # TODO: two functions based on s/s_raw ?
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(tmp_pt, P)
    if s:
        crypto.decodeint_into_noreduce(_tmp_sc_1, s)
        crypto.scalarmult_into(tmp_pt, tmp_pt, _tmp_sc_1)
    else:
        assert s_raw is not None
        crypto.scalarmult_into(tmp_pt, tmp_pt, s_raw)
    crypto.encodepoint_into(dst, tmp_pt)
    return dst


def _scalarmult8(dst: bytearray | None, P, tmp_pt: crypto.Point = _tmp_pt_1):
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(tmp_pt, P)
    crypto.ge25519_mul8(tmp_pt, tmp_pt)
    crypto.encodepoint_into(dst, tmp_pt)
    return dst


def _scalarmultH(dst: bytearray, x: bytes) -> bytearray:
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into(_tmp_sc_1, x)
    crypto.scalarmult_into(_tmp_pt_1, _XMR_HP, _tmp_sc_1)
    crypto.encodepoint_into(dst, _tmp_pt_1)
    return dst


def _scalarmult_base(dst: bytearray, x: bytes) -> bytearray:
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, x)
    crypto.scalarmult_base_into(_tmp_pt_1, _tmp_sc_1)
    crypto.encodepoint_into(dst, _tmp_pt_1)
    return dst


def _sc_gen(dst: bytearray | None = None) -> bytearray:
    dst = _ensure_dst_key(dst)
    crypto.random_scalar(_tmp_sc_1)
    crypto.encodeint_into(dst, _tmp_sc_1)
    return dst


def _sc_add(dst: bytearray | None, a: bytes, b: bytes) -> bytearray:
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.sc_add_into(_tmp_sc_3, _tmp_sc_1, _tmp_sc_2)
    crypto.encodeint_into(dst, _tmp_sc_3)
    return dst


def _sc_sub(
    dst: bytearray | None,
    a: bytes | crypto.Scalar,
    b: bytes | crypto.Scalar,
) -> bytearray:
    dst = _ensure_dst_key(dst)
    if not isinstance(a, crypto.Scalar):
        crypto.decodeint_into_noreduce(_tmp_sc_1, a)
        a = _tmp_sc_1
    if not isinstance(b, crypto.Scalar):
        crypto.decodeint_into_noreduce(_tmp_sc_2, b)
        b = _tmp_sc_2
    crypto.sc_sub_into(_tmp_sc_3, a, b)
    crypto.encodeint_into(dst, _tmp_sc_3)
    return dst


def _sc_mul(dst: bytearray | None, a: bytes, b: bytes | crypto.Scalar) -> bytearray:
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    if not isinstance(b, crypto.Scalar):
        crypto.decodeint_into_noreduce(_tmp_sc_2, b)
        b = _tmp_sc_2
    crypto.sc_mul_into(_tmp_sc_3, _tmp_sc_1, b)
    crypto.encodeint_into(dst, _tmp_sc_3)
    return dst


def _sc_mul8(dst: bytearray | None, a: bytes) -> bytearray:
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, _EIGHT)
    crypto.sc_mul_into(_tmp_sc_3, _tmp_sc_1, _tmp_sc_2)
    crypto.encodeint_into(dst, _tmp_sc_3)
    return dst


def _sc_muladd(
    dst: ScalarDst | None,
    a: bytes | crypto.Scalar,
    b: bytes | crypto.Scalar,
    c: bytes | crypto.Scalar,
) -> ScalarDst:
    if isinstance(dst, crypto.Scalar):
        dst_sc = dst
    else:
        dst_sc = _tmp_sc_4
    if not isinstance(a, crypto.Scalar):
        crypto.decodeint_into_noreduce(_tmp_sc_1, a)
        a = _tmp_sc_1
    if not isinstance(b, crypto.Scalar):
        crypto.decodeint_into_noreduce(_tmp_sc_2, b)
        b = _tmp_sc_2
    if not isinstance(c, crypto.Scalar):
        crypto.decodeint_into_noreduce(_tmp_sc_3, c)
        c = _tmp_sc_3
    crypto.sc_muladd_into(dst_sc, a, b, c)
    if not isinstance(dst, crypto.Scalar):
        dst = _ensure_dst_key(dst)
        crypto.encodeint_into(dst, dst_sc)
    return dst


def _sc_mulsub(dst: bytearray | None, a: bytes, b: bytes, c: bytes) -> bytearray:
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.decodeint_into_noreduce(_tmp_sc_3, c)
    crypto.sc_mulsub_into(_tmp_sc_4, _tmp_sc_1, _tmp_sc_2, _tmp_sc_3)
    crypto.encodeint_into(dst, _tmp_sc_4)
    return dst


def _add_keys(dst: bytearray | None, A: bytes, B: bytes) -> bytearray:
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(_tmp_pt_1, A)
    crypto.decodepoint_into(_tmp_pt_2, B)
    crypto.point_add_into(_tmp_pt_3, _tmp_pt_1, _tmp_pt_2)
    crypto.encodepoint_into(dst, _tmp_pt_3)
    return dst


def _sub_keys(dst: bytearray | None, A: bytes, B: bytes) -> bytearray:
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(_tmp_pt_1, A)
    crypto.decodepoint_into(_tmp_pt_2, B)
    crypto.point_sub_into(_tmp_pt_3, _tmp_pt_1, _tmp_pt_2)
    crypto.encodepoint_into(dst, _tmp_pt_3)
    return dst


def _add_keys2(dst: bytearray | None, a: bytes, b: bytes, B: bytes) -> bytearray:
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.decodepoint_into(_tmp_pt_1, B)
    crypto.add_keys2_into(_tmp_pt_2, _tmp_sc_1, _tmp_sc_2, _tmp_pt_1)
    crypto.encodepoint_into(dst, _tmp_pt_2)
    return dst


def _hash_to_scalar(dst, data):
    dst = _ensure_dst_key(dst)
    crypto.hash_to_scalar_into(_tmp_sc_1, data)
    crypto.encodeint_into(dst, _tmp_sc_1)
    return dst


def _hash_vct_to_scalar(dst, data):
    dst = _ensure_dst_key(dst)
    ctx = crypto_helpers.get_keccak()
    for x in data:
        ctx.update(x)
    hsh = ctx.digest()

    crypto.decodeint_into(_tmp_sc_1, hsh)
    crypto.encodeint_into(dst, _tmp_sc_1)
    return dst


def _get_exponent_plus(dst, base, idx):
    return _get_exponent_univ(dst, base, idx, b"bulletproof_plus")


def _get_exponent_univ(dst, base, idx, salt):
    dst = _ensure_dst_key(dst)
    lsalt = len(salt)
    final_size = lsalt + 32 + uvarint_size(idx)
    memcpy(_tmp_bf_exp, 0, base, 0, 32)
    memcpy(_tmp_bf_exp, 32, salt, 0, lsalt)
    dump_uvarint_b_into(idx, _tmp_bf_exp, 32 + lsalt)
    crypto.fast_hash_into(_tmp_bf_1, _tmp_bf_exp, final_size)
    crypto.hash_to_point_into(_tmp_pt_4, _tmp_bf_1)
    crypto.encodepoint_into(dst, _tmp_pt_4)
    return dst


def _sc_square_mult(
    dst: crypto.Scalar | None, x: crypto.Scalar, n: int
) -> crypto.Scalar:
    if n == 0:
        return crypto.decodeint_into_noreduce(dst, _ONE)

    lg = int(math.log(n, 2))
    dst = crypto.sc_copy(dst, x)
    for i in range(1, lg + 1):
        crypto.sc_mul_into(dst, dst, dst)
        if n & (1 << (lg - i)) > 0:
            crypto.sc_mul_into(dst, dst, x)
    return dst


def _invert_batch(x):
    scratch = _ensure_dst_keyvect(None, len(x))
    acc = bytearray(_ONE)
    for n in range(len(x)):
        utils.ensure(x[n] != _ZERO, "cannot invert zero")
        scratch[n] = acc
        if n == 0:
            memcpy(acc, 0, x[0], 0, 32)  # acc = x[0]
        else:
            _sc_mul(acc, acc, x[n])

    _invert(acc, acc)
    tmp = _ensure_dst_key(None)

    for i in range(len(x) - 1, -1, -1):
        _sc_mul(tmp, acc, x[i])
        x[i] = _sc_mul(x[i], acc, scratch[i])
        memcpy(acc, 0, tmp, 0, 32)
    return x


def _sum_of_even_powers(res, x, n):
    """
    Given a scalar, construct the sum of its powers from 2 to n (where n is a power of 2):
    Output x**2 + x**4 + x**6 + ... + x**n
    """
    utils.ensure(n & (n - 1) == 0, "n is not 2^x")
    utils.ensure(n != 0, "n == 0")

    x1 = bytearray(x)
    _sc_mul(x1, x1, x1)

    res = _ensure_dst_key(res)
    memcpy(res, 0, x1, 0, len(x1))
    while n > 2:
        _sc_muladd(res, x1, res, res)
        _sc_mul(x1, x1, x1)
        n /= 2
    return res


def _sum_of_scalar_powers(res, x, n):
    """
    Given a scalar, return the sum of its powers from 1 to n
    Output x**1 + x**2 + x**3 + ... + x**n
    """
    utils.ensure(n != 0, "n == 0")
    res = _ensure_dst_key(res)
    memcpy(res, 0, _ONE, 0, len(_ONE))

    if n == 1:
        memcpy(res, 0, x, 0, len(x))
        return res

    n += 1
    x1 = bytearray(x)
    is_power_of_2 = (n & (n - 1)) == 0
    if is_power_of_2:
        _sc_add(res, res, x1)
        while n > 2:
            _sc_mul(x1, x1, x1)
            _sc_muladd(res, x1, res, res)
            n /= 2
    else:
        prev = bytearray(x1)
        for i in range(1, n):
            if i > 1:
                _sc_mul(prev, prev, x1)
            _sc_add(res, res, prev)

    _sc_sub(res, res, _ONE)
    return res


#
# Key Vectors
#


class KeyVBase(Generic[T]):
    """
    Base KeyVector object
    """

    __slots__ = ("current_idx", "size")

    def __init__(self, elems: int = 64) -> None:
        self.current_idx = 0
        self.size = elems

    def idxize(self, idx: int) -> int:
        if idx < 0:
            idx = self.size + idx
        if idx >= self.size:
            raise IndexError(f"Index out of bounds {idx} vs {self.size}")
        return idx

    def __getitem__(self, item: int) -> T:
        raise NotImplementedError

    def __setitem__(self, key: int, value: T) -> None:
        raise NotImplementedError

    def __iter__(self) -> Iterator[T]:
        self.current_idx = 0
        return self

    def __next__(self) -> T:
        if self.current_idx >= self.size:
            raise StopIteration
        else:
            self.current_idx += 1
            return self[self.current_idx - 1]

    def __len__(self) -> int:
        return self.size

    def to(self, idx: int, buff: bytearray | None = None, offset: int = 0) -> bytearray:
        buff = _ensure_dst_key(buff)
        return memcpy(buff, offset, self.__getitem__(self.idxize(idx)), 0, 32)

    def read(self, idx: int, buff: bytes, offset: int = 0) -> bytes:
        raise NotImplementedError

    def slice(self, res, start: int, stop: int):
        for i in range(start, stop):
            res[i - start] = self[i]
        return res

    def slice_view(self, start: int, stop: int) -> "KeyVSliced":
        return KeyVSliced(self, start, stop)


_CHBITS = const(5)
_CHSIZE = const(1 << _CHBITS)


if TYPE_CHECKING:
    KeyVBaseType = KeyVBase
else:
    KeyVBaseType = (KeyVBase,)


class KeyV(KeyVBaseType[T]):
    """
    KeyVector abstraction
    Constant precomputed buffers = bytes, frozen. Same operation as normal.

    Non-constant KeyVector is separated to _CHSIZE elements chunks to avoid problems with
    the heap fragmentation. In this it is more probable that the chunks are correctly
    allocated as smaller continuous memory is required. Chunk is assumed to
    have _CHSIZE elements at all times to minimize corner cases handling. BP require either
    multiple of _CHSIZE elements vectors or less than _CHSIZE.

    Some chunk-dependent cases are not implemented as they are currently not needed in the BP.
    """

    __slots__ = ("current_idx", "size", "d", "mv", "const", "cur", "chunked")

    def __init__(
        self,
        elems: int = 64,
        buffer: bytes | None = None,
        const: bool = False,
        no_init: bool = False,
    ) -> None:
        super().__init__(elems)
        self.d: bytes | bytearray | list[bytearray] | None = None
        self.mv: memoryview | None = None
        self.const = const
        self.cur = _ensure_dst_key()
        self.chunked = False
        if no_init:
            pass
        elif buffer:
            self.d = buffer  # can be immutable (bytes)
            self.size = len(buffer) // 32
        else:
            self._set_d(elems)

        if not no_init:
            self._set_mv()

    def _set_d(self, elems: int) -> None:
        if elems > _CHSIZE and elems % _CHSIZE == 0:
            self.chunked = True
            gc.collect()
            self.d = [bytearray(32 * _CHSIZE) for _ in range(elems // _CHSIZE)]

        else:
            self.chunked = False
            gc.collect()
            self.d = bytearray(32 * elems)

    def _set_mv(self) -> None:
        if not self.chunked:
            assert isinstance(self.d, TBYTES)
            self.mv = memoryview(self.d)

    def __getitem__(self, item):
        """
        Returns corresponding 32 byte array.
        Creates new memoryview on access.
        """
        if self.chunked:
            return self.to(item)
        item = self.idxize(item)
        assert self.mv is not None
        return self.mv[item * 32 : (item + 1) * 32]

    def __setitem__(self, key, value):
        if self.chunked:
            self.read(key, value)
        if self.const:
            raise ValueError("Constant KeyV")
        ck = self[key]
        for i in range(32):
            ck[i] = value[i]

    def to(self, idx, buff: bytearray | None = None, offset: int = 0):
        idx = self.idxize(idx)
        if self.chunked:
            assert isinstance(self.d, list)
            memcpy(
                buff if buff else self.cur,
                offset,
                self.d[idx >> _CHBITS],
                (idx & (_CHSIZE - 1)) << 5,
                32,
            )
        else:
            assert isinstance(self.d, (bytes, bytearray))
            memcpy(buff if buff else self.cur, offset, self.d, idx << 5, 32)
        return buff if buff else self.cur

    def read(self, idx: int, buff: bytes, offset: int = 0) -> bytes:
        idx = self.idxize(idx)
        if self.chunked:
            assert isinstance(self.d, list)
            memcpy(self.d[idx >> _CHBITS], (idx & (_CHSIZE - 1)) << 5, buff, offset, 32)
        else:
            assert isinstance(self.d, bytearray)
            memcpy(self.d, idx << 5, buff, offset, 32)

    def resize(self, nsize, chop: int = False, realloc: int = False):
        if self.size == nsize:
            return

        if self.chunked and nsize <= _CHSIZE:
            assert isinstance(self.d, list)
            self.chunked = False  # de-chunk
            if self.size > nsize and realloc:
                gc.collect()
                self.d = bytearray(self.d[0][: nsize << 5])
            elif self.size > nsize and not chop:
                gc.collect()
                self.d = self.d[0][: nsize << 5]
            else:
                gc.collect()
                self.d = bytearray(nsize << 5)

        elif self.chunked and self.size < nsize:
            assert isinstance(self.d, list)
            if nsize % _CHSIZE != 0 or realloc or chop:
                raise ValueError("Unsupported")  # not needed
            for i in range((nsize - self.size) // _CHSIZE):
                self.d.append(bytearray(32 * _CHSIZE))

        elif self.chunked:
            assert isinstance(self.d, list)
            if nsize % _CHSIZE != 0:
                raise ValueError("Unsupported")  # not needed
            for i in range((self.size - nsize) // _CHSIZE):
                self.d.pop()
            if realloc:
                for i in range(nsize // _CHSIZE):
                    self.d[i] = bytearray(self.d[i])

        else:
            assert isinstance(self.d, (bytes, bytearray))
            if self.size > nsize and realloc:
                gc.collect()
                self.d = bytearray(self.d[: nsize << 5])
            elif self.size > nsize and not chop:
                gc.collect()
                self.d = self.d[: nsize << 5]
            else:
                gc.collect()
                self.d = bytearray(nsize << 5)

        self.size = nsize
        self._set_mv()

    def realloc(self, nsize, collect: int = False):
        self.d = None
        self.mv = None
        if collect:
            gc.collect()  # gc collect prev. allocation

        self._set_d(nsize)
        self.size = nsize
        self._set_mv()

    def realloc_init_from(self, nsize, src, offset: int = 0, collect: int = False):
        if not isinstance(src, KeyV):
            raise ValueError("KeyV supported only")
        self.realloc(nsize, collect)

        if not self.chunked and not src.chunked:
            assert isinstance(self.d, bytearray)
            assert isinstance(src.d, (bytes, bytearray))
            memcpy(self.d, 0, src.d, offset << 5, nsize << 5)

        elif self.chunked and not src.chunked or self.chunked and src.chunked:
            for i in range(nsize):
                self.read(i, src.to(i + offset))

        elif not self.chunked and src.chunked:
            assert isinstance(self.d, bytearray)
            assert isinstance(src.d, list)
            for i in range(nsize >> _CHBITS):
                memcpy(
                    self.d,
                    i << 11,
                    src.d[i + (offset >> _CHBITS)],
                    (offset & (_CHSIZE - 1)) << 5 if i == 0 else 0,
                    nsize << 5 if i <= nsize >> _CHBITS else (nsize & _CHSIZE) << 5,
                )


class KeyVEval(KeyVBase):
    """
    KeyVector computed / evaluated on demand
    """

    __slots__ = ("current_idx", "size", "fnc", "raw", "scalar", "buff")

    def __init__(self, elems=64, src=None, raw: int = False, scalar=True):
        super().__init__(elems)
        self.fnc = src
        self.raw = raw
        self.scalar = scalar
        self.buff = (
            _ensure_dst_key()
            if not raw
            else (crypto.Scalar() if scalar else crypto.Point())
        )

    def __getitem__(self, item):
        return self.fnc(self.idxize(item), self.buff)

    def to(self, idx, buff: bytearray | None = None, offset: int = 0):
        self.fnc(self.idxize(idx), self.buff)
        if self.raw:
            if offset != 0:
                raise ValueError("Not supported")
            if self.scalar and buff:
                return crypto.sc_copy(buff, self.buff)
            elif self.scalar:
                return self.buff
            else:
                raise ValueError("Not supported")
        else:
            memcpy(buff, offset, self.buff, 0, 32)
        return buff if buff else self.buff


class KeyVSized(KeyVBase):
    """
    Resized vector, wrapping possibly larger vector
    (e.g., precomputed, but has to have exact size for further computations)
    """

    __slots__ = ("current_idx", "size", "wrapped")

    def __init__(self, wrapped, new_size):
        super().__init__(new_size)
        self.wrapped = wrapped

    def __getitem__(self, item):
        return self.wrapped[self.idxize(item)]

    def __setitem__(self, key, value):
        self.wrapped[self.idxize(key)] = value


class KeyVConst(KeyVBase):
    __slots__ = ("current_idx", "size", "elem")

    def __init__(self, size, elem, copy=True):
        super().__init__(size)
        self.elem = _init_key(elem) if copy else elem

    def __getitem__(self, item):
        return self.elem

    def to(self, idx: int, buff: bytearray, offset: int = 0):
        memcpy(buff, offset, self.elem, 0, 32)
        return buff if buff else self.elem


class KeyVPrecomp(KeyVBase):
    """
    Vector with possibly large size and some precomputed prefix.
    Usable for Gi vector with precomputed usual sizes (i.e., 2 output transactions)
    but possible to compute further
    """

    __slots__ = ("current_idx", "size", "precomp_prefix", "aux_comp_fnc", "buff")

    def __init__(self, size, precomp_prefix, aux_comp_fnc) -> None:
        super().__init__(size)
        self.precomp_prefix = precomp_prefix
        self.aux_comp_fnc = aux_comp_fnc
        self.buff = _ensure_dst_key()

    def __getitem__(self, item):
        item = self.idxize(item)
        if item < len(self.precomp_prefix):
            return self.precomp_prefix[item]
        return self.aux_comp_fnc(item, self.buff)

    def to(self, idx: int, buff: bytearray | None = None, offset: int = 0) -> bytearray:
        item = self.idxize(idx)
        if item < len(self.precomp_prefix):
            return self.precomp_prefix.to(item, buff if buff else self.buff, offset)
        self.aux_comp_fnc(item, self.buff)
        memcpy(buff, offset, self.buff, 0, 32)
        return buff if buff else self.buff


class KeyVSliced(KeyVBase):
    """
    Sliced in-memory vector version, remapping
    """

    __slots__ = ("current_idx", "size", "wrapped", "offset")

    def __init__(self, src, start, stop):
        super().__init__(stop - start)
        self.wrapped = src
        self.offset = start

    def __getitem__(self, item):
        return self.wrapped[self.offset + self.idxize(item)]

    def __setitem__(self, key, value) -> None:
        self.wrapped[self.offset + self.idxize(key)] = value

    def resize(self, nsize: int, chop: bool = False) -> None:
        raise ValueError("Not supported")

    def to(self, idx, buff: bytearray | None = None, offset: int = 0):
        return self.wrapped.to(self.offset + self.idxize(idx), buff, offset)

    def read(self, idx, buff, offset: int = 0):
        return self.wrapped.read(self.offset + self.idxize(idx), buff, offset)


class KeyVPowersBackwards(KeyVBase):
    """
    Vector of x^i.

    Used with BP+
    Allows arbitrary jumps as it is used in the folding mechanism. However, sequential access is the fastest.
    """

    __slots__ = (
        "current_idx",
        "size",
        "x",
        "x_inv",
        "x_max",
        "cur_sc",
        "tmp_sc",
        "raw",
        "cur",
        "last_idx",
    )

    def __init__(
        self,
        size: int,
        x: ScalarDst,
        x_inv: ScalarDst | None = None,
        x_max: ScalarDst | None = None,
        raw: int = False,
    ):
        super().__init__(size)
        self.raw = raw
        self.cur = bytearray(32) if not raw else crypto.Scalar()
        self.cur_sc = crypto.Scalar()
        self.last_idx = 0

        self.x = _load_scalar(None, x)
        self.x_inv = crypto.Scalar()
        self.x_max = crypto.Scalar()
        self.tmp_sc = crypto.Scalar()  # TODO: use static helper when everything works
        if x_inv:
            _load_scalar(self.x_inv, x_inv)
        else:
            crypto.sc_inv_into(self.x_inv, self.x)

        if x_max:
            _load_scalar(self.x_max, x_max)
        else:
            _sc_square_mult(self.x_max, self.x, size - 1)

        self.reset()

    def reset(self):
        self.last_idx = self.size - 1
        crypto.sc_copy(self.cur_sc, self.x_max)

    def move_more(self, item: int, prev: int):
        sdiff = prev - item
        if sdiff < 0:
            raise ValueError("Not supported")

        _sc_square_mult(self.tmp_sc, self.x_inv, sdiff)
        crypto.sc_mul_into(self.cur_sc, self.cur_sc, self.tmp_sc)

    def __getitem__(self, item):
        prev = self.last_idx
        item = self.idxize(item)
        self.last_idx = item

        if item == 0:
            return self.cur_sc if self.raw else _copy_key(self.cur, _ONE)
        elif item == 1:
            crypto.sc_copy(self.cur_sc, self.x)
        elif item == self.size - 1:  # reset
            self.reset()
        elif item == prev:
            pass
        elif (
            item == prev - 1
        ):  # backward step, mult inverse to decrease acc power by one
            crypto.sc_mul_into(self.cur_sc, self.cur_sc, self.x_inv)
        elif item < prev:  # jump backward
            self.move_more(item, prev)
        else:  # arbitrary jump
            self.reset()
            self.move_more(item, self.last_idx)
            self.last_idx = item

        return self.cur_sc if self.raw else crypto.encodeint_into(self.cur, self.cur_sc)


class VctD(KeyVBase):
    """
    Vector of d[j*N+i] = z**(2*(j+1)) * 2**i,  i \\in [0,N), j \\in [0,M)

    Used with BP+.
    Allows arbitrary jumps as it is used in the folding mechanism. However, sequential access is the fastest.
    """

    __slots__ = (
        "current_idx",
        "size",
        "N",
        "z_sq",
        "z_last",
        "two",
        "cur_sc",
        "tmp_sc",
        "cur",
        "last_idx",
        "current_n",
        "raw",
    )

    def __init__(self, N: int, M: int, z_sq: bytearray, raw: bool = False):
        super().__init__(N * M)
        self.N = N
        self.raw = raw
        self.z_sq = crypto.decodeint_into_noreduce(None, z_sq)
        self.z_last = crypto.Scalar()
        self.two = crypto.decodeint_into_noreduce(None, _TWO)
        self.cur_sc = crypto.Scalar()
        self.tmp_sc = crypto.Scalar()  # TODO: use static helper when everything works
        self.cur = _ensure_dst_key() if not self.raw else None
        self.last_idx = 0
        self.current_n = 0
        self.reset()

    def reset(self):
        self.current_idx = 0
        self.current_n = 0
        crypto.sc_copy(self.z_last, self.z_sq)
        crypto.sc_copy(self.cur_sc, self.z_sq)
        if not self.raw:
            crypto.encodeint_into(self.cur, self.cur_sc)  # z**2 + 2**0

    def move_one(self, item: int):
        """Fast linear jump step"""
        self.current_n += 1
        if item != 0 and self.current_n >= self.N:  # reset 2**i part,
            self.current_n = 0
            crypto.sc_mul_into(self.z_last, self.z_last, self.z_sq)
            crypto.sc_copy(self.cur_sc, self.z_last)
        else:
            crypto.sc_mul_into(self.cur_sc, self.cur_sc, self.two)
        if not self.raw:
            crypto.encodeint_into(self.cur, self.cur_sc)

    def move_more(self, item: int, prev: int):
        """More costly but required arbitrary jump forward"""
        sdiff = item - prev
        if sdiff < 0:
            raise ValueError("Not supported")

        self.current_n = item % self.N  # reset for move_one incremental move
        same_2 = sdiff % self.N == 0  # same 2**i component? simpler move
        z_squares_to_mul = (item // self.N) - (prev // self.N)

        # If z component needs to be updated, compute update and add it
        if z_squares_to_mul > 0:
            _sc_square_mult(self.tmp_sc, self.z_sq, z_squares_to_mul)
            crypto.sc_mul_into(self.z_last, self.z_last, self.tmp_sc)
            if same_2:
                crypto.sc_mul_into(self.cur_sc, self.cur_sc, self.tmp_sc)
                return

        # Optimal jump is complicated as due to 2**(i%64), power2 component can be lower in the new position
        # Thus reset and rebuild from z_last
        if not same_2:
            crypto.sc_copy(self.cur_sc, self.z_last)
            _sc_square_mult(self.tmp_sc, self.two, item % self.N)
            crypto.sc_mul_into(self.cur_sc, self.cur_sc, self.tmp_sc)

    def __getitem__(self, item):
        prev = self.last_idx
        item = self.idxize(item)
        self.last_idx = item

        if item == 0:
            self.reset()
        elif item == prev:
            pass
        elif item == prev + 1:
            self.move_one(item)
        elif item > prev:
            self.move_more(item, prev)
        else:
            self.reset()
            self.move_more(item, 0)
        return self.cur if not self.raw else self.cur_sc


class KeyHadamardFoldedVct(KeyVBase):
    """
    Hadamard-folded evaluated vector
    """

    __slots__ = (
        "current_idx",
        "size",
        "src",
        "a",
        "b",
        "raw",
        "gc_fnc",
        "cur_pt",
        "tmp_pt",
        "cur",
    )

    def __init__(
        self, src: KeyVBase, a: ScalarDst, b: ScalarDst, raw: bool = False, gc_fnc=None
    ):
        super().__init__(len(src) >> 1)
        self.src = src
        self.raw = raw
        self.gc_fnc = gc_fnc
        self.a = _load_scalar(None, a)
        self.b = _load_scalar(None, b)
        self.cur_pt = crypto.Point()
        self.tmp_pt = crypto.Point()
        self.cur = _ensure_dst_key() if not self.raw else None

    def __getitem__(self, item):
        i = self.idxize(item)
        crypto.decodepoint_into(self.cur_pt, self.src.to(i))
        crypto.decodepoint_into(self.tmp_pt, self.src.to(self.size + i))
        crypto.add_keys3_into(self.cur_pt, self.a, self.cur_pt, self.b, self.tmp_pt)
        if self.gc_fnc:
            self.gc_fnc(i)
        if not self.raw:
            return crypto.encodepoint_into(self.cur, self.cur_pt)
        else:
            return self.cur_pt


class KeyScalarFoldedVct(KeyVBase):
    """
    Scalar-folded evaluated vector
    """

    __slots__ = (
        "current_idx",
        "size",
        "src",
        "a",
        "b",
        "raw",
        "gc_fnc",
        "cur_sc",
        "tmp_sc",
        "cur",
    )

    def __init__(
        self, src: KeyVBase, a: ScalarDst, b: ScalarDst, raw: bool = False, gc_fnc=None
    ):
        super().__init__(len(src) >> 1)
        self.src = src
        self.raw = raw
        self.gc_fnc = gc_fnc
        self.a = _load_scalar(None, a)
        self.b = _load_scalar(None, b)
        self.cur_sc = crypto.Scalar()
        self.tmp_sc = crypto.Scalar()
        self.cur = _ensure_dst_key() if not self.raw else None

    def __getitem__(self, item):
        i = self.idxize(item)

        crypto.decodeint_into_noreduce(self.tmp_sc, self.src.to(i))
        crypto.sc_mul_into(self.tmp_sc, self.tmp_sc, self.a)
        crypto.decodeint_into_noreduce(self.cur_sc, self.src.to(self.size + i))
        crypto.sc_muladd_into(self.cur_sc, self.cur_sc, self.b, self.tmp_sc)

        if self.gc_fnc:
            self.gc_fnc(i)
        if not self.raw:
            return crypto.encodeint_into(self.cur, self.cur_sc)
        else:
            return self.cur_sc


class KeyChallengeCacheVct(KeyVBase):
    """
    Challenge cache vector for BP+ verification
    More on this in the verification code, near "challenge_cache" definition
    """

    __slots__ = (
        "nbits",
        "ch_",
        "chi",
        "precomp",
        "precomp_depth",
        "cur",
    )

    def __init__(
        self, nbits: int, ch_: KeyVBase, chi: KeyVBase, precomputed: KeyVBase | None
    ):
        super().__init__(1 << nbits)
        self.nbits = nbits
        self.ch_ = ch_
        self.chi = chi
        self.precomp = precomputed
        self.precomp_depth = 0
        self.cur = _ensure_dst_key()
        if not precomputed:
            return

        while (1 << self.precomp_depth) < len(precomputed):
            self.precomp_depth += 1

    def __getitem__(self, item):
        i = self.idxize(item)
        bits_done = 0

        if self.precomp:
            _copy_key(self.cur, self.precomp[i >> (self.nbits - self.precomp_depth)])
            bits_done += self.precomp_depth
        else:
            _copy_key(self.cur, _ONE)

        for j in range(self.nbits - 1, bits_done - 1, -1):
            if i & (1 << (self.nbits - 1 - j)) > 0:
                _sc_mul(self.cur, self.cur, self.ch_[j])
            else:
                _sc_mul(self.cur, self.cur, self.chi[j])
        return self.cur


def _ensure_dst_keyvect(dst=None, size: int | None = None):
    if dst is None:
        dst = KeyV(elems=size)
        return dst
    if size is not None and size != len(dst):
        dst.resize(size)
    return dst


def _vector_exponent_custom(A, B, a, b, dst=None, a_raw=None, b_raw=None):
    """
    \\sum_{i=0}^{|A|}  a_i A_i + b_i B_i
    """
    dst = _ensure_dst_key(dst)
    crypto.identity_into(_tmp_pt_2)

    for i in range(len(a or a_raw)):
        if a:
            crypto.decodeint_into_noreduce(_tmp_sc_1, a.to(i))
        crypto.decodepoint_into(_tmp_pt_3, A.to(i))
        if b:
            crypto.decodeint_into_noreduce(_tmp_sc_2, b.to(i))
        crypto.decodepoint_into(_tmp_pt_4, B.to(i))
        crypto.add_keys3_into(
            _tmp_pt_1,
            _tmp_sc_1 if a else a_raw.to(i),
            _tmp_pt_3,
            _tmp_sc_2 if b else b_raw.to(i),
            _tmp_pt_4,
        )
        crypto.point_add_into(_tmp_pt_2, _tmp_pt_2, _tmp_pt_1)
        _gc_iter(i)
    crypto.encodepoint_into(dst, _tmp_pt_2)
    return dst


def _weighted_inner_product(
    dst: bytearray | None, a: KeyVBase, b: KeyVBase, y: bytearray
):
    """
    Output a_0*b_0*y**1 + a_1*b_1*y**2 + ... + a_{n-1}*b_{n-1}*y**n
    """
    if len(a) != len(b):
        raise ValueError("Incompatible sizes of a and b")
    dst = _ensure_dst_key(dst)
    y_sc = crypto.decodeint_into_noreduce(_tmp_sc_4, y)
    y_pow = crypto.sc_copy(_tmp_sc_5, _tmp_sc_4)
    crypto.decodeint_into_noreduce(_tmp_sc_1, _ZERO)

    for i in range(len(a)):
        crypto.decodeint_into_noreduce(_tmp_sc_2, a.to(i))
        crypto.decodeint_into_noreduce(_tmp_sc_3, b.to(i))
        crypto.sc_mul_into(_tmp_sc_2, _tmp_sc_2, _tmp_sc_3)
        crypto.sc_muladd_into(_tmp_sc_1, _tmp_sc_2, y_pow, _tmp_sc_1)
        crypto.sc_mul_into(y_pow, y_pow, y_sc)
        _gc_iter(i)

    crypto.encodeint_into(dst, _tmp_sc_1)
    return dst


def _hadamard_fold(v, a, b, into=None, into_offset: int = 0, vR=None, vRoff=0):
    """
    Folds a curvepoint array using a two way scaled Hadamard product

    ln = len(v); h = ln // 2
    v_i = a v_i + b v_{h + i}
    """
    h = len(v) // 2
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    into = into if into else v

    for i in range(h):
        crypto.decodepoint_into(_tmp_pt_1, v.to(i))
        crypto.decodepoint_into(_tmp_pt_2, v.to(h + i) if not vR else vR.to(i + vRoff))
        crypto.add_keys3_into(_tmp_pt_3, _tmp_sc_1, _tmp_pt_1, _tmp_sc_2, _tmp_pt_2)
        crypto.encodepoint_into(_tmp_bf_0, _tmp_pt_3)
        into.read(i + into_offset, _tmp_bf_0)
        _gc_iter(i)

    return into


def _cross_inner_product(l0, r0, l1, r1):
    """
    t1   = l0 . r1 + l1 . r0
    t2   = l1 . r1
    """
    sc_t1 = crypto.Scalar()
    sc_t2 = crypto.Scalar()
    tl = crypto.Scalar()
    tr = crypto.Scalar()

    for i in range(len(l0)):
        crypto.decodeint_into_noreduce(tl, l0.to(i))
        crypto.decodeint_into_noreduce(tr, r1.to(i))
        crypto.sc_muladd_into(sc_t1, tl, tr, sc_t1)

        crypto.decodeint_into_noreduce(tl, l1.to(i))
        crypto.sc_muladd_into(sc_t2, tl, tr, sc_t2)

        crypto.decodeint_into_noreduce(tr, r0.to(i))
        crypto.sc_muladd_into(sc_t1, tl, tr, sc_t1)

        _gc_iter(i)

    return crypto_helpers.encodeint(sc_t1), crypto_helpers.encodeint(sc_t2)


def _hash_cache_mash(dst, hash_cache, *args):
    dst = _ensure_dst_key(dst)
    ctx = crypto_helpers.get_keccak()
    ctx.update(hash_cache)

    for x in args:
        if x is None:
            break
        ctx.update(x)
    hsh = ctx.digest()

    crypto.decodeint_into(_tmp_sc_1, hsh)
    crypto.encodeint_into(hash_cache, _tmp_sc_1)
    _copy_key(dst, hash_cache)
    return dst


def _is_reduced(sc) -> bool:
    return crypto.encodeint_into(_tmp_bf_0, crypto.decodeint_into(_tmp_sc_1, sc)) == sc


class MultiExpSequential:
    """
    MultiExp object similar to MultiExp array of [(scalar, point), ]
    MultiExp computes simply: res = \\sum_i scalar_i * point_i
    Straus / Pippenger algorithms are implemented in the original Monero C++ code for the speed
    but the memory cost is around 1 MB which is not affordable here in HW devices.

    Moreover, Monero needs speed for very fast verification for blockchain verification which is not
    priority in this use case.

    MultiExp holder with sequential evaluation
    """

    def __init__(
        self, size: int | None = None, points: list | None = None, point_fnc=None
    ) -> None:
        self.current_idx = 0
        self.size = size if size else None
        self.points = points if points else []
        self.point_fnc = point_fnc
        if points and size is None:
            self.size = len(points) if points else 0
        else:
            self.size = 0

        self.acc = crypto.Point()
        self.tmp = _ensure_dst_key()

    def get_point(self, idx):
        return (
            self.point_fnc(idx, None) if idx >= len(self.points) else self.points[idx]
        )

    def add_pair(self, scalar, point) -> None:
        self._acc(scalar, point)

    def add_scalar(self, scalar) -> None:
        self._acc(scalar, self.get_point(self.current_idx))

    def add_scalar_idx(self, scalar, idx: int) -> None:
        self._acc(scalar, self.get_point(idx))

    def _acc(self, scalar, point) -> None:
        crypto.decodeint_into_noreduce(_tmp_sc_1, scalar)
        crypto.decodepoint_into(_tmp_pt_2, point)
        crypto.scalarmult_into(_tmp_pt_3, _tmp_pt_2, _tmp_sc_1)
        crypto.point_add_into(self.acc, self.acc, _tmp_pt_3)
        self.current_idx += 1
        self.size += 1

    def eval(self, dst):
        dst = _ensure_dst_key(dst)
        return crypto.encodepoint_into(dst, self.acc)


def _multiexp(dst=None, data=None):
    return data.eval(dst)


class BulletProofGenException(Exception):
    pass


def _compute_LR(
    size: int,
    y: bytearray,
    G: KeyVBase,
    G0: int,
    H: KeyVBase,
    H0: int,
    a: KeyVBase,
    a0: int,
    b: KeyVBase,
    b0: int,
    c: bytearray,
    d: bytearray,
    tmp: bytearray = _tmp_bf_0,
) -> bytearray:
    """
    LR computation for BP+
    returns:
       c * 8^{-1} * H +
       d * 8^{-1} * G +
      \\sum_i a_{a0 + i} * 8^{-1} * y * G_{G0+i} +
              b_{b0 + i} * 8^{-1} *     H_{H0+i}
    """
    muex = MultiExpSequential()
    for i in range(size):
        _sc_mul(tmp, a.to(a0 + i), y)
        _sc_mul(tmp, tmp, _INV_EIGHT)
        muex.add_pair(tmp, G.to(G0 + i))

        _sc_mul(tmp, b.to(b0 + i), _INV_EIGHT)
        muex.add_pair(tmp, H.to(H0 + i))

    muex.add_pair(_sc_mul(tmp, c, _INV_EIGHT), _XMR_H)
    muex.add_pair(_sc_mul(tmp, d, _INV_EIGHT), _XMR_G)
    return _multiexp(tmp, muex)


class BulletProofPlusData:
    def __init__(self):
        self.y = None
        self.z = None
        self.e = None
        self.challenges = None
        self.logM = None
        self.inv_offset = None


class BulletProofPlusBuilder:
    """
    Bulletproof+
    https://eprint.iacr.org/2020/735.pdf
    https://github.com/monero-project/monero/blob/67e5ca9ad6f1c861ad315476a88f9d36c38a0abb/src/ringct/bulletproofs_plus.cc
    """

    def __init__(self, save_mem=True) -> None:
        self.save_mem = save_mem

        # BP_PLUS_GI_PRE = _get_exponent_plus(Gi[i], _XMR_H, i * 2 + 1)
        self.Gprec = KeyV(buffer=crypto.BP_PLUS_GI_PRE, const=True)

        # BP_PLUS_HI_PRE = None  #_get_exponent_plus(Hi[i], _XMR_H, i * 2)
        self.Hprec = KeyV(buffer=crypto.BP_PLUS_HI_PRE, const=True)

        # aL, aR amount bitmasks, can be freed once not needed
        self.aL = None
        self.aR = None

        self.gc_fnc = gc.collect
        self.gc_trace = None

    def gc(self, *args) -> None:
        if self.gc_trace:
            self.gc_trace(*args)
        if self.gc_fnc:
            self.gc_fnc()

    def aX_vcts(self, sv, MN) -> tuple:
        num_inp = len(sv)
        sc_zero = crypto.decodeint_into_noreduce(None, _ZERO)
        sc_one = crypto.decodeint_into_noreduce(None, _ONE)
        sc_mone = crypto.decodeint_into_noreduce(None, _MINUS_ONE)

        def e_xL(idx, d=None, is_a=True):
            j, i = idx // _BP_N, idx % _BP_N
            r = None
            if j < num_inp and sv[j][i // 8] & (1 << i % 8):
                r = sc_one if is_a else sc_zero
            else:
                r = sc_zero if is_a else sc_mone
            if d:
                return crypto.sc_copy(d, r)
            return r

        aL = KeyVEval(MN, lambda i, d: e_xL(i, d, True), raw=True)
        aR = KeyVEval(MN, lambda i, d: e_xL(i, d, False), raw=True)
        return aL, aR

    def _gprec_aux(self, size: int) -> KeyVPrecomp:
        return KeyVPrecomp(
            size, self.Gprec, lambda i, d: _get_exponent_plus(d, _XMR_H, i * 2 + 1)
        )

    def _hprec_aux(self, size: int) -> KeyVPrecomp:
        return KeyVPrecomp(
            size, self.Hprec, lambda i, d: _get_exponent_plus(d, _XMR_H, i * 2)
        )

    def vector_exponent(self, a, b, dst=None, a_raw=None, b_raw=None):
        return _vector_exponent_custom(self.Gprec, self.Hprec, a, b, dst, a_raw, b_raw)

    def prove(
        self, sv: list[crypto.Scalar], gamma: list[crypto.Scalar]
    ) -> BulletproofPlus:
        return self.prove_batch([sv], [gamma])

    def prove_setup(self, sv: list[crypto.Scalar], gamma: list[crypto.Scalar]) -> tuple:
        utils.ensure(len(sv) == len(gamma), "|sv| != |gamma|")
        utils.ensure(len(sv) > 0, "sv empty")

        gc.collect()
        sv = [crypto_helpers.encodeint(x) for x in sv]
        gamma = [crypto_helpers.encodeint(x) for x in gamma]

        M, logM = 1, 0
        while M <= _BP_M and M < len(sv):
            logM += 1
            M = 1 << logM
        MN = M * _BP_N

        V = _ensure_dst_keyvect(None, len(sv))
        for i in range(len(sv)):
            _add_keys2(_tmp_bf_0, gamma[i], sv[i], _XMR_H)
            _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
            V.read(i, _tmp_bf_0)

        self.prove_setup_aLaR(MN, None, sv)
        return M, logM, V, gamma

    def prove_setup_aLaR(self, MN, sv, sv_vct=None):
        sv_vct = sv_vct if sv_vct else [crypto_helpers.encodeint(x) for x in sv]
        self.aL, self.aR = self.aX_vcts(sv_vct, MN)

    def prove_batch(
        self, sv: list[crypto.Scalar], gamma: list[crypto.Scalar]
    ) -> BulletproofPlus:
        M, logM, V, gamma = self.prove_setup(sv, gamma)
        hash_cache = _ensure_dst_key()
        while True:
            self.gc(10)
            try:
                return self._prove_batch_main(
                    V, gamma, hash_cache, logM, _BP_LOG_N, M, _BP_N
                )
            except BulletProofGenException:
                self.prove_setup_aLaR(M * _BP_N, sv)
                continue

    def _prove_batch_main(
        self,
        V: KeyVBase,
        gamma: list[crypto.Scalar],
        hash_cache: bytearray,
        logM: int,
        logN: int,
        M: int,
        N: int,
    ) -> BulletproofPlus:
        _hash_vct_to_scalar(hash_cache, V)

        MN = M * N
        logMN = logM + logN

        tmp = _ensure_dst_key()
        tmp2 = _ensure_dst_key()
        memcpy(hash_cache, 0, _INITIAL_TRANSCRIPT, 0, len(_INITIAL_TRANSCRIPT))
        _hash_cache_mash(hash_cache, hash_cache, _hash_vct_to_scalar(tmp, V))

        # compute A = 8^{-1} ( \alpha G + \sum_{i=0}^{MN-1} a_{L,i} \Gi_i + a_{R,i} \Hi_i)
        aL = self.aL
        aR = self.aR
        inv_8_sc = crypto.decodeint_into_noreduce(None, _INV_EIGHT)
        aL8 = KeyVEval(
            len(aL),
            lambda i, d: crypto.sc_mul_into(d, aL[i], inv_8_sc),  # noqa: F821
            raw=True,
        )
        aR8 = KeyVEval(
            len(aL),
            lambda i, d: crypto.sc_mul_into(d, aR[i], inv_8_sc),  # noqa: F821
            raw=True,
        )
        alpha = _sc_gen()

        A = _ensure_dst_key()
        Gprec = self._gprec_aux(MN)  # Extended precomputed GiHi
        Hprec = self._hprec_aux(MN)
        _vector_exponent_custom(
            Gprec, Hprec, a=None, b=None, a_raw=aL8, b_raw=aR8, dst=A
        )
        _sc_mul(tmp, alpha, _INV_EIGHT)
        _add_keys(A, A, _scalarmult_base(_tmp_bf_1, tmp))
        del (aL8, aR8, inv_8_sc)
        self.gc(11)

        # Challenges
        y = _hash_cache_mash(None, hash_cache, A)
        if y == _ZERO:
            raise BulletProofGenException()
        z = _hash_to_scalar(None, y)
        if z == _ZERO:
            raise BulletProofGenException()
        _copy_key(hash_cache, z)
        self.gc(12)

        zc = crypto.decodeint_into_noreduce(None, z)
        z_squared = crypto.encodeint_into(None, crypto.sc_mul_into(_tmp_sc_1, zc, zc))
        d_vct = VctD(N, M, z_squared, raw=True)
        del (z,)

        # aL1 = aL - z
        aL1_sc = crypto.Scalar()

        def aL1_fnc(i, d):
            return crypto.encodeint_into(d, crypto.sc_sub_into(aL1_sc, aL.to(i), zc))

        aprime = KeyVEval(MN, aL1_fnc, raw=False)  # aL1

        # aR1[i] = (aR[i] - z) + d[i] * y**(MN-i)
        y_sc = crypto.decodeint_into_noreduce(None, y)
        yinv = crypto.sc_inv_into(None, y_sc)
        _sc_square_mult(_tmp_sc_5, y_sc, MN - 1)  # y**(MN-1)
        crypto.sc_mul_into(_tmp_sc_5, _tmp_sc_5, y_sc)  # y**MN

        ypow_back = KeyVPowersBackwards(
            MN + 1, y, x_inv=yinv, x_max=_tmp_sc_5, raw=True
        )
        aR1_sc1 = crypto.Scalar()

        def aR1_fnc(i, d):
            crypto.sc_add_into(aR1_sc1, aR.to(i), zc)
            crypto.sc_muladd_into(aR1_sc1, d_vct[i], ypow_back[MN - i], aR1_sc1)
            return crypto.encodeint_into(d, aR1_sc1)

        bprime = KeyVEval(MN, aR1_fnc, raw=False)  # aR1

        self.gc(13)
        _copy_key(tmp, _ONE)
        alpha1 = _copy_key(None, alpha)
        crypto.sc_mul_into(_tmp_sc_4, ypow_back.x_max, y_sc)
        crypto.encodeint_into(_tmp_bf_0, _tmp_sc_4)  # compute y**(MN+1)
        for j in range(len(V)):
            _sc_mul(tmp, tmp, z_squared)
            _sc_mul(tmp2, _tmp_bf_0, tmp)
            _sc_muladd(alpha1, tmp2, gamma[j], alpha1)

        # y, y**-1 powers
        ypow = _sc_square_mult(None, y_sc, MN >> 1)
        yinvpow = _sc_square_mult(None, yinv, MN >> 1)
        del (z_squared, alpha)

        # Proof loop phase
        challenge = _ensure_dst_key()
        challenge_inv = _ensure_dst_key()
        rnd = 0
        nprime = MN
        Gprime = Gprec
        Hprime = Hprec
        L = _ensure_dst_keyvect(None, logMN)
        R = _ensure_dst_keyvect(None, logMN)
        tmp_sc_1 = crypto.Scalar()
        del (logMN,)
        if not self.save_mem:
            del (Gprec, Hprec)

        dL = _ensure_dst_key()
        dR = _ensure_dst_key()
        cL = _ensure_dst_key()
        cR = _ensure_dst_key()
        while nprime > 1:
            npr2 = nprime
            nprime >>= 1
            self.gc(22)

            # Compute cL, cR
            # cL = \\sum_i y^{i+1} * aprime_i                         * bprime_{i + nprime}
            # cL = \\sum_i y^{i+1} * aprime_{i + nprime} * y^{nprime} * bprime_{i}
            _weighted_inner_product(
                cL, aprime.slice_view(0, nprime), bprime.slice_view(nprime, npr2), y
            )

            def vec_sc_fnc(i, d):
                crypto.decodeint_into_noreduce(tmp_sc_1, aprime.to(i + nprime))
                crypto.sc_mul_into(tmp_sc_1, tmp_sc_1, ypow)
                crypto.encodeint_into(d, tmp_sc_1)

            vec_aprime_x_ypownprime = KeyVEval(nprime, vec_sc_fnc)
            _weighted_inner_product(
                cR, vec_aprime_x_ypownprime, bprime.slice_view(0, nprime), y
            )
            del (vec_aprime_x_ypownprime,)
            self.gc(25)

            _sc_gen(dL)
            _sc_gen(dR)

            # Compute L[r], R[r]
            # L[r] = cL * 8^{-1} * H + dL * 8^{-1} * G +
            #        \\sum_i aprime_{i}          * 8^{-1} * y^{-nprime} * Gprime_{nprime + i} +
            #                bprime_{nprime + i} * 8^{-1} *               Hprime_{i}
            #
            # R[r] = cR * 8^{-1} * H + dR * 8^{-1} * G +
            #        \\sum_i aprime_{nprime + i} * 8^{-1} * y^{nprime}  * Gprime_{i} +
            #                bprime_{i}          * 8^{-1} *               Hprime_{nprime + i}
            _compute_LR(
                size=nprime,
                y=yinvpow,
                G=Gprime,
                G0=nprime,
                H=Hprime,
                H0=0,
                a=aprime,
                a0=0,
                b=bprime,
                b0=nprime,
                c=cL,
                d=dL,
                tmp=tmp,
            )
            L.read(rnd, tmp)

            _compute_LR(
                size=nprime,
                y=ypow,
                G=Gprime,
                G0=0,
                H=Hprime,
                H0=nprime,
                a=aprime,
                a0=nprime,
                b=bprime,
                b0=0,
                c=cR,
                d=dR,
                tmp=tmp,
            )
            R.read(rnd, tmp)
            self.gc(26)

            _hash_cache_mash(challenge, hash_cache, L[rnd], R[rnd])
            if challenge == _ZERO:
                raise BulletProofGenException()

            _invert(challenge_inv, challenge)
            _sc_mul(tmp, crypto.encodeint_into(_tmp_bf_0, yinvpow), challenge)
            self.gc(27)

            # Hadamard fold Gprime, Hprime
            # When memory saving is enabled, Gprime and Hprime vectors are folded in-memory for round=1
            # Depth 2 in-memory folding would be also possible if needed: np2 = nprime // 2
            # Gprime_new[i] = c * (a * Gprime[i]       + b * Gprime[i+nprime]) +
            #                 d * (a * Gprime[np2 + i] + b * Gprime[i+nprime + np2])
            Gprime_new = Gprime
            if self.save_mem and rnd == 0:
                Gprime = KeyHadamardFoldedVct(
                    Gprime, a=challenge_inv, b=tmp, gc_fnc=_gc_iter
                )
            elif (self.save_mem and rnd == 1) or (not self.save_mem and rnd == 0):
                Gprime_new = KeyV(nprime)

            if not self.save_mem or rnd != 0:
                Gprime = _hadamard_fold(Gprime, challenge_inv, tmp, into=Gprime_new)
                Gprime.resize(nprime)
            del (Gprime_new,)
            self.gc(30)

            Hprime_new = Hprime
            if self.save_mem and rnd == 0:
                Hprime = KeyHadamardFoldedVct(
                    Hprime, a=challenge, b=challenge_inv, gc_fnc=_gc_iter
                )
            elif (self.save_mem and rnd == 1) or (not self.save_mem and rnd == 0):
                Hprime_new = KeyV(nprime)

            if not self.save_mem or rnd != 0:
                Hprime = _hadamard_fold(
                    Hprime, challenge, challenge_inv, into=Hprime_new
                )
                Hprime.resize(nprime)
            del (Hprime_new,)
            self.gc(30)

            # Scalar fold aprime, bprime
            # aprime[i] = challenge     * aprime[i] + tmp       * aprime[i + nprime]
            # bprime[i] = challenge_inv * bprime[i] + challenge * bprime[i + nprime]
            # When memory saving is enabled, aprime vector is folded in-memory for round=1
            _sc_mul(tmp, challenge_inv, ypow)

            aprime_new = aprime
            if self.save_mem and rnd == 0:
                aprime = KeyScalarFoldedVct(aprime, a=challenge, b=tmp, gc_fnc=_gc_iter)
            elif (self.save_mem and rnd == 1) or (not self.save_mem and rnd == 0):
                aprime_new = KeyV(nprime)

            if not self.save_mem or rnd != 0:
                for i in range(nprime):
                    _sc_mul(tmp2, aprime.to(i), challenge)
                    aprime_new.read(
                        i, _sc_muladd(_tmp_bf_0, aprime.to(i + nprime), tmp, tmp2)
                    )

                aprime = aprime_new
                aprime.resize(nprime)

            if (self.save_mem and rnd == 1) or (not self.save_mem and rnd == 0):
                pass
                # self.aL = None
                # del (aL1_fnc, aL1_sc, aL)
            self.gc(31)

            bprime_new = KeyV(nprime) if rnd == 0 else bprime
            if rnd == 0:
                # Two-phase folding for bprime, so it can be linearly scanned (faster) for r=0 (eval vector)
                for i in range(nprime):
                    bprime_new.read(i, _sc_mul(tmp, bprime[i], challenge_inv))
                for i in range(nprime):
                    _sc_muladd(tmp, bprime[i + nprime], challenge, bprime_new[i])
                    bprime_new.read(i, tmp)

                self.aR = None
                del (aR1_fnc, aR1_sc1, aR, d_vct, ypow_back)
                self.gc(31)

            else:
                for i in range(nprime):
                    _sc_mul(tmp2, bprime.to(i), challenge_inv)
                    bprime_new.read(
                        i, _sc_muladd(_tmp_bf_0, bprime.to(i + nprime), challenge, tmp2)
                    )

            bprime = bprime_new
            bprime.resize(nprime)
            self.gc(32)

            _sc_muladd(alpha1, dL, _sc_mul(tmp, challenge, challenge), alpha1)
            _sc_muladd(alpha1, dR, _sc_mul(tmp, challenge_inv, challenge_inv), alpha1)

            # end: update ypow, yinvpow; reduce by halves
            nnprime = nprime >> 1
            if nnprime > 0:
                crypto.sc_mul_into(
                    ypow, ypow, _sc_square_mult(_tmp_sc_1, yinv, nnprime)
                )
                crypto.sc_mul_into(
                    yinvpow, yinvpow, _sc_square_mult(_tmp_sc_1, y_sc, nnprime)
                )

            self.gc(49)
            rnd += 1

        # Final round computations
        del (cL, cR, dL, dR)
        self.gc(50)

        r = _sc_gen()
        s = _sc_gen()
        d_ = _sc_gen()
        eta = _sc_gen()

        muex = MultiExpSequential()
        muex.add_pair(_sc_mul(tmp, r, _INV_EIGHT), Gprime.to(0))
        muex.add_pair(_sc_mul(tmp, s, _INV_EIGHT), Hprime.to(0))
        muex.add_pair(_sc_mul(tmp, d_, _INV_EIGHT), _XMR_G)

        _sc_mul(tmp, r, y)
        _sc_mul(tmp, tmp, bprime[0])
        _sc_mul(tmp2, s, y)
        _sc_mul(tmp2, tmp2, aprime[0])
        _sc_add(tmp, tmp, tmp2)
        muex.add_pair(_sc_mul(tmp2, tmp, _INV_EIGHT), _XMR_H)
        A1 = _multiexp(None, muex)

        _sc_mul(tmp, r, y)
        _sc_mul(tmp, tmp, s)
        _sc_mul(tmp, tmp, _INV_EIGHT)
        _sc_mul(tmp2, eta, _INV_EIGHT)
        B = _add_keys2(None, tmp2, tmp, _XMR_H)

        e = _hash_cache_mash(None, hash_cache, A1, B)
        if e == _ZERO:
            raise BulletProofGenException()

        e_squared = _sc_mul(None, e, e)
        r1 = _sc_muladd(None, aprime[0], e, r)
        s1 = _sc_muladd(None, bprime[0], e, s)
        d1 = _sc_muladd(None, d_, e, eta)
        _sc_muladd(d1, alpha1, e_squared, d1)

        from .serialize_messages.tx_rsig_bulletproof import BulletproofPlus

        return BulletproofPlus(V=V, A=A, A1=A1, B=B, r1=r1, s1=s1, d1=d1, L=L, R=R)

    def verify(self, proof: BulletproofPlus) -> bool:
        return self.verify_batch([proof])

    def verify_batch(self, proofs: list[BulletproofPlus]):
        """
        BP+ batch verification
        """
        max_length = 0
        for proof in proofs:
            utils.ensure(_is_reduced(proof.r1), "Input scalar not in range")
            utils.ensure(_is_reduced(proof.s1), "Input scalar not in range")
            utils.ensure(_is_reduced(proof.d1), "Input scalar not in range")
            utils.ensure(len(proof.V) >= 1, "V does not have at least one element")
            utils.ensure(len(proof.L) == len(proof.R), "|L| != |R|")
            utils.ensure(len(proof.L) > 0, "Empty proof")
            max_length = max(max_length, len(proof.L))

        utils.ensure(max_length < 32, "At least one proof is too large")
        self.gc(1)

        logN = 6
        N = 1 << logN
        tmp = _ensure_dst_key()

        max_length = 0  # size of each of the longest proof's inner-product vectors
        nV = 0  # number of output commitments across all proofs
        inv_offset = 0
        max_logm = 0

        proof_data = []
        to_invert_offset = 0
        to_invert = _ensure_dst_keyvect(None, 11 * len(proofs))
        for proof in proofs:
            max_length = max(max_length, len(proof.L))
            nV += len(proof.V)
            pd = BulletProofPlusData()
            proof_data.append(pd)

            # Reconstruct the challenges
            transcript = bytearray(_INITIAL_TRANSCRIPT)
            _hash_cache_mash(transcript, transcript, _hash_vct_to_scalar(tmp, proof.V))

            pd.y = _hash_cache_mash(None, transcript, proof.A)
            utils.ensure(not (pd.y == _ZERO), "y == 0")
            pd.z = _hash_to_scalar(None, pd.y)
            _copy_key(transcript, pd.z)

            # Determine the number of inner-product rounds based on proof size
            pd.logM = 0
            while True:
                M = 1 << pd.logM
                if M > _BP_M or M >= len(proof.V):
                    break
                pd.logM += 1

            max_logm = max(max_logm, pd.logM)
            rounds = pd.logM + logN
            utils.ensure(rounds > 0, "zero rounds")

            # The inner-product challenges are computed per round
            pd.challenges = _ensure_dst_keyvect(None, rounds)
            for j in range(rounds):
                pd.challenges[j] = _hash_cache_mash(
                    pd.challenges[j], transcript, proof.L[j], proof.R[j]
                )
                utils.ensure(pd.challenges[j] != _ZERO, "challenges[j] == 0")

            # Final challenge
            pd.e = _hash_cache_mash(None, transcript, proof.A1, proof.B)
            utils.ensure(pd.e != _ZERO, "e == 0")

            # batch scalar inversions
            pd.inv_offset = inv_offset
            for j in range(rounds):  # max rounds is 10 = lg(16*64) = lg(1024)
                to_invert.read(to_invert_offset, pd.challenges[j])
                to_invert_offset += 1

            to_invert.read(to_invert_offset, pd.y)
            to_invert_offset += 1
            inv_offset += rounds + 1
            self.gc(2)

        to_invert.resize(inv_offset)
        self.gc(2)

        utils.ensure(max_length < 32, "At least one proof is too large")
        maxMN = 1 << max_length
        tmp2 = _ensure_dst_key()

        # multiexp_size = nV + (2 * (max_logm + logN) + 3) * len(proofs) + 2 * maxMN
        Gprec = self._gprec_aux(maxMN)  # Extended precomputed GiHi
        Hprec = self._hprec_aux(maxMN)
        muex_expl = MultiExpSequential()
        muex_gh = MultiExpSequential(
            point_fnc=lambda i, d: Gprec[i >> 1] if i & 1 == 0 else Hprec[i >> 1]
        )

        inverses = _invert_batch(to_invert)
        del (to_invert,)
        self.gc(3)

        # Weights and aggregates
        #
        # The idea is to take the single multiscalar multiplication used in the verification
        #  of each proof in the batch and weight it using a random weighting factor, resulting
        #  in just one multiscalar multiplication check to zero for the entire batch.
        # We can further simplify the verifier complexity by including common group elements
        #  only once in this single multiscalar multiplication.
        # Common group elements' weighted scalar sums are tracked across proofs for this reason.
        #
        # To build a multiscalar multiplication for each proof, we use the method described in
        #  Section 6.1 of the preprint. Note that the result given there does not account for
        #    the construction of the inner-product inputs that are produced in the range proof
        #  verifier algorithm; we have done so here.

        G_scalar = bytearray(_ZERO)
        H_scalar = bytearray(_ZERO)
        # Gi_scalars = _vector_dup(_ZERO, maxMN)
        # Hi_scalars = _vector_dup(_ZERO, maxMN)

        proof_data_index = 0
        for proof in proofs:
            self.gc(4)
            pd = proof_data[proof_data_index]  # type: BulletProofPlusData
            proof_data_index += 1

            utils.ensure(len(proof.L) == 6 + pd.logM, "Proof is not the expected size")
            M = 1 << pd.logM
            MN = M * N
            weight = bytearray(_ZERO)
            while weight == _ZERO:
                _sc_gen(weight)

            # Rescale previously offset proof elements
            #
            # Compute necessary powers of the y-challenge
            y_MN = bytearray(pd.y)
            y_MN_1 = _ensure_dst_key(None)
            temp_MN = MN
            while temp_MN > 1:
                _sc_mul(y_MN, y_MN, y_MN)
                temp_MN /= 2

            _sc_mul(y_MN_1, y_MN, pd.y)

            # V_j: -e**2 * z**(2*j+1) * y**(MN+1) * weight
            e_squared = _ensure_dst_key(None)
            _sc_mul(e_squared, pd.e, pd.e)

            z_squared = _ensure_dst_key(None)
            _sc_mul(z_squared, pd.z, pd.z)

            _sc_sub(tmp, _ZERO, e_squared)
            _sc_mul(tmp, tmp, y_MN_1)
            _sc_mul(tmp, tmp, weight)

            for j in range(len(proof.V)):
                _sc_mul(tmp, tmp, z_squared)
                # This ensures that all such group elements are in the prime-order subgroup.
                muex_expl.add_pair(tmp, _scalarmult8(tmp2, proof.V[j]))

            # B: -weight
            _sc_mul(tmp, _MINUS_ONE, weight)
            muex_expl.add_pair(tmp, _scalarmult8(tmp2, proof.B))

            # A1: -weight * e
            _sc_mul(tmp, tmp, pd.e)
            muex_expl.add_pair(tmp, _scalarmult8(tmp2, proof.A1))

            # A: -weight * e * e
            minus_weight_e_squared = _sc_mul(None, tmp, pd.e)
            muex_expl.add_pair(minus_weight_e_squared, _scalarmult8(tmp2, proof.A))

            # G: weight * d1
            _sc_muladd(G_scalar, weight, proof.d1, G_scalar)
            self.gc(5)

            # Windowed vector
            # d[j*N+i] = z **(2*(j+1)) * 2**i
            # d is being read iteratively from [0..MN) only once.
            # Can be computed on the fly: hold last z and 2**i, add together
            d = VctD(N, M, z_squared)

            # More efficient computation of sum(d)
            sum_d = _ensure_dst_key(None)
            _sc_mul(
                sum_d, _TWO_SIXTY_FOUR_MINUS_ONE, _sum_of_even_powers(None, pd.z, 2 * M)
            )

            # H: weight*( r1*y*s1 + e**2*( y**(MN+1)*z*sum(d) + (z**2-z)*sum(y) ) )
            sum_y = _sum_of_scalar_powers(None, pd.y, MN)
            _sc_sub(tmp, z_squared, pd.z)
            _sc_mul(tmp, tmp, sum_y)

            _sc_mul(tmp2, y_MN_1, pd.z)
            _sc_mul(tmp2, tmp2, sum_d)
            _sc_add(tmp, tmp, tmp2)
            _sc_mul(tmp, tmp, e_squared)
            _sc_mul(tmp2, proof.r1, pd.y)
            _sc_mul(tmp2, tmp2, proof.s1)
            _sc_add(tmp, tmp, tmp2)
            _sc_muladd(H_scalar, tmp, weight, H_scalar)

            # Compute the number of rounds for the inner-product argument
            rounds = pd.logM + logN
            utils.ensure(rounds > 0, "zero rounds")

            # challenges_inv = inverses[pd.inv_offset]
            yinv = inverses[pd.inv_offset + rounds]
            self.gc(6)

            # Description of challenges_cache:
            #  Let define   ch_[i] = pd.challenges[i] and
            #               chi[i] = pd.challenges[i]^{-1}
            #  Also define  b_j[i] = i-th bit of integer j, 0 is MSB
            #                        encoded in {rounds} bits
            #
            # challenges_cache[i] contains multiplication ch_ or chi depending on the b_i
            # i.e., its binary representation. chi is for 0, ch_ for 1 in the b_i repr.
            #
            # challenges_cache[i] = \\mult_{j \in [0, rounds)} (b_i[j] * ch_[j]) +
            #                                                (1-b_i[j]) * chi[j]
            # Originally, it is constructed iteratively, starting with 1 bit, 2 bits.
            # We cannot afford having it all precomputed, thus we precompute it up to
            # a threshold challenges_cache_depth_lim bits, the rest is evaluated on the fly
            challenges_cache_depth_lim = const(8)
            challenges_cache_depth = min(rounds, challenges_cache_depth_lim)
            challenges_cache = _ensure_dst_keyvect(None, 1 << challenges_cache_depth)

            challenges_cache[0] = inverses[pd.inv_offset]
            challenges_cache[1] = pd.challenges[0]

            for j in range(1, challenges_cache_depth):
                slots = 1 << (j + 1)
                for s in range(slots - 1, -1, -2):
                    challenges_cache.read(
                        s,
                        _sc_mul(
                            _tmp_bf_0,
                            challenges_cache[s // 2],
                            pd.challenges[j],  # even s
                        ),
                    )
                    challenges_cache.read(
                        s - 1,
                        _sc_mul(
                            _tmp_bf_0,
                            challenges_cache[s // 2],
                            inverses[pd.inv_offset + j],  # odd s
                        ),
                    )

            if rounds > challenges_cache_depth:
                challenges_cache = KeyChallengeCacheVct(
                    rounds,
                    pd.challenges,
                    inverses.slice_view(pd.inv_offset, pd.inv_offset + rounds + 1),
                    challenges_cache,
                )

            # Gi and Hi
            self.gc(7)
            e_r1_w_y = _ensure_dst_key()
            _sc_mul(e_r1_w_y, pd.e, proof.r1)
            _sc_mul(e_r1_w_y, e_r1_w_y, weight)
            e_s1_w = _ensure_dst_key()
            _sc_mul(e_s1_w, pd.e, proof.s1)
            _sc_mul(e_s1_w, e_s1_w, weight)
            e_squared_z_w = _ensure_dst_key()
            _sc_mul(e_squared_z_w, e_squared, pd.z)
            _sc_mul(e_squared_z_w, e_squared_z_w, weight)
            minus_e_squared_z_w = _ensure_dst_key()
            _sc_sub(minus_e_squared_z_w, _ZERO, e_squared_z_w)
            minus_e_squared_w_y = _ensure_dst_key()
            _sc_sub(minus_e_squared_w_y, _ZERO, e_squared)
            _sc_mul(minus_e_squared_w_y, minus_e_squared_w_y, weight)
            _sc_mul(minus_e_squared_w_y, minus_e_squared_w_y, y_MN)

            g_scalar = _ensure_dst_key()
            h_scalar = _ensure_dst_key()
            for i in range(MN):
                if i % 8 == 0:
                    self.gc(8)
                _copy_key(g_scalar, e_r1_w_y)

                # Use the binary decomposition of the index
                _sc_muladd(g_scalar, g_scalar, challenges_cache[i], e_squared_z_w)
                _sc_muladd(
                    h_scalar,
                    e_s1_w,
                    challenges_cache[(~i) & (MN - 1)],
                    minus_e_squared_z_w,
                )

                # Complete the scalar derivation
                _sc_muladd(h_scalar, minus_e_squared_w_y, d[i], h_scalar)
                # Gi_scalars.read(i, _sc_add(Gi_scalars[i], Gi_scalars[i], g_scalar))  # Gi_scalars[i] accumulates across proofs; (g1+g2)G = g1G + g2G
                # Hi_scalars.read(i, _sc_add(Hi_scalars[i], Hi_scalars[i], h_scalar))

                muex_gh.add_scalar_idx(g_scalar, 2 * i)
                muex_gh.add_scalar_idx(h_scalar, 2 * i + 1)

                # Update iterated values
                _sc_mul(e_r1_w_y, e_r1_w_y, yinv)
                _sc_mul(minus_e_squared_w_y, minus_e_squared_w_y, yinv)
            del (challenges_cache, d)
            self.gc(9)

            # L_j: -weight*e*e*challenges[j]**2
            # R_j: -weight*e*e*challenges[j]**(-2)
            for j in range(rounds):
                _sc_mul(tmp, pd.challenges[j], pd.challenges[j])
                _sc_mul(tmp, tmp, minus_weight_e_squared)
                muex_expl.add_pair(tmp, _scalarmult8(tmp2, proof.L[j]))

                _sc_mul(tmp, inverses[pd.inv_offset + j], inverses[pd.inv_offset + j])
                _sc_mul(tmp, tmp, minus_weight_e_squared)
                muex_expl.add_pair(tmp, _scalarmult8(tmp2, proof.R[j]))
            proof_data[proof_data_index - 1] = None
            del (pd,)
        del (inverses,)
        self.gc(10)

        # Verify all proofs in the weighted batch
        muex_expl.add_pair(G_scalar, _XMR_G)
        muex_expl.add_pair(H_scalar, _XMR_H)
        # for i in range(maxMN):
        #     muex_gh.add_scalar_idx(Gi_scalars[i], i*2)
        #     muex_gh.add_scalar_idx(Hi_scalars[i], i*2 + 1)

        m1 = _multiexp(tmp, muex_gh)
        m2 = _multiexp(tmp2, muex_expl)
        muex = _add_keys(tmp, m1, m2)

        if muex != _ONE:
            raise ValueError("Verification error")

        return True
