# Copyright (c) 2023 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilafalseone.abcmm

Advanced, block-chained, message manager.

"""

import logging
from abc import abstractmethod
from collections import OrderedDict, UserDict
from collections.abc import (
    Callable,
    Iterable,
    Iterator,
    Mapping,
    Sequence,
    Sized
)
from hashlib import file_digest, new as get_hasher
from io import BufferedIOBase, BufferedReader, BytesIO
from itertools import chain as iter_chain
from queue import Queue
from secrets import token_bytes
from threading import RLock, Thread
from typing import Any, Self, Union
from weakref import WeakValueDictionary

from .ilfocore.constants import ENCODING, Address
from .ilfocore.utils import (
    pack_with_size,
    read_by_size,
    read_integral,
    write_integral,
    write_with_size
)
from .ilfocore.utils.multithread import call_forever, in_queue

from .basemodule import Bounded, DataBased
from .session import Session
from .session import DynamicSync, Sync, concat_varname, get_servfunc
from .session import Fillers, SyncFiller
from .utils import Inner, OrderedSet, SortedDict, SortedSet
from .restype import (
    Cryptic as _Cryptic,
    ResType,
    ResTypeManager,
    Resource,
    Serializable,
    TypedMapping,
    WithMsg as _WithMsg
)
from .signing import Signer, SigningManager

# IDE
T = None


class WithMsg[T: Serializable](_WithMsg):

    """New WithMsg class."""

    __slots__ = '_msg'

    def __init__(self, msg: T):
        self._msg = msg

    @property
    def msg(self) -> T:
        return self._msg


class Cryptic(_Cryptic):

    """New Cryptic class."""

    __slots__ = ()

    class Material(Serializable, Inner):

        def to_fillers(self, fillers: Fillers):
            raise NotImplementedError

        def rtype(self):
            raise NotImplementedError

    @property
    def material(self) -> Material | None:
        return self.Material(self) if self.is_decrypted else None


class Hashed(Cryptic):

    """Hashed class."""

    __slots__ = ()

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """Hash algorithm."""

    @property
    def is_decrypted(self) -> bool:
        return self.algorithm is not None


class Salted[T: Resource](WithMsg[T], Resource, Hashed, Bounded):

    """Cryptic resource with salt."""

    __slots__ = '_mod', '_hash', '_alg', '_salt'

    def __init__(self, mod: 'ABCMM', id_: int, alg: str | None, *args):
        Resource.__init__(self, id_)
        self._mod = mod
        self._alg = alg
        if alg is None:
            self._hash, = args
            self._salt = msg = None
        else:
            self._salt, msg = args
        super().__init__(msg)

    class Material(Cryptic.Material):

        """Material class of Salted class."""

        def to_bytes(self) -> bytes:
            salted = self._outer
            return pack_with_size(salted.salt) + WithMsg.to_bytes(salted)

    __eq__ = Serializable.__eq__

    def to_bytes(self) -> bytes:
        return get_hasher(
            self._alg, self._salt + super().to_bytes()
        ).digest() if self.is_decrypted else self._hash

    def to_fillers(self, fillers: Fillers):
        fillers.append(SyncFiller((self._mod, 'alg'), self._alg))
        if self.is_decrypted:
            self._material.to_fillers(fillers)
        else:
            fillers.append(SyncFiller((self._mod, 'alg'), None))
            Serializable.to_fillers(self, fillers)

    @property
    def algorithm(self) -> str:
        """Hash algorithm."""
        return self._alg

    @property
    def salt(self) -> bytes:
        """Random bytes."""
        return self._salt

    @property
    def rtype(self) -> ResType:
        """.salted"""
        return self._mod.type_salted

    @property
    def module(self) -> 'ABCMM':
        return self._mod


class Owned[T: Resource](WithMsg[T], Resource, Bounded):

    """Resource with its owner."""

    __slots__ = '_mod', '_owner'

    def __init__(self, mod: 'ABCMM', id_: int, owner: Signer, msg: Resource):
        super().__init__(msg)
        Resource.__init__(self, id_)
        self._mod = mod
        self._owner = owner

    def __eq__(self, other):
        return (isinstance(other, Owned)
                and self._owner == other._owner
                and self._msg == other._msg)

    def to_fillers(self, fillers: Fillers):
        self._owner.to_fillers(fillers)
        super().to_fillers(fillers)

    def to_bytes(self) -> bytes:
        return pack_with_size(self._owner.to_bytes()) + super().to_bytes()

    @property
    def owner(self) -> Signer:
        """Owner of the inner message."""
        return self._owner

    @property
    def rtype(self) -> ResType:
        """.owned"""
        return self._mod.type_owned

    @property
    def module(self) -> 'ABCMM':
        return self._mod


class MsgBlock[T: Serializable](WithMsg[T], Resource, Cryptic, Bounded):

    """MsgBlock class."""

    __slots__ = ('_chain', '_pos', '_hash', '_alg', '_owner', '_salt', '_data',
                 '_prev_ids', '_next_ids', '_sigs', '_signers',
                 '_mod', '_lock')

    def __init__(
        self,
        mod: 'ABCMM',

        id_: int,
        chain: Union[int, 'Chain'] = None, pos: int | None = None,
        hash_: bytes = None,

        alg: str = None,
        msg: Resource = None,

        prev_ids: tuple[int] = None,
        next_ids: OrderedSet[int] = None
    ):
        Bounded.__init__(self, mod)
        Resource.__init__(self, mod.type_msgblk, )
        if isinstance(chain, int):
            chain = mod.get_chain(chain)
            chain.blocks[pos] = self
        self._chain = chain
        self._pos = pos
        self._hash = hash_

        self._alg = alg
        self._msg = msg

        self._prev_ids = prev_ids
        self._next_ids = next_ids

        self._signers: set[Signer] = None

        self._lock = RLock()

    class Material(Cryptic.Material):

        """Material class of MsgBlock class."""

        __slots__ = ()

        @staticmethod
        def _combine(
                prev_blks: Iterable['MsgBlock'], msg: Serializable) -> bytes:
            write_integral(len(prev_blks), buf := BytesIO())
            for blk in prev_blks:
                write_with_size(blk.to_bytes(), buf)
            write_with_size(msg.rtype.to_bytes(), buf)
            write_with_size(msg.to_bytes(), buf)
            return buf.getvalue()

        @staticmethod
        def compute_hash(
            alg: str, prev_blks: Iterable['MsgBlock'], msg: Serializable
        ) -> bytes:
            """Compute hash of the block to be constructed."""
            return get_hasher(
                alg, MsgBlock.Material._combine(prev_blks, msg)).digest()

        def to_bytes(self) -> bytes:
            blk = self._outer
            return self._combine(blk.prev, blk.msg)

    @classmethod
    def unknown_block(cls, mod: 'ABCMM', id_: int, chain_id: int, pos: int,
                      hash_: bytes) -> Self:
        """Construct a unknown block."""
        return cls(mod, id_, chain_id, pos, hash_)

    def to_fillers(self, fillers: Fillers):
        fillers.append(SyncFiller((self._mod, 'msgblk'), self._hash))

    def to_bytes(self) -> bytes:
        self.load_data()
        return self._hash

    def __repr__(self) -> str:
        cls_name = self.__class__.__name__
        id_ = self._id
        if (hash_ := self._hash) is None:
            return f"{cls_name}(id_={id_})"
        return (f"{cls_name}(id_={id_}, chain={self._chain}, "
                f" pos={self._pos}, hash={hash_})")

    # def _add_signer(self, signer: int):
    #     if signer in (signers := self.signers):
    #         return
    #     self._mod.sql_conn.execute(
    #         "INSERT INTO signed_block(blk, signer) VALUES(?, ?)",
    #         (self._id, signer))
    #     signers.add(signer)
    #     if self.salt is not None:
    #         for blk in self.prev:
    #             blk._add_signer(signer)

    # def _add_signature(self, signer: int, signature: bytes):
    #     """Add a signature the block without authentication."""
    #     self._sigs[signer] = signature
    #     with self._mod.sql_conn as conn:
    #         conn.execute(
    #             "INSERT INTO signature(blk, signer, sig) VALUES(?, ?, ?)",
    #             (self._id, signer, signature))
    #         self._add_signer(signer)

    # def set_signature(self, signer: int, signature: bytes, verify=True):
    #     """Set the signature of a signer of block."""
    #     if signer in self.signatures:
    #         return
    #     pub_key = self._mod.public_keys[signer]
    #     if verify:
    #         pub_key.verify(signature, self.hash)
    #     self._add_signature(signer, signature)

    # def get_signature(self, signer: int) -> bytes:
    #     """Sign the block if the signer has not signed it.

    #     Return the signature.

    #     """
    #     if (sig := self.signatures.get(signer)) is not None:
    #         return sig
    #     if (priv_key := self._mod.private_keys[signer]) is None:
    #         return None
    #     sig = priv_key.sign(self.hash)
    #     self._add_signature(signer, sig)
    #     return sig

    # def hide(self) -> bytes | None:
    #     """Hide a block."""
    #     self.load_data()
    #     if (alg := self._alg) is None:
    #         return None
    #     if (owner := self._owner) is None:
    #         return self._data
    #     if self._salt is None:
    #         return None
    #     buf = BytesIO()
    #     for prev_blk in self.prev:
    #         write_with_size(prev_blk.hash, buf)
    #     write_with_size(bytes(self._type, ENCODING), buf)
    #     write_with_size(self._data, buf)
    #     write_with_size(self._mod.public_keys[owner].to_bytes(), buf)
    #     self._owner = None
    #     self._salt = None
    #     self._type = None
    #     self._data = body_hash = file_digest(buf, alg).digest()
    #     with self._mod.sql_conn as conn:
    #         conn.execute("""
    #             UPDATE block
    #             SET owner = NULL, salt = NULL, type = NULL, data = ?
    #             WHERE id = ?""", (body_hash, self._id))
    #     logging.debug("block %r is hidden", self)
    #     return body_hash

    @property
    def chain(self) -> 'Chain':
        """The chain of the block."""
        self.load_data()
        return self._chain

    @property
    def position(self) -> int:
        """The position of the block in its chain."""
        self.load_data()
        return self._pos

    @property
    def algorithm(self) -> str:
        """Hash algorithm of the block."""
        self.load_data()
        return self._alg

    @property
    def message(self) -> Resource:
        """Block message."""
        self.load_data()
        return self._msg

    @property
    def loaded_chain(self) -> bool:
        """If self._chain is loaded."""
        return self._chain is not None

    @property
    def loaded_hash(self) -> bool:
        """If self._hash is loaded."""
        return self._hash is not None

    @property
    def loaded_prev(self) -> bool:
        """If self._prev_id is loaded."""
        return self._prev_ids

    @property
    def loaded_next(self) -> bool:
        """If self._next_id is loaded."""
        return self._next_ids

    def load_data(self):
        """Load from table block."""
        if self.loaded_hash:
            return
        mod = self._mod
        if self.loaded_chain:
            (chain := self._chain).load_hash(*mod.find_range(
                chain, self._pos, MsgBlock.loaded_hash.fget))
            return

        chain_id, pos, self._hash, alg, *left = next(mod.sql_conn.execute("""
            SELECT hash, alg, salt, owner, type, res FROM soblock WHERE id = ?
            """, (id_ := self._rid,)))
        if alg is not None:
            self._alg = alg
            self._msg = mod.from_row(id_, alg, *left)
        self._chain = chain = mod.get_chain(chain_id)
        self._pos = pos
        chain.blocks[pos] = self

    @property
    def prev_ids(self) -> tuple[int]:
        """The IDs of previous blocks."""
        if not self.loaded_prev:
            (chain := self._chain).load_branch(*self._mod.find_range(
                chain, self._pos, MsgBlock.loaded_prev.fget), True)
        return self._prev_ids

    @property
    def next_ids(self) -> OrderedSet[int]:
        """The IDs of next blocks."""
        if not self.loaded_next:
            (chain := self._chain).load_branch(*self._mod.find_range(
                chain, self._pos, MsgBlock.loaded_next.fget), False)
        return self._next_ids

    @property
    def prev(self) -> Iterator[Self]:
        """Previous blocks."""
        for id_ in self.prev_ids:
            yield self._mod.type_msgblk.mapping.rid[id_]

    @property
    def next(self) -> Iterator[Self]:
        """Next blocks."""
        for id_ in self.next_block_ids:
            yield self._mod.type_msgblk.mapping.rid[id_]

    @property
    def signatures(self) -> dict[int, bytes]:
        """Signatures of the block's hash."""
        if (sigs := self._sigs) is None:
            sql_exec = self._mod.sql_conn.execute
            params = (self._id,)
            self._sigs = sigs = dict(sql_exec(
                "SELECT signer, sig FROM signature WHERE blk = ?", params))
        return sigs

    @property
    def signers(self) -> set[int]:
        """Signers who have signed the block."""
        if (signers := self._signers) is None:
            sql_exec = self._mod.sql_conn.execute
            params = (self._id,)
            self._signers = signers = {signer for signer, in sql_exec(
                "SELECT signer FROM signed_block WHERE blk = ?", params)}
        return signers

    @property
    def module(self) -> 'ABCMM':
        return self._mod


class BrokenGraph(Resource, Bounded):

    """Acyclic graph of blocks whose iteration
    can be stopped by a block with specific body.

    """

    __slots__ = '_mod', '_start', '_end', '_breaker'

    def __init__(self, mod: 'ABCMM', id_: int,
                 start: Iterable[MsgBlock], end: Iterable[MsgBlock],
                 breaker: Serializable | None = None):
        super().__init__(id_)
        Bounded.__init__(self, mod)
        end = set(end)
        start = set(start) - end
        end |= start
        self._start, self._end = start, end
        self._breaker = breaker

    def shall_break(self, blk: MsgBlock):
        """Return True if iteration breaks here."""
        return False

    def _iter(self, reverse: bool) -> Iterator[MsgBlock]:
        next_lvl = list(self._start)
        end = {
            blk: (len(blk.next) if reverse else len(blk.prev_ids)) - 1
            for blk in self._end}
        while next_lvl:
            curr_lvl = next_lvl.copy()
            next_lvl.clear()
            for blk in curr_lvl:
                yield blk
                if ((cnt := end.get(blk)) is not None
                        or blk.body == self._breaker):
                    if cnt:
                        cnt -= 1
                    else:
                        del end[blk]
                    break
                next_lvl += blk.prev if reverse else blk.next
                if cnt := len(blk.prev_ids if reverse else blk.next_ids) - 1:
                    end[blk] = cnt

    def __iter__(self) -> Iterator[MsgBlock]:
        yield from self._iter(False)

    def __reverse__(self) -> Iterator[MsgBlock]:
        yield from self._iter(True)

    @property
    def start(self) -> set[MsgBlock]:
        """Where the iteration starts."""
        return self._start

    @property
    def end(self) -> set[MsgBlock]:
        """Where the iteration breaks."""
        return self._end

    @property
    def breaker(self) -> Resource | None:
        """Where iteration breaks in broken block graph."""
        return self._breaker

    @property
    def rtype(self) -> ResType:
        """.brokengraph"""
        return self._mod.type_brokengraph

    @property
    def module(self) -> 'ABCMM':
        return self._mod


class Graph(BrokenGraph):

    """Acyclic graph of blocks."""

    __slots__ = ()

    def __init__(self, mod: 'ABCMM', id_: int,
                 start: Iterable[MsgBlock], end: Iterable[MsgBlock]):
        super().__init__(mod, id_, start, end)

    @property
    def rtype(self) -> ResType:
        """.graph"""
        return self._mod.type_graph


class Chain(Sequence[MsgBlock], Bounded):

    """Chain."""

    __slots__ = '_mod', '_id', '_blks', '_len', '_lock', '__weakref__'

    def __init__(self, mod: 'ABCMM', id_: int):
        self._mod = mod
        self._id = id_
        self._len: int = None
        self._blks: SortedDict[int, MsgBlock] = SortedDict()
        self._lock = RLock()

    def __len__(self) -> int:
        """Return the length of chain."""
        if (len_ := self._len) is None:
            max_ = next(self._mod.sql_conn.execute(
                "SELECT MAX(pos) FROM block WHERE chain = ?", (self._id,)))[0]
            self._len = len_ = max_ + 1 if max_ is not None else 0
        return len_

    def __iter__(self) -> Iterator[MsgBlock]:
        for pos in range(len(self)):
            yield self[pos]

    def __contains__(self, blk: MsgBlock) -> bool:
        return isinstance(blk, MsgBlock) and blk.chain is self

    def __reversed__(self) -> Iterator[MsgBlock]:
        for pos in reversed(range(len(self))):
            yield self[pos]

    def _from_row(self, pos: int, blk_id: int,
                  *left: tuple[bytes, str, int, bytes, int, int]) -> MsgBlock:
        mod = self._mod
        blk = mod.type_msgblk.mapping.rid[blk_id]
        if not blk.loaded_hash:
            blk._hash, alg, *left = left
            if alg is None:
                return blk
            blk._alg = alg
            blk._msg = mod.from_row(blk_id, alg, *left)
        if not blk.loaded_chain:
            blk._chain = self
            blk._pos = pos
        return blk

    def __getitem__(self, key: int | slice) -> MsgBlock | SortedSet[MsgBlock]:
        """Get a block or blocks."""
        mod = self._mod
        pos_blks = self._blks
        if isinstance(key, int):
            if key < 0:
                key += len(self)
            if key >= len(self) or key < 0:
                return None

            if (blk := pos_blks.get(key, None)) is not None:
                mod.id_blocks.move_to_end(blk.rid)
                return blk
            self.load_hash(*mod.find_range(self, key,
                           MsgBlock.loaded_hash.fget))
            return pos_blks[key]

        start, stop, step = key.indices(len(self))
        keys = pos_blks.keys()
        poses = SortedSet()
        poses[:] = range(start, stop)
        poses -= keys
        if poses:
            self.load_hash(poses[0], poses[-1])
        return pos_blks.values()[
            keys.bisect(start, 0, stop): keys.bisect(stop, start): step]

    def index(self, blk: MsgBlock, start=None, stop=None) -> int:
        if blk in self:
            return blk.position
        raise ValueError(blk)

    def count(self, blk: MsgBlock) -> int:
        return int(blk in self)

    def __eq__(self, obj: Any) -> bool:
        return self is obj

    def __repr__(self):
        return f"{self.__class__.__name__}(id_={self._id})"

    def load_hash(self, start: int, stop: int):
        """Load blk._hash."""
        mod = self._mod
        if stop - start > mod.blocks_maxlen:
            raise ValueError(start)
        pos_blks = self._blks
        keys = pos_blks.keys()
        items = pos_blks.items()
        j = keys.bisect(stop, i := 0)
        for pos, *left in (rsl := mod.sql_conn.execute("""
                SELECT pos, id, hash, alg, owner, salt, type, res FROM block
                WHERE chain = ? AND pos BETWEEN ? AND ? ORDER BY pos
                """, (self._id, start, stop - 1))):
            if (i := keys.bisect(pos, i, j)) >= len(keys):
                items.append((pos, self._from_row(pos, *left)))
                for pos, row in zip(range(pos, stop), rsl):
                    items.append((pos, self._from_row(pos, *left)))
                break
            if keys[i] != pos:
                items.insert(i, (pos, self._from_row(pos, *left)))
                i += 1
                j += 1

    def load_branch(self, start: int, stop: int, prev: bool = None):
        """Load blk.prev_ids and blk.next_block_ids."""
        if prev is None:
            self.load_branches(start, stop, True)
            prev = False
        blks = self[start: stop]
        end = stop - 1
        if prev:
            rsl = self._mod.sql_conn.execute("""
                SELECT next_pos, prev_id FROM branch
                WHERE next_chain = ? AND next_pos BETWEEN ? AND ?
                ORDER BY next_pos
                """, (self._id, start + 1 if start else start, end))
        else:
            blks = reversed(blks)
            rsl = self._mod.sql_conn.execute("""
                SELECT prev_pos, next_id FROM branch
                WHERE prev_chain = ? AND prev_pos BETWEEN ? AND ?
                ORDER BY prev_pos DESC
                """, (self._id, start, end - 1 if stop < len(self) else end))
        row = next(rsl, None)
        last: int = None
        for blk in blks:
            pos = blk.position
            if (to_load := blk._prev_ids is None
                    if prev else blk._next_ids is None):
                if prev:
                    prev_ids = [last] if pos else []
                else:
                    blk._next_ids = next_ids = OrderedSet()
                    if pos < len(self) - 1:
                        next_ids.add(last)
            while row is not None and row[0] == pos:
                if to_load:
                    if prev:
                        prev_ids.apppend(row[1])
                    else:
                        next_ids.add(row[1])
                row = next(rsl, None)
            if to_load and prev:
                blk._prev_ids = tuple(prev_ids)
            last = blk.rid
            if to_load:
                logging.debug(
                    f"{blk.rid} load context {prev_ids if prev else next_ids}")

    @property
    def id(self) -> int:
        """Chain ID."""
        return self._id

    @property
    def blocks(self) -> SortedDict[int, MsgBlock]:
        """Dictionary of blocks ordered by index of blocks."""
        return self._blks

    @property
    def module(self) -> 'ABCMM':
        return self._mod


CheckFunc = Callable[[MsgBlock], bool]


RangeFinder = Callable[[Chain, int, CheckFunc], tuple[int, int]]


def find_mono(chain: Chain, pos: int, maxoff: int, step: int,
              check: CheckFunc) -> int:
    """Find a position mono-directly."""
    keys = chain.blocks.keys()
    values = chain.blocks.values()

    stop = pos + maxoff
    for i in range(keys.bisect(pos), j := len(keys), step):
        if (new := keys[i]) >= stop:
            break
        if check(values[i]):
            stop = new
            break
    else:
        if stop > j:
            stop = j
    return stop


class BidirectedFinder(RangeFinder):

    """Bidirected range finder class."""

    __slots__ = '_backward', '_forward'

    def __init__(self, backward: int, forward: int):
        self._backward = backward
        self._forward = forward

    def __call__(self, chain: Chain, pos: int, check: CheckFunc
                 ) -> tuple[int, int]:
        """Call to get range from a position."""
        return (find_mono(chain, pos, self._from, 1, check),
                find_mono(chain, pos, self._backward, -1, check))

    @property
    def backward(self) -> int:
        """Backward offset."""
        return self._off

    @backward.setter
    def backward(self, value: int):
        """Set backward offset."""
        if not isinstance(value, int):
            raise TypeError(type(value))
        self._backward = value

    @property
    def forward(self) -> int:
        """Forward offset."""
        return self._from

    @forward.setter
    def forward(self, value: int):
        """Set forward offset."""
        if not isinstance(value, int):
            raise TypeError(type(value))
        self._forward = value


class LimitedFinder(RangeFinder):

    """Limited range finder class."""

    __slots__ = '_maxlen', '_off'

    def __init__(self, maxlen: int, offset: int | None = None):
        self._maxlen = maxlen
        self._off = offset

    def __call__(self, chain: Chain, pos: int, check: CheckFunc
                 ) -> tuple[int, int]:
        """Call to get range from a position."""
        from_ = find_mono(chain, pos, self._off, -1, check)
        to = find_mono(chain, from_, self._maxlen, 1, check)
        return from_, to

    @property
    def maxlen(self) -> int:
        """The maximum length of the range."""
        return self._maxlen

    @maxlen.setter
    def maxlen(self, value: int):
        """Bounded to the specified maximum length."""
        if not isinstance(value, int):
            raise TypeError(type(value))
        if value <= 0:
            raise ValueError(value)
        self._maxlen = value

    @property
    def offset(self) -> int:
        """Offset."""
        return self._off

    @offset.setter
    def offset(self, value: int):
        """Set offset."""
        if not isinstance(value, int):
            raise TypeError(type(value))
        self._off = value


def _ser_str(str_: str, buf: BufferedIOBase) -> int:
    """Serialize a data type into buffer."""
    return write_with_size(bytes(str_, ENCODING), buf)


def _deser_str(buf: BufferedReader) -> str | None:
    """Deserialize a string from buffer."""
    return str(read_by_size(buf), ENCODING)


def _deser_alg(buf: BufferedReader) -> str | None:
    """Deserialize a data type from buffer."""
    return get_hasher(_deser_str(buf)).name


class SaltedMapping(TypedMapping[Salted], Bounded):

    def __len__(self) -> int:
        conn = self._mod.sql_conn
        not_hidden, = next(conn.execute(
            "SELECT COUNT(*) FROM soblock WHERE salt IS NOT NULL"))
        hidden, = next(conn.execute("SELECT COUNT(*) FROM salted_hash"))
        return not_hidden + hidden

    class IDMapping(Mapping[int, Salted], Inner['SaltedMapping']):

        def __len__(self) -> int:
            return len(self._outer)

        def __getitem__(self, key: int) -> Salted:
            outer = self._outer
            msg = outer.module.type_msgblk.mapping.rid[key].msg
            if msg.type == outer.rtype:
                return msg
            raise KeyError(key)

    @property
    def rid(self) -> IDMapping:
        """Mapping using ID as key."""
        return self.IDMapping(self)

    class HashMapping(Mapping[bytes, Salted], Inner['SaltedMapping']):

        def __len__(self) -> int:
            return len(self._outer)

        def __getitem__(self, key: bytes) -> Salted:
            return Salted(self._outer.mod, None, None, key)

    @property
    def bytes(self) -> HashMapping:
        return self.HashMapping(self)

    def read(self, con: Session, buf: BufferedReader) -> Salted:
        if (alg := read_by_size(buf, not_none=False)) is None:
            hash_ = read_by_size(buf)
            return Salted(self._mod, None, alg, hash_)
        salt = read_by_size(buf)
        type_ = self._mod.restype_manager.type.mapping.read(con, buf)
        msg = type_.mapping.read(con, buf)
        return Salted(self, None, alg, salt, msg)

    @property
    def rtype(self) -> ResType:
        """.salted"""
        return self._mod.type_salted


class OwnedMapping(TypedMapping[Owned], Bounded):

    """Owned resource mapping."""

    def __init__(self, mod: 'ABCMM'):
        super().__init__(mod)
        self._id_map = None
        self._bytes_map = None
        self._sync_map = None

    def __len__(self) -> int:
        cnt, = next(self._mod.sql_conn.execute(
            "SELECT COUNT(*) FROM soblock WHERE owner IS NOT NULL"))
        return cnt

    class IDMapping(Mapping[int, Owned], Inner['OwnedMapping']):

        def __len__(self) -> int:
            return len(self._outer)

        def __getitem__(self, key: int) -> Salted:
            outer = self._outer
            msg = outer.module.type_msgblk.mapping.rid[key].msg
            if msg.type == outer.rtype:
                return msg
            raise KeyError(key)

    @property
    def rid(self) -> IDMapping:
        """Mapping using ID as key."""
        return self.IDMapping(self)

    class BytesMapping(Mapping[bytes, Owned], Inner['OwnedMapping']):

        def __len__(self) -> int:
            return len(self._outer)

        def __getitem__(self, key: bytes) -> Salted:
            mod = self._outer.module
            signer = mod.signing_manager.type_signer.mapping.bytes[
                read_by_size(buf := BytesIO(key))]
            type_ = mod.restype_manager.type.mapping.bytes[
                read_by_size(buf)]
            msg = type_.mapping.bytes[read_by_size(buf)]
            return Owned(self, None, signer, msg)

    @property
    def bytes(self) -> BytesMapping:
        return self.BytesMapping(self)

    def read(self, con: Session, buf: BufferedReader) -> Owned:
        mod = self._mod
        signer = mod.signing_manager.type_signer.mapping.read(buf)
        type_ = mod.restype_manager.type.mapping.read(con, buf)
        msg = type_.mapping.read(con, buf)
        return Owned(self, None, signer, msg)

    @property
    def rtype(self) -> ResType:
        """.owned"""
        return self._mod.type_owned


class MsgBlkMapping(TypedMapping[MsgBlock], Bounded):

    """MsgBlock mapping."""

    def __init__(self, mod: 'ABCMM'):
        super().__init__(mod)
        self._id_map = self.IDMapping(self)
        self._hash_map = self.HashMapping(self)

    def __len__(self) -> int:
        cnt, = next(self._mod.sql_conn.execute("SELECT COUNT(*) FROM block"))
        return cnt

    class IDMapping(UserDict[int, MsgBlock], Inner['MsgBlkMapping']):

        def __init__(self, outer: 'MsgBlkMapping'):
            super().__init__()
            Inner.__init__(self, outer)
            self.data = OrderedDict(self.data)

        def __len__(self) -> int:
            return len(self._outer)

        def __contains__(self, key: int) -> bool:
            return self.get(key) is not None

        def get(self, key: int, default=None):
            if not isinstance(key, int):
                return default

            blks = self.data
            if (blk := blks.get(key)) is not None:
                blks.move_to_end(key)
                return blk

            outer = self._outer
            outer.spare()
            mod = outer.module
            if (row := next(mod.sql_conn.execute("""
                    SELECT id, chain, pos, hash, alg, owner, salt, type, data
                    FROM block WHERE hash = ?
                    """, (key,)), None)) is None:
                return default

            id_, _, _, hash_, *left = row
            blks[id_] = blk = MsgBlock(mod, *row)
            outer.hash.data[hash_] = blk
            return blk

        def __getitem__(self, key: int):
            blks = self.data
            if (blk := blks.get(key)) is not None:
                blks.move_to_end(key)
            else:
                outer = self._outer
                outer.spare()
                blks[key] = blk = MsgBlock(outer.module, key)
            return blk

        def __setitem__(self, key: int, value: MsgBlock):
            self._outer.spare()
            self.data[key] = value

    class HashMapping(UserDict[bytes, MsgBlock], Inner['MsgBlkMapping']):

        def __init__(self, outer: 'MsgBlkMapping'):
            super().__init__()
            Inner.__init__(self, outer)

        def __len__(self):
            return len(self._outer)

        def __contains__(self, key: int) -> bool:
            return self.get(key) is not None

        def get(self, key: int, default=None):
            hash_blks = self.data
            outer = self._outer
            id_blks = outer.rid.data
            if (blk := hash_blks.get(key)) is not None:
                id_blks.move_to_end(blk.rid)
                return blk

            outer.spare()
            mod = outer.module
            if (row := next(mod.sql_conn.execute("""
                    SELECT id, chain, pos, hash, alg, owner, salt, type, data
                    FROM block WHERE hash = ?
                    """, (key,)), None)) is None:
                return default

            id_blks[blk.rid] = blk = MsgBlock(mod, *row)
            hash_blks[key] = blk
            return blk

        def __getitem__(self, key: int):
            if (blk := self.get(key)) is not None:
                return blk

            outer = self._outer
            mod = outer.module
            logging.debug("gen blk %r", key)
            with mod.sql_conn as conn:
                rowid = conn.execute(
                    "INSERT INTO block(hash, chain, pos) VALUES(?, ?, 0)",
                    (key, chain_id := mod._new_chain_id)
                ).lastrowid
                id_, = next(conn.execute(
                    "SELECT id FROM block WHERE rowid = ?", (rowid,)))
            outer.rid.data[blk.rid] = blk = MsgBlock.unknown_block(
                mod, id_, Chain(mod, chain_id), 0, key)
            self.data[key] = blk
            return blk

    def spare(self) -> int | None:
        """Pop a block from ID-block dict if it is full."""
        if len(id_blks := self.rid.data) >= self._mod.blocks_maxlen:
            id_, blk = id_blks.popitem(False)
            if blk.loaded_chain:
                del blk.chain.blocks[blk.position]
            if blk.loaded_hash:
                del self.hash.data[blk.hash]
            return id_
        return None

    def read(self, con: Session, buf: BufferedReader) -> MsgBlock:
        return con.syncs[self._mod, 'msgblk'].read(buf)

    @property
    def rid(self) -> IDMapping:
        """Mapping using ID as key."""
        return self._id_map

    @property
    def bytes(self) -> HashMapping:
        return self._hash_map


in_queue = in_queue('_queue')


class ABCMM(DataBased):

    """Advanced, block-chained, message manager."""

    name = 'abcmm'

    def __init__(
        self,
        database: str,
        blocks_maxlen=1024,
        chains_maxlen=1024,
        sync_blocks_maxlen=128,
        chain_compatability=0,
        find_range=LimitedFinder(16)
    ):
        super().__init__()
        self._blks_maxlen = blocks_maxlen
        self._chains_maxlen = chains_maxlen
        self._syncblks_maxlen = sync_blocks_maxlen
        self._chain_cmpt = chain_compatability
        self.find_range = find_range

        self._rtyper: ResTypeManager = None
        self._singer: SigningManager = None
        self._type_msgblk: ResType = None
        self._type_salted: ResType = None
        self._type_owner: ResType = None
        self._chains: WeakValueDictionary[int, Chain] = WeakValueDictionary()
        self._lost_chain_ids: SortedSet[int] = SortedSet()
        self._max_chain_id = 0
        self._new_blks: Queue[MsgBlock] = Queue()
        self._queue = Queue()
        self._thread = Thread(target=call_forever, args=(self._queue,))

        self._lock = RLock()

    def load_data(self, conn):
        """Load data from database."""
        super().__init__(conn)
        mods = self._account.modules
        self._rtyper = rtyper = mods[ResTypeManager.name]
        self._singer = mods[SigningManager.name]
        self._type_msgblk = type_ = rtyper.type.mapping.str['.msgblk']
        type_.mapping = MsgBlkMapping(self)
        self._type_salted = type_ = rtyper.type.mapping.str['.salted']
        type_.mapping = SaltedMapping(self)
        self._type_owned = type_ = rtyper.type.mapping.str['.owned']
        type_.mapping = OwnedMapping(self)
        with conn:
            conn.executescript("""                
                CREATE TABLE IF NOT EXISTS soblock(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain INTEGER NOT NULL,
                    pos INTEGER NOT NULL,
                    hash BLOB NOT NULL UNIQUE,
                    
                    alg TEXT,
                    owner INTEGER,
                    salt BLOB,
                    
                    type INTEGER,
                    res INTERGER,
                    
                    UNIQUE(chain, pos)
                );
                
                CREATE TABLE IF NOT EXISTS branch(
                    prev_id INTEGER NOT NULL,
                    prev_chain INTEGER NOT NULL,
                    prev_pos INTEGER NOT NULL,
                    next_id INTEGER NOT NULL,
                    next_chain INTEGER NOT NULL,
                    next_pos INTEGER NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS signed_block(
                    blk INTEGER NOT NULL,
                    signer INTEGER NOT NULL
                );
                
                CREATE UNIQUE INDEX IF NOT EXISTS chain_index
                ON block(chain, pos);
                CREATE UNIQUE INDEX IF NOT EXISTS hash_index ON block(hash);
                CREATE INDEX IF NOT EXISTS owner_index ON block(owner);
                CREATE INDEX IF NOT EXISTS type_index ON block(type);
                
                CREATE INDEX IF NOT EXISTS branch_prev_index
                ON branch(prev_chain, prev_pos);
                CREATE INDEX IF NOT EXISTS branch_next_index
                ON branch(next_chain, next_pos);
                
                CREATE INDEX IF NOT EXISTS signed_block_index
                ON signed_block(blk);
            """)

            last = next(conn.execute("SELECT MAX(chain) FROM block"))[0]
            if last is None:
                last = 0
            self._max_chain_id = last
            (chains := SortedSet())[:] = conn.execute(
                "SELECT DISTINCT chain FROM block ORDER BY chain")

        (losts := self._lost_chain_ids)[:] = range(1, last)
        losts -= chains

    def start(self):
        """Start the module."""
        name = self.name
        load = self._account.load_service
        load(name + '.msgblk', self._serv_blk)
        load(name + '.alg', get_servfunc(concat_varname(self, 'alg_sync')))
        self._thread.start()
        logging.debug("module abcmm started")

    @in_queue
    def setup_session(self, con):
        """Session starts."""
        super().setup_session(con)
        name = self.name
        servs = self._account.services
        serv_msgblk, serv_alg = servs[name + '.msgblk'], servs[name + '.alg']
        con.synchronize_service(serv_msgblk, serv_alg)
        syncs = con.syncs
        syncs[self, 'hash'] = DynamicSync()
        syncs[self, 'alg'] = Sync(serv_alg, _ser_str, _deser_alg)

    def stop(self):
        """Stop the thread."""
        super().stop()
        self._queue.put(None)

    def close(self):
        """Close the module."""
        super().close()
        self._chains.clear()

    @in_queue
    def _serv_blk(self, con, buf):
        """Handle received blocks."""
        syncs = con.syncs
        sync_msgblk = syncs[self, 'msgblk']
        sync_alg = syncs[self, 'alg']
        try:
            prev_blks = [self._type_msgblk.mapping.read(con, buf)
                         for _ in range(read_integral(buf))]
        except ValueError:
            buf.read()
            return
        logging.debug("recv blk")
        logging.debug("prev blks %r", prev_blks)
        while buf.peek():
            try:
                alg = sync_alg.read(buf)
                prev_blks = [self._type_msgblk.mapping.read(con, buf)
                             for _ in range(read_integral(buf))]
                msg_type = self._rtyper.type.mapping.read(con, buf)
                msg = msg_type.mapping.read(con, buf)
                # elif (owner := key_sync.read(buf)) is None:
                #     hash_ = read_by_size(buf)
                # else:
                #     logging.debug("alg %r", alg)
                #     logging.debug("owner %r", owner)
                #     salt = read_by_size(buf)
            except ValueError as e:
                logging.debug("recv blk failed %r", e)
                buf.read()
                con.close()
                return

            logging.debug("recv blk materials")
            blk = self.convert_block(alg, prev_blks, msg)
            sync_msgblk.add_to_recvlist(blk.to_bytes())
            self._new_blks.put(blk)
            prev_blks = [blk]

        logging.debug("handled blk")

    def sync_alg(self, con: Session, *algs: str):
        """Send hash algorithms."""
        con.service_sync.write(self.name + '.alg', buf := BytesIO())
        sync = con.syncs[self, 'alg']
        for alg in algs:
            sync.send(alg, buf)
        con.send(buf.getvalue())

    @property
    def _new_chain_id(self):
        """Return a new chain ID."""
        if losts := self._lost_chain_ids:
            return losts.pop(0)
        self._max_chain_id = chain_id = self._max_chain_id + 1
        return chain_id

    def get_chain(self, id_: int) -> Chain:
        """Get a chain."""
        if (chain := (chains := self._chains).get(id_)) is None:
            chains[id_] = chain = Chain(self, id_)
        return chain

    def to_sob(self, msg: Resource) -> tuple[
            bytes | None, Signer | None, Resource]:
        """Convert message of SOBlock into salt-owner-body row."""
        owner = None
        if msg.rtype == self._type_salted and msg.is_decrypted:
            salt = msg.salt
            msg = msg.msg
            if msg.rtype == self._type_owned:
                owner = msg.owner
                msg = msg.msg
        else:
            salt = None
        return salt, owner, msg

    def from_row(self, blk_id: int, alg: str,
                 salt: bytes | None, owner_id: int | None,
                 body_type_id: int, body_id: int) -> Resource:
        """Construct message of SOBlock from data row."""
        type_ = self._rtyper.type.mapping.rid[body_type_id]
        if type_ == self._type_salted and body_id == blk_id:
            # Hidden
            return Salted(self, blk_id, alg, *next(self.sql_conn.execute(
                "SELECT hash FROM salted_hash WHERE id = ?", (body_id,))))

        msg = type_.mapping.rid[body_id]
        if owner_id is not None:
            owner = self._singer.type_signer.mapping.rid[owner_id]
            msg = Owned(self, blk_id, owner, msg)
            type_ = msg.rtype
        if salt is not None:
            msg = Salted(self, blk_id, alg, salt, msg)
        return msg

    def generate_block(self, hash_size: int) -> MsgBlock:
        """Generate an unknown block."""
        return self._type_msgblk.mapping.bytes[token_bytes(hash_size)]

    def construct_block(
        self,
        alg: str,
        prev_blks: Sized,
        msg: Resource
    ) -> MsgBlock:
        """Convert a block from its materials."""
        logging.debug("construct blk alg %r, prev %r, msg %r",
                      alg, prev_blks, msg)
        hash_ = MsgBlock.Material.compute_hash(alg, prev_blks, msg)
        with self._sql_conn as conn:
            blk = self._type_msgblk.mapping.bytes.get(hash_)
            if blk is not None:
                # Block exists
                logging.debug("blk exists")
                blk_id = blk.rid
                if not blk.is_decrypted:
                    # Replace unknown block
                    logging.debug("replace unknown blk")
                    if prev_blks:
                        conn.executemany(
                            "INSERT INTO link(prev, next) VALUES(?, ?)",
                            [(prev_blk.rid, blk_id)
                             for prev_blk in prev_blks])
                        prev_blk = prev_blks[0]
                        chain = prev_blk.chain
                        pos = prev_blk.position + 1
                        params = chain.id, pos, (lost := blk.chain.id)
                        logging.debug("lose %r to %r[%r]",
                                      blk.chain, chain, pos)
                        conn.execute("""
                            UPDATE block SET chain = ?, pos = pos + ?
                            WHERE chain = ?""", params)
                        conn.execute("""
                            UPDATE branch
                            SET prev_chain = ?, prev_pos = prev_pos + ?
                            WHERE prev = ?""", params)
                        conn.execute("""
                            UPDATE branch
                            SET next_chain = ?, next_pos = next_pos + ?
                            WHERE next = ?""", params)
                        if lost >= self._max_chain_id:
                            self._max_chain_id -= 1
                        else:
                            self._lost_chain_ids.add(lost)
                        logging.debug("max chain id %r, lost %r",
                                      self._max_chain_id, lost)
                    else:
                        logging.debug("no chain changed")
                    blk._alg = alg

                salt, owner, body = self.to_sob(msg)
                owner_id = None if owner is None else owner.rid
                if blk.is_decrypted:
                    salted = blk.msg
                    if (salt is None
                        or salted.rtype != self._type_salted
                            or salted.is_decrypted):
                        # Duplicate adding
                        logging.debug("duplicate adding")
                        return blk
                blk._msg = msg
                conn.execute("""
                    UPDATE block
                    SET alg = ?, salt = ?, owner = ?, type = ?, res = ?
                    WHERE id = ?
                    """, (alg, salt, owner_id, msg.rtype.rid, msg.rid, blk_id))
                return blk

            logging.debug("new blk")
            if prev_blks and len(
                    chain := (prev_blk := prev_blks[0]).chain) <= (
                        pos := prev_blk.position + 1):
                logging.debug("insert blk to %r[%r]", chain, pos)
                chain_id = chain.id
            else:
                # Create new chain
                logging.debug("create new chain")
                self._chains[chain_id] = chain = Chain(
                    self, chain_id := self._new_chain_id)
                pos = 0

            if (prev_blks and chain and (brc_ids := chain[0].prev_ids)
                and
                (off :=
                 (brc_blk := self.type_msgblk.mapping.rid[brc_ids[0]]
                  ).position + 1) + pos
                    >= len(prev_chain := brc_blk.chain) + self._chain_cmpt):
                # Do chain-exchange
                # Exchage columns of table block
                conn.execute("""
                    UPDATE block SET chain = -1, pos = pos - ?
                    WHERE chain = ? AND pos >= ?
                    """, (off, prev_chain_id := prev_chain.id, off))
                conn.execute("""
                    UPDATE block SET chain = ?, pos = pos + ?
                    WHERE chain = ?""", (prev_chain_id, off, chain_id))
                conn.execute(
                    "UPDATE block SET chain = ? WHERE chain = -1", (chain_id,))

                # Exchange columns of table branch
                conn.execute("""
                    UPDATE branch SET next_chain = -1, next_pos = next_pos - ?
                    WHERE next_chain = ? AND next_pos >= ?
                    """, (off, chain_id, off))
                conn.execute("""
                    UPDATE branch SET next_chain = ?, next_pos = next_pos + ?
                    WHERE next_chain = ?""", (prev_chain_id, off, chain_id))
                conn.execute("""
                    UPDATE branch SET next_chain = ?, next_pos = next_pos - ?
                    WHERE next_chain = -1""", (chain_id, off))

                conn.execute("""
                    UPDATE branch SET prev_chain = -1, prev_pos = prev_pos - ?
                    WHERE prev_chain = ? AND prev_pos >= ?
                    """, (off, chain_id, off))
                conn.execute("""
                    UPDATE branch SET prev_chain = ?, prev_pos = prev_pos + ?
                    WHERE prev_chain = ?""", (prev_chain_id, off, chain_id))
                conn.execute("""
                    UPDATE branch SET prev_chain = ?, prev_pos = prev_pos - ?
                    WHERE prev_chain = -1""", (chain_id, off))

                chain_blks = chain.blocks
                ext_keys = chain_blks.keys()
                ext_values = chain_blks.values()
                for blk in ext_values:
                    blk._chain = prev_chain
                    blk._pos += off
                    logging.debug("update %r with %r[%r]",
                                  blk, prev_chain, blk.position)

                prev_chain_blks = prev_chain.blocks
                keys = prev_chain_blks.keys()
                values = prev_chain_blks.values()
                i = prev_chain_blks.index(off)
                for blk in values[i:]:
                    blk._chain = chain
                    blk._pos -= off
                    logging.debug("update %r with %r[%r]",
                                  blk, chain, blk.position)

                keys[:], new_keys = keys[:i], keys[i:]
                values[:], new_values = values[:i], values[i:]
                keys += ext_keys
                values += ext_values
                ext_keys[:] = new_keys
                ext_values[:] = new_values

                if chain._len is not None:
                    chain._len -= off
                if prev_chain._len is not None:
                    prev_chain._len += off

                logging.debug("exchange %r[%r:] to %r",
                              prev_chain, off, chain)
                chain = prev_chain
                chain_id = prev_chain_id
                pos += off

            salt, owner, body = self.to_sob(msg)
            owner_id = None if owner is None else owner.rid
            rowid = conn.execute("""
                INSERT INTO block(
                    hash, chain, pos, alg, owner, salt, type, res
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)""", (
                hash_, chain_id, pos,
                alg, owner_id, salt, body.rtype.rid, body.rid)).lastrowid
            blk_id = next(conn.execute(
                "SELECT id FROM block WHERE rowid = ?", (rowid,)))[0]
            blk = MsgBlock(self, blk_id, chain, pos, hash_,
                           alg, msg,
                           tuple(prev_blk.rid for prev_blk in prev_blks),
                           OrderedSet())

            if prev_blk:
                for prev_blk in prev_blks:
                    if (next_ids := prev_blk._next_ids) is not None:
                        next_ids.add(blk_id)
                iter_ = iter(prev_blks)
                if pos and (next_ids := next(iter_)._next_ids) is not None:
                    next_ids.move_to_end(blk_id, False)
                conn.executemany("""
                    INSERT INTO branch(
                        prev_id, prev_chain, prev_pos,
                        next_id, next_chain, next_pos
                    ) VALUES(?, ?, ?, ?, ?, ?)
                    """, ((prev_blk.rid, prev_blk.chain.id, prev_blk.position,
                           blk_id, chain_id, pos) for prev_blk in iter_))
        logging.debug("add %r at %r[%r]", blk, chain, pos)
        self._type_msgblk.mapping.rid[blk_id] = blk
        chain.blocks.items().append((pos, blk))
        # Append block to the end of chain
        if chain._len is not None:
            chain._len += 1
        return blk

    def send_blocks(self, start: Iterable[MsgBlock], stop: Iterable[MsgBlock],
                    con: Session | Address):
        """Send blocks to target."""
        syncs, pkgs = self.fill_block_packs(
            self.pack_blocks(start, stop), con)
        if syncs:
            pkgs = iter_chain(
                (buf.getvalue() for buf in syncs.values()), pkgs)
        con.send(pkgs)

    # def pack_blocks(
    #     self,
    #     graph: Graph
    # ) -> list[tuple[BytesIO, Fillers]]:
    #     """Return block packs to be filled."""
    #     maxlen = self._syncblks_maxlen
    #     blksync_name = concat_varname(self, 'hash_sync')
    #     algsync_name = concat_varname(self, 'alg_sync')
    #     keysync_name = concat_varname(self, 'key_sync')
    #     typesync_name = concat_varname(self, 'type_sync')

    #     next_lvl: list[tuple[MsgBlock, int,
    #                          BytesIO, Fillers, list[bytes]]] = []
    #     packs: list[tuple[BytesIO, Fillers, list[bytes]]] = []

    #     start, stop = graph.start.copy(), graph.stop.copy()
    #     for blk in start:
    #         pass

    #     for blk in start:
    #         write_integral(len(prev_blks := blk.prev),
    #                        buf := BytesIO())
    #         fillers = Fillers((0, blksync_name, prev_blk.hash)
    #                           for prev_blk in prev_blks)
    #         next_lvl.append((blk, len(prev_blks), buf, fillers, hashes := []))
    #         packs.append((buf, fillers, hashes))

    #     while next_lvl:
    #         curr_lvl = next_lvl.copy()
    #         next_lvl.clear()
    #         for blk, cnt, buf, fillers, hashes in curr_lvl:
    #             # Pack block
    #             fillers.append_filler(buf.tell(), algsync_name, blk.algorithm)
    #             if blk.is_unknown:
    #                 continue
    #             fillers.append_filler(buf.tell(), keysync_name, blk.owner)
    #             if blk.is_hidden:
    #                 write_with_size(blk.data, buf)
    #                 #
    #                 continue
    #             else:
    #                 write_with_size(blk.salt, buf)
    #                 fillers.append_filler(buf.tell(), typesync_name, blk.type)
    #                 write_with_size(blk.data, buf)
    #                 hashes.append(blk.hash)
    #             # Try to visit next level
    #             if not (next_blks := blk.next_blocks):
    #                 continue
    #             if (cnt < maxlen
    #                 and
    #                 len(blk := next(new := iter(next_blks)).prev)
    #                     == 1):
    #                 next_lvl.append((blk, cnt + 1, buf, fillers))
    #             else:
    #                 new = next_blks

    #             # Create branch buffers
    #             for blk in new:
    #                 if blk in stop:
    #                     continue
    #                 stop.add(blk)
    #                 write_integral(len(prev_blks := blk.prev),
    #                                buf := BytesIO())
    #                 fillers = Fillers((0, blksync_name, prev_blk.hash)
    #                                   for prev_blk in prev_blks)
    #                 next_lvl.append(
    #                     (blk, len(prev_blks), buf, fillers, hashes := []))
    #                 packs.append((buf, fillers, hashes))

    # def fill_block_packs(
    #     self,
    #     packs: Sequence[tuple[BytesIO, Sequence[Filler], Sequence[bytes]]],
    #     con: Session | Address,
    # ) -> tuple[dict[str, BytesIO], list[bytes]]:
    #     """Fill block packs."""
    #     if isinstance(con, Address):
    #         con = self._account.node.sessions.get(con)
    #         if con is None:
    #             return

    #     serv_sync = con.service_sync
    #     serv_name = self.name + '.msgblk'
    #     syncs = con.syncs
    #     hash_sync: DynamicSync[bytes] = syncs[self, 'msgblk']
    #     senddict = hash_sync.senddict
    #     sync_bufs: dict[str, BytesIO] = {}
    #     filled_packs: list[bytes] = []
    #     for unfilled, fillers, hashes in packs:
    #         serv_sync.write(serv_name, buf := BytesIO())
    #         for step, name, obj in fillers:
    #             sync = vars_[name]

    #             if obj not in sync.sendmap:
    #                 if (sync_buf := sync_bufs.get(name)) is None:
    #                     serv_sync.write(self.syncname_to_servname[name],
    #                                     sync_buf := BytesIO())
    #                     sync_bufs[name] = sync_buf
    #                 sync.send(obj, sync_buf)

    #             buf.write(unfilled.read(step))
    #             sync.write(obj, buf)
    #         buf.write(unfilled.read())
    #         for hash_ in hashes:
    #             if hash_ not in senddict:
    #                 hash_sync.add_to_senddict(hash_)
    #             else:
    #                 senddict.move_to_end(hash_)
    #         filled_packs.append(buf.getvalue())

    #     return sync_bufs, filled_packs

    @property
    def new_blocks(self) -> Queue[MsgBlock]:
        """Return queue of new blocks."""
        return self._new_blks

    @property
    def blocks_maxlen(self) -> int:
        """Maximum size of the dictionary of loaded blocks."""
        return self._blks_maxlen

    @blocks_maxlen.setter
    def blocks_maxlen(self, maxlen: int):
        """Set blocks_maxlen."""
        self._blks_maxlen = maxlen

    @property
    def chains_maxlen(self) -> int:
        """Maximum size of the dictionary of loaded chains."""
        return self._chains_maxlen

    @chains_maxlen.setter
    def chains_maxlen(self, maxlen: int):
        """Set chains_maxlen."""
        self._chains_maxlen = maxlen

    @property
    def chain_compatability(self) -> int:
        """Chain compatability."""
        return self._chain_cmpt

    @chain_compatability.setter
    def chain_compatability(self, compatability: int):
        """Set chain_compatability."""
        self._chain_cmpt = compatability

    @property
    def chains(self) -> WeakValueDictionary[int, Chain]:
        """ID-to-chain dictionary of loaded chains."""
        return self._chains

    @property
    def type_owned(self) -> ResType:
        """.owned"""
        return self._type_owned

    @property
    def type_salted(self) -> ResType:
        """.salted"""
        return self._type_salted

    @property
    def type_msgblk(self) -> ResType:
        """.msgblk"""
        return self._type_msgblk

    @property
    def restype_manager(self) -> ResTypeManager:
        """RTypeMapping instance bounded."""
        return self._rtyper

    @property
    def signing_manager(self) -> ResTypeManager:
        """SigningManager instance bounded."""
        return self._singer
