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
    Collection,
    Iterable,
    Iterator,
    Mapping,
    Sequence
)
from dataclasses import dataclass
from hashlib import new as get_hasher
from io import BufferedIOBase, BufferedReader, BytesIO
from queue import Queue
from secrets import token_bytes
from threading import RLock, Thread
from weakref import WeakValueDictionary
from typing import Any, Self, Union

from .ilfocore.utils import (
    NULL,
    pack_with_size,
    read_by_size,
    read_integral,
    write_integral,
    write_with_size
)
from .ilfocore.utils.multithread import call_forever, in_queue

from .basemodule import Bound as _Bound, DataBased
from .session import Session, concat_varname, get_servfunc
from .session import SYNC_MARK, RecvList, SendDict, Sync, ser_str, deser_str
from .session import Filler, Fillers, SyncFiller

from .decreq import Cryptic as _Cryptic, InnerRes, InnerSer
from .restype import (
    ResType,
    ResTypeManager,
    Resource,
    Serializable,
    TypedMapping,
    WithMsg,
    encode
)
from .signing import Signer, SigningManager

from .utils import Inner, OrderedSet, SortedDict, SortedSet
from .utils import FuncWrapper, WrappedSequence


class Bound(_Bound['ABCMM']):

    """The class of objects binding to ABCMM."""

    def __init__(self, mod):
        self._mod = mod

    def module(self) -> 'ABCMM':
        """ABCMM module."""
        return self._mod


class Cryptic(_Cryptic):

    """New Cryptic interface."""

    __slots__ = ()

    @abstractmethod
    def Material[T: Cryptic](self) -> InnerSer:
        """Inner Material class."""

    @property
    def material(self) -> InnerSer[Self] | None:
        return self.Material(self) if self.is_decrypted else None


class Hashed(Cryptic):

    """Hashed class."""

    __slots__ = ()

    class OtherMat[T: Hashed](InnerRes[T]):

        """Material without hash algorithm."""

        def __eq__(self, other) -> bool:
            return (self is other
                    or isinstance(other, self.__class__)
                    and self.rdig == other.rdig)

        def __hash__(self) -> int:
            return hash((self.__class__, self.rdig))

        @property
        def rtype(self) -> bytes:
            raise NotImplementedError

    class Material[T: Hashed](InnerRes[T]):

        """Material class."""

        def Other(self) -> 'Hashed.OtherMat[T]':
            """Other material class."""
            return self._outer.OtherMat

        def to_fillers(self, fillers: Fillers):
            outer = self._outer
            fillers.append(SyncFiller(
                ('ABCMM', 'alg'), alg := outer.algorithm))
            if alg is None:
                fillers.append(outer.rdig)
            else:
                self.Other(outer).to_fillers(fillers)

        def to_bytes(self) -> bytes:
            outer = self._outer
            if (alg := outer.algorithm) is None:
                return outer.to_bytes()
            return pack_with_size(encode(alg)) + self.Other(outer).to_bytes()

    def to_fillers(self, fillers: Fillers):
        fillers.append(NULL + self.rdig)

    def to_bytes(self) -> bytes:
        return NULL + self.rdig

    def compute_hash(self) -> bytes:
        """Compute hash of the resource."""
        return get_hasher(
            self.algorithm, self.OtherMat(self).rdig
        ).digest()

    @property
    def is_decrypted(self) -> bool:
        return self.algorithm is not None

    @property
    def algorithm(self) -> str:
        """Hash algorithm."""


class Owned[T: Resource](WithMsg[T], Resource, _Bound):

    """Resource with its owner."""

    __slots__ = '_mod', '_id', '_owner', '_msg'

    def __init__(self, mod: 'ABCMM', id_: int, owner: Signer, msg: Resource):
        self._mod = mod
        self._id = id_
        self._owner = owner
        self._msg = msg

    def __eq__(self, other):
        return (self is other
                or isinstance(other, Owned)
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
    def msg(self) -> Resource:
        return self._msg

    @property
    def rid(self) -> int:
        return self._id

    @property
    def rtype(self) -> ResType:
        """.owned"""
        return self._mod.restype_manager.mapping.str['.owned']

    @property
    def module(self) -> 'ABCMM':
        return self._mod


class Salted[T: Resource](WithMsg[T], Resource, Hashed, _Bound):

    """Cryptic resource with salt."""

    __slots__ = '_mod', '_id', '_hash', '_alg', '_salt'

    def __init__(self, mod: 'ABCMM', id_: int, alg: str | None, *args):
        self._mod = mod
        self._id = id_
        self._alg = alg
        if alg is None:
            self._hash, = args
            self._salt = self._msg = None
        else:
            self._salt, self._msg = args

    class OtherMat(Hashed.OtherMat['Salted']):

        """OtherMat class of Salted class."""

        def to_fillers(self, fillers: Fillers):
            outer = self._outer
            fillers.append(outer.salt)
            WithMsg.to_fillers(outer, fillers)

        def to_bytes(self) -> bytes:
            outer = self._outer
            return pack_with_size(outer.salt) + WithMsg.to_bytes(outer)

        @property
        def rdig(self) -> bytes:
            outer = self._outer
            pack_with_size(outer.salt) + WithMsg.rdig.fget(outer)

    @property
    def algorithm(self) -> str:
        """Hash algorithm."""
        return self._alg

    @property
    def salt(self) -> bytes:
        """Random bytes."""
        return self._salt

    @property
    def msg(self) -> Resource:
        return self._msg

    @property
    def rid(self) -> int:
        return self._id

    @property
    def rdig(self) -> bytes:
        return self.compute_hash() if self.is_decrypted else self._hash

    @property
    def rtype(self) -> ResType:
        """.salted"""
        return self._mod.restype_manager.mapping.str['.salted']

    @property
    def module(self) -> 'ABCMM':
        return self._mod


type Checker = Callable[[MsgBlock], bool]


def break_here(blk: 'MsgBlock') -> bool:
    """Break after current action."""
    return True

def continue_here(blk: 'MsgBlock') -> bool:
    """Do not break after current action."""
    return False


class MsgBlock[T: Serializable](WithMsg[T], Resource, Cryptic, _Bound):

    """MsgBlock class."""

    __slots__ = ('_mod', '_id', '_chain', '_pos', '_hash',
                 '_alg', '_msg',
                 '_prev_ids', '_next_ids', '_sigs', '_signers',
                 '_lock')

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
        self._mod = mod
        self._id = id_
        if isinstance(chain, int):
            chain = mod.get_chain(chain)
            chain.data[pos] = self
        self._chain = chain
        self._pos = pos
        self._hash = hash_

        self._alg = alg
        self._msg = msg

        self._prev_ids = prev_ids
        self._next_ids = next_ids

        self._signers: set[Signer] = None

        self._lock = RLock()

    class OtherMat(Hashed.OtherMat['MsgBlock']):

        """OtherMat class of MsgBlock class."""

        def to_fillers(self, fillers: Fillers):
            outer = self._outer
            fillers.appned(pack_with_size(len(prev_blks := outer.prev)))
            for blk in prev_blks:
                blk.to_fillers(outer, fillers)
            WithMsg.to_fillers(outer, fillers)

        def to_bytes(self, check=break_here) -> bytes:
            outer = self._outer
            write_integral(len(prev_blks := outer.prev), buf := BytesIO())
            for blk in prev_blks:
                write_with_size(blk.to_bytes(check), buf)
            buf.write(WithMsg.to_bytes(outer))
            return buf.getvalue()

        @property
        def rdig(self) -> bytes:
            outer = self._outer
            write_integral(len(prev_blks := outer.prev), buf := BytesIO())
            for blk in prev_blks:
                write_with_size(blk.rdig, buf)
            buf.write(WithMsg.rdig.fget(outer))
            return buf.getvalue()

    class MsgBlkFiller(Filler, Inner['MsgBlock']):

        """MsgBlock filler."""

        def __init__(self, outer: 'MsgBlock', packed: Fillers):
            super().__init__(outer)
            self._packed = packed

        def fill(self, con: Session, buf: BytesIO) -> int:
            """Write the object to be synchorized."""
            outer = self._outer
            mod = outer.module
            sync = con.syncs[mod, 'msgblk']
            if (hash_ := outer.hash) in (senddict := sync.senddict):
                return sync.write(hash_)
            size = con.fill(self._packed, buf)
            senddict[hash_]
            return size

        @property
        def packed(self) -> Fillers:
            """Packed fillers."""
            return self._packed

    class Material(Hashed.Material['MsgBlock']):

        """Material class of MsgBlock class."""

        def to_fillers(self, fillers: Fillers, check=break_here):
            outer = self._outer
            alg = outer.algorithm
            packed = [SyncFiller((outer.module, 'alg'), alg)]
            if alg is None:
                packed.append(outer.rdig)
            else:
                self.Other(outer).to_fillers(packed, check)
            fillers.append(outer.MsgBlkFiller(outer, packed))

        def to_bytes(self, check=break_here) -> bytes:
            outer = self._outer
            if (alg := outer.algorithm) is None:
                return outer.to_bytes()
            return (pack_with_size(encode(alg))
                    + self.Other(outer).to_bytes(check))

    def compute_hash(self, *args) -> bytes:
        """Compute hash of the block to be constructed."""
        if args:
            alg, prev_blks, msg = self, *args
            hasher = get_hasher(alg)
            write_integral(len(prev_blks), buf := BytesIO())
            for blk in prev_blks:
                write_with_size(blk.rdig, buf)
            write_with_size(msg.rtype.rdig, buf)
            buf.write(msg.rdig)
            hasher.update(buf.getbuffer())
            return hasher.digest()

        return super().compute_hash()

    @classmethod
    def unknown_block(cls, mod: 'ABCMM', id_: int, chain_id: int, pos: int,
                      hash_: bytes) -> Self:
        """Construct a unknown block.""",
        return cls(mod, id_, chain_id, pos, hash_)

    def to_fillers(self, fillers: Fillers, check=break_here):
        if check(self) or (mat := self.material) is None:
            fillers.append(SyncFiller((self._mod, 'msgblk'), self.rdig))
        return mat.to_fillers(fillers, check)

    def to_bytes(self, check=break_here) -> bytes:
        if check(self) or (mat := self.material) is None:
            return NULL + self.rdig
        return mat.to_bytes(check)

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
    def rdig(self) -> bytes:
        self.load_data()
        return self._hash

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
            (chain := self._chain).load_hash(*mod.find_to_load(
                chain, self._pos, MsgBlock.loaded_hash.fget))
            return

        chain_id, pos, self._hash, alg, *left = next(mod.sql_conn.execute("""
            SELECT hash, alg, salt, owner, mtype, msg FROM soblock WHERE id = ?
            """, (id_ := self._id,)))
        if alg is not None:
            self._alg = alg
            self._msg = mod.from_row(id_, alg, *left)
        self._chain = chain = mod.get_chain(chain_id)
        self._pos = pos
        chain.data[pos] = self

    @property
    def prev_ids(self) -> tuple[int]:
        """The IDs of previous blocks."""
        if not self.loaded_prev:
            (chain := self._chain).load_branch(*self._mod.find_to_load(
                chain, self._pos, MsgBlock.loaded_prev.fget), True)
        return self._prev_ids

    @property
    def next_ids(self) -> OrderedSet[int]:
        """The IDs of next blocks."""
        if not self.loaded_next:
            (chain := self._chain).load_branch(*self._mod.find_to_load(
                chain, self._pos, MsgBlock.loaded_next.fget), False)
        return self._next_ids

    @property
    def prev(self) -> WrappedSequence[Self, int]:
        """Previous blocks."""
        return WrappedSequence(self._prev_ids, FuncWrapper(
            MsgBlock.rid.fget, self._mod.type_msgblk.mapping.rid.__getitem__))

    @property
    def next(self) -> WrappedSequence[Self, int]:
        """Next blocks."""
        return WrappedSequence(self._next_ids, FuncWrapper(
            MsgBlock.rid.fget, self._mod.type_msgblk.mapping.rid.__getitem__))

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
    def msg(self) -> Resource:
        return self._msg

    @property
    def rid(self) -> int:
        return self._id

    @property
    def rtype(self) -> ResType:
        """.msgblk"""
        return self._mod.restype_manager.mapping.str['.msgblk']

    @property
    def module(self) -> 'ABCMM':
        return self._mod


class BrokenCheck:

    """BrokenCheck class."""

    __slots__ = '_end', '_breaker'

    def __init__(
        self,
        end: Iterable[MsgBlock],
        breaker: Serializable | None = None
    ):
        self._end = {blk: len_ - 1 for blk in end if (len_ := len(blk.next))}
        self._breaker = breaker

    def __call__(self, blk: MsgBlock) -> bool:
        cnt = (end := self._end).get(blk)
        if cnt is not None or blk.msg == self._breaker:
            if cnt:
                end[blk] -= 1
            else:
                del end[blk]
            return True
        if (cnt := len(blk.next) - 2) >= 0:
            end[blk] = cnt
        return False

    @property
    def end(self) -> dict[MsgBlock, int]:
        """Ending blocks."""
        return self._end

    @property
    def breaker(self) -> Serializable:
        """Breaker."""
        return self._breaker


class BrokenGraph(Resource, _Bound):

    """Acyclic graph of blocks whose iteration
    can be stopped by a block with specific body.

    """

    __slots__ = '_mod', '_id', '_start', '_end', '_breaker'

    def __init__(self, mod: 'ABCMM', id_: int,
                 start: Iterable[MsgBlock], end: Iterable[MsgBlock],
                 breaker: Serializable | None = None):
        self._mod = mod
        self._id = id_
        self._start = start = OrderedSet(start),
        self._end = OrderedSet(end) - start
        self._breaker = breaker

    def _iter(self, reverse: bool) -> Iterator[MsgBlock]:
        breaker = self._breaker
        end = set(self._end)
        start = set(self._start) - end
        end |= start
        next_lvl = list(start)
        end = {blk: (len(blk.next) if reverse else len(blk.prev)) - 1
               for blk in end}
        while next_lvl:
            curr_lvl = next_lvl.copy()
            next_lvl.clear()
            for blk in curr_lvl:
                yield blk
                if (cnt := end.get(blk)) is not None or blk.msg == breaker:
                    if cnt:
                        cnt -= 1
                    else:
                        del end[blk]
                    break
                next_lvl += blk.prev if reverse else blk.next
                if cnt := len(blk.prev if reverse else blk.next) - 1:
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
    def rid(self) -> int:
        return self._id

    @property
    def rdig(self) -> bytes:
        raise NotImplementedError

    @property
    def rtype(self) -> ResType:
        """.brkgraph"""
        return self._mod.restype_manager.mapping.str['.brkgraph']

    @property
    def module(self) -> 'ABCMM':
        return self._mod


type Finder = Callable[[Chain, int], tuple[int, int]]


class Graph(BrokenGraph):

    """Acyclic graph of blocks."""

    __slots__ = ()

    def __init__(self, mod: 'ABCMM', id_: int,
                 start: Iterable[MsgBlock], end: Iterable[MsgBlock]):
        super().__init__(mod, id_, start, end)

    def __contains__(self, blk: MsgBlock):
        self._mod.sql_conn.execute("SELECT * FROM soblock WHERE chain WHERE ")
        blk.chain

    @property
    def rdig(self) -> bytes:
        write_integral(len(start := self._start), buf := BytesIO())
        for blk in start:
            write_with_size(blk.rdig, buf)
        for blk in self._end:
            write_with_size(blk.rdig, buf)
        return buf.getvalue()

    @property
    def rtype(self) -> ResType:
        """.graph"""
        return self._mod.restype_manager.mapping.str['.graph']


class Chain(Sequence[MsgBlock], _Bound):


    """Chain."""

    __slots__ = '_mod', '_id', '_blks', '_len', '_lock', '__weakref__'

    def __init__(self, mod: 'ABCMM', id_: int):
        self._mod = mod
        self._id = id_
        self._len: int = None
        self._data: SortedDict[int, MsgBlock] = SortedDict()
        self._lock = RLock()

    def __len__(self) -> int:
        """Return the length of chain."""
        if (len_ := self._len) is None:
            max_, = next(self._mod.sql_conn.execute(
                "SELECT MAX(pos) FROM soblock WHERE chain = ?", (self._id,)))
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
        pos_blks = self._data
        if isinstance(key, int):
            if key < 0:
                key += len(self)
            if key >= len(self) or key < 0:
                return None

            if (blk := pos_blks.get(key, None)) is not None:
                mod.id_blocks.move_to_end(blk.rid)
                return blk
            self.load_hash(*mod.find_to_load(
                self, key, MsgBlock.loaded_hash.fget))
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
        pos_blks = self._data
        keys = pos_blks.keys()
        items = pos_blks.items()
        j = keys.bisect(stop, i := 0)
        for pos, *left in (rsl := mod.sql_conn.execute("""
                SELECT pos, id, hash, alg, salt, owner, mtype, msg FROM soblock
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
            self.load_branch(start, stop, True)
            prev = False
        blks = self[start: stop]
        if prev:
            if start:
                start += 1
        else:
            blks = reversed(blks)
            if stop < len(self):
                stop -= 1
        item = next(items := self.branches(start, stop, prev), None)
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
            while item is not None:
                pos_brc, brc_id, *_ = item
                if pos_brc == pos:
                    if to_load:
                        if prev:
                            prev_ids.apppend(brc_id)
                        else:
                            next_ids.add(brc_id)
                    item = next(items, None)
            if to_load and prev:
                blk._prev_ids = tuple(prev_ids)
            last = blk.rid
            if to_load:
                logging.debug(
                    f"{blk.rid} load context {prev_ids if prev else next_ids}")

    def branches(self, start=0, stop: int = None, prev=True
                 ) -> Iterator[tuple[int, tuple[int, int, int]]]:
        """Return iterator of (pos, brc_id, brc_chain, brc_pos) tuple."""
        end = stop - 1 if stop is not None else len(self)
        if prev:
            rsl = self._mod.sql_conn.execute("""
                SELECT next_pos, prev_id, prev_chain, prev_pos FROM branch
                WHERE next_chain = ? AND next_pos BETWEEN ? AND ?
                ORDER BY next_pos
                """, (self._id, start, end))
        else:
            rsl = self._mod.sql_conn.execute("""
                SELECT prev_pos, next_id, next_chain, next_pos FROM branch
                WHERE prev_chain = ? AND prev_pos BETWEEN ? AND ?
                ORDER BY prev_pos DESC
                """, (self._id, start, end))
        yield from rsl

    def find_slices(self, pos: int, finding: list['Chain', int, int],
                    find: Finder = None):
        rang = find(self, pos) if find is not None else (pos, pos)
        finding.append((self, *rang))
        for _, brc in self.branches:
            chain, pos = brc
            if chain is not self:
                chain.find_slice(pos, finding, find)

    @property
    def id(self) -> int:
        """Chain ID."""
        return self._id

    @property
    def blocks(self) -> SortedDict[int, MsgBlock]:
        """Dictionary of blocks ordered by index of blocks."""
        return self._data

    @property
    def module(self) -> 'ABCMM':
        return self._mod


type ToLoadFinder = Callable[[Chain, int, Checker], tuple[int, int]]


@dataclass(slots=True)
class MonoToLoadFinder:

    """Monodirected to-load range finder class."""

    maxlen: int
    step: int

    def find_mono(self, chain: Chain, pos: int, check: Checker
                  ) -> int:
        """Find a position mono-directly."""
        keys = chain.data.keys()
        values = chain.data.values()

        stop = pos + self.maxlen
        for i in range(keys.bisect(pos), j := len(keys), self.step):
            if (new := keys[i]) >= stop:
                break
            if check(values[i]):
                stop = new
                break
        else:
            if stop > j:
                stop = j
        return stop

    def __call__(self, chain: Chain, pos: int, check: Checker
                 ) -> tuple[int, int]:
        stop = self.find_mono(chain, pos, check)
        return (pos, stop) if pos <= stop else (stop, pos)


@dataclass(slots=True)
class BiToLoadFinder:

    """Bidirected to-load range finder class."""

    backward: int
    forward: int

    def __call__(self, chain: Chain, pos: int, check: Checker
                 ) -> tuple[int, int]:
        return (
            MonoToLoadFinder(self.forward, 1).find_mono(chain, pos, check),
            MonoToLoadFinder(self.backward, -1).find_mono(chain, pos, check)
        )


@dataclass(slots=True)
class TotalToLoadFinder:

    """To-load range finder whose result range length is limited."""

    maxlen: int
    offset: int | None = None

    def __call__(self, chain: Chain, pos: int, check: Checker
                 ) -> tuple[int, int]:
        maxlen, off = self.maxlen, self.offset
        from_ = MonoToLoadFinder(off, -1).find_mono(chain, pos, check)
        to = MonoToLoadFinder(maxlen + off, 1).find_mono(chain, pos, check)
        if (diff := to - from_ - maxlen) < 0:
            from_ = MonoToLoadFinder(diff, -1).find_mono(chain, pos, check)
        return from_, to


class InnerMapping[KT, VT: Serializable, MT: TypedMapping](
        Mapping[KT, VT], Inner[MT]):

    """Inner mapping class."""

    def __len__(self) -> int:
        return len(self._outer)


class SaltedMapping(TypedMapping, Bound):

    _M_ARGS = Salted, 'SalteMapping'

    def __len__(self) -> int:
        conn = self._mod.sql_conn
        not_hidden, = next(conn.execute(
            "SELECT COUNT(*) FROM soblock WHERE salt IS NOT NULL"))
        hidden, = next(conn.execute("SELECT COUNT(*) FROM salted_hash"))
        return not_hidden + hidden

    class IDMapping(InnerMapping[int, *_M_ARGS]):

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

    class HashMapping(InnerMapping[bytes, *_M_ARGS]):

        def __getitem__(self, key: bytes) -> Salted:
            return Salted(self._outer.mod, None, None, key)

    @property
    def hash(self) -> HashMapping:
        """Mapping using hash as key."""
        return self.HashMapping(self)

    class BytesMapping(InnerMapping[bytes, *_M_ARGS]):

        def __getitem__(self, key: bytes) -> Salted:
            mod = self._outer.module
            buf = BytesIO(key)
            if (alg := read_by_size(buf, not_none=False)) is None:
                return self.hash[read_by_size(buf)]
            salt = read_by_size(buf)
            type_ = mod.restype_manager.mapping.bytes[read_by_size(buf)]
            msg = type_.mapping.bytes[buf.read()]
            return Salted(mod, None, alg, salt, msg)

    @property
    def bytes(self) -> BytesMapping:
        return self.BytesMapping(self)

    def read(self, con: Session, buf: BufferedReader) -> Salted:
        mod = self._mod
        if (alg := read_by_size(buf, not_none=False)) is None:
            return self.hash[read_by_size(buf)]
        salt = read_by_size(buf)
        type_ = mod.restype_manager.mapping.read(con, buf)
        msg = type_.mapping.read(con, buf)
        return Salted(mod, None, alg, salt, msg)

    @property
    def rtype(self) -> ResType:
        """.salted"""
        return self._mod.restype_manager.mapping.str['.salted']


class OwnedMapping(TypedMapping[Owned], Bound):

    """Owned resource mapping."""

    _M_ARGS = Owned, 'OwnedMapping'

    def __len__(self) -> int:
        cnt, = next(self._mod.sql_conn.execute(
            "SELECT COUNT(*) FROM soblock WHERE owner IS NOT NULL"))
        return cnt

    class IDMapping(InnerMapping[int, *_M_ARGS]):

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

    class BytesMapping(InnerMapping[bytes, *_M_ARGS]):

        def __getitem__(self, key: bytes) -> Salted:
            mod = self._outer.module
            signer = mod.signing_manager.type_signer.mapping.bytes[
                read_by_size(buf := BytesIO(key))]
            type_ = mod.restype_manager.mapping.bytes[read_by_size(buf)]
            msg = type_.mapping.bytes[buf.read()]
            return Owned(mod, None, signer, msg)

    @property
    def bytes(self) -> BytesMapping:
        return self.BytesMapping(self)

    def read(self, con: Session, buf: BufferedReader) -> Owned:
        mod = self._mod
        signer = mod.signing_manager.type_signer.mapping.read(buf)
        type_ = mod.restype_manager.mapping.read(con, buf)
        msg = type_.mapping.read(con, buf)
        return Owned(mod, None, signer, msg)

    @property
    def rtype(self) -> ResType:
        """.owned"""
        return self._mod.restype_manager.mapping.str['.owned']


class LRUDict[KT, VT](OrderedDict[KT, VT]):

    """LRUDict class."""

    def __init__(self, dict_: Mapping[KT, VT] | Iterable[tuple[KT, VT]],
                 maxsize: int):
        super().__init__(dict_)
        self.maxsize = maxsize


type BlockMaterial = tuple[str, Collection[MsgBlock], Resource]


class MsgBlkMapping(TypedMapping[MsgBlock], Bound):

    """MsgBlock mapping."""

    def __len__(self) -> int:
        cnt, = next(self._mod.sql_conn.execute("SELECT COUNT(*) FROM soblock"))
        return cnt

    def __init__(self, mod: 'ABCMM', loading_maxsize: int):
        super().__init__(mod)
        self._id_map = self.IDMapping(self, loading_maxsize)
        self._hash_map = self.HashMapping(self)

    class IDMapping(UserDict[int, MsgBlock], Inner['MsgBlkMapping']):

        def __init__(self, outer: 'MsgBlkMapping', loading_maxsize: int):
            super().__init__()
            Inner.__init__(self, outer)
            self.data = LRUDict(self.data, loading_maxsize)

        def __len__(self) -> int:
            return len(self._outer)

        def __contains__(self, key: int) -> bool:
            return self.get(key) is not None

        def get(self, key: int, default=None) -> MsgBlock:
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
                    SELECT id, chain, pos, hash, alg, salt, owner, mtype, msg
                    FROM soblock WHERE hash = ?
                    """, (key,)), None)) is None:
                return default

            id_, _, _, hash_, *left = row
            blks[id_] = blk = MsgBlock(mod, *row)
            outer.hash.data[hash_] = blk
            return blk

        def __getitem__(self, key: int) -> MsgBlock:
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

        def __len__(self) -> int:
            return len(self._outer)

        def __contains__(self, key: int) -> bool:
            return self.get(key) is not None

        def get(self, key: int, default=None) -> MsgBlock:
            hash_blks = self.data
            outer = self._outer
            id_blks = outer.rid.data
            if (blk := hash_blks.get(key)) is not None:
                id_blks.move_to_end(blk.rid)
                return blk

            outer.spare()
            mod = outer.module
            if (row := next(mod.sql_conn.execute("""
                    SELECT id, chain, pos, hash, alg, salt, owner, mtype, msg
                    FROM soblock WHERE hash = ?
                    """, (key,)), None)) is None:
                return default

            id_blks[blk.rid] = blk = MsgBlock(mod, *row)
            hash_blks[key] = blk
            return blk

        def __getitem__(self, key: int) -> MsgBlock:
            if (blk := self.get(key)) is not None:
                return blk

            outer = self._outer
            mod = outer.module
            logging.debug("gen blk %r", key)
            with mod.sql_conn as conn:
                rowid = conn.execute(
                    "INSERT INTO soblock(hash, chain, pos) VALUES(?, ?, 0)",
                    (key, chain_id := mod._new_chain_id)
                ).lastrowid
                id_, = next(conn.execute(
                    "SELECT id FROM soblock WHERE rowid = ?", (rowid,)))
            outer.rid.data[blk.rid] = blk = MsgBlock.unknown_block(
                mod, id_, Chain(mod, chain_id), 0, key)
            self.data[key] = blk
            return blk

    class MaterialMapping(Inner['MsgBlkMapping']):

        def __len__(self) -> int:
            return len(self._outer)

        def __getitem__(self, key: BlockMaterial) -> MsgBlock:
            alg, prev_blks, msg, *_ext = key
            outer = self._outer
            mod = outer.module
            logging.debug("construct blk alg %r, prev %r, msg %r",
                          alg, prev_blks, msg)
            if _ext:
                hash_, = _ext
            else:
                hash_ = MsgBlock.compute_hash(alg, prev_blks, msg)
            with mod.sql_conn as conn:
                blk = outer.rdig.get(hash_)
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
                            del mod.chains[lost]
                            logging.debug("max chain id %r, lost %r",
                                          mod.chains.max_id, lost)
                        else:
                            logging.debug("no chain changed")
                        blk._alg = alg

                    salt, owner, body = mod.to_sob(msg)
                    owner_id = None if owner is None else owner.rid
                    if blk.is_decrypted:
                        salted = blk.msg
                        if (salt is None
                            or str(salted.rtype) != 'salted'
                                or salted.is_decrypted):
                            # Duplicate adding
                            logging.debug("duplicate adding")
                            return blk
                    blk._msg = msg
                    conn.execute("""
                        UPDATE soblock
                        SET alg = ?, salt = ?, owner = ?, mtype = ?, msg = ?
                        WHERE id = ?
                        """, (
                        alg, salt, owner_id, msg.rtype.rid, msg.rid, blk_id
                    ))
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
                    chains = mod.chains
                    chains[chain_id] = chain = Chain(
                        mod, chain_id := chains.new_chain_id)
                    pos = 0

                if (prev_blks and chain and (brc_ids := chain[0].prev_ids)
                    and
                    (off :=

                     (brc_blk := outer.rid[brc_ids[0]]).position + 1) + pos
                    >=
                    len(prev_chain := brc_blk.chain) + mod.chain_compatability

                        ):
                    # Do chain-exchange
                    # Exchage columns of table block
                    conn.execute("""
                        UPDATE soblock SET chain = -1, pos = pos - ?
                        WHERE chain = ? AND pos >= ?
                        """, (off, prev_chain_id := prev_chain.id, off))
                    conn.execute("""
                        UPDATE soblock SET chain = ?, pos = pos + ?
                        WHERE chain = ?""", (prev_chain_id, off, chain_id))
                    conn.execute(
                        "UPDATE soblock SET chain = ? WHERE chain = -1",
                        (chain_id,))

                    # Exchange columns of table branch
                    conn.execute("""
                        UPDATE branch
                        SET next_chain = -1, next_pos = next_pos - ?
                        WHERE next_chain = ? AND next_pos >= ?
                        """, (off, chain_id, off))
                    conn.execute("""
                        UPDATE branch
                        SET next_chain = ?, next_pos = next_pos + ?
                        WHERE next_chain = ?
                        """, (prev_chain_id, off, chain_id))
                    conn.execute("""
                        UPDATE branch
                        SET next_chain = ?, next_pos = next_pos - ?
                        WHERE next_chain = -1""", (chain_id, off))

                    conn.execute("""
                        UPDATE branch
                        SET prev_chain = -1, prev_pos = prev_pos - ?
                        WHERE prev_chain = ? AND prev_pos >= ?
                        """, (off, chain_id, off))
                    conn.execute("""
                        UPDATE branch
                        SET prev_chain = ?, prev_pos = prev_pos + ?
                        WHERE prev_chain = ?
                        """, (prev_chain_id, off, chain_id))
                    conn.execute("""
                        UPDATE branch
                        SET prev_chain = ?, prev_pos = prev_pos - ?
                        WHERE prev_chain = -1""", (chain_id, off))

                    chain_blks = chain.data
                    ext_keys = chain_blks.keys()
                    ext_values = chain_blks.values()
                    for blk in ext_values:
                        blk._chain = prev_chain
                        blk._pos += off
                        logging.debug("update %r with %r[%r]",
                                      blk, prev_chain, blk.position)

                    prev_chain_blks = prev_chain.data
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

                salt, owner, body = mod.to_sob(msg)
                owner_id = None if owner is None else owner.rid
                rowid = conn.execute("""
                    INSERT INTO soblock(
                        hash, chain, pos, alg, salt, owner, mtype, msg
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)""", (
                    hash_, chain_id, pos,
                    alg, salt, owner_id, body.rtype.rid, body.rid)).lastrowid
                blk_id = next(conn.execute(
                    "SELECT id FROM soblock WHERE rowid = ?", (rowid,)))[0]
                blk = MsgBlock(mod, blk_id, chain, pos, hash_, alg, msg,
                               tuple(prev_blk.rid for prev_blk in prev_blks),
                               OrderedSet())

                if prev_blk:
                    for prev_blk in prev_blks:
                        if (next_ids := prev_blk._next_ids) is not None:
                            next_ids.add(blk_id)
                    iter_ = iter(prev_blks)
                    if pos and (
                            next_ids := next(iter_)._next_ids) is not None:
                        next_ids.move_to_end(blk_id, False)
                    conn.executemany("""
                        INSERT INTO branch(
                            prev_id, prev_chain, prev_pos,
                            next_id, next_chain, next_pos
                        ) VALUES(?, ?, ?, ?, ?, ?)
                        """, (
                        (prev_blk.rid, prev_blk.chain.id, prev_blk.position,
                         blk_id, chain_id, pos) for prev_blk in iter_))
            logging.debug("add %r at %r[%r]", blk, chain, pos)
            outer.rid[blk_id] = blk
            chain.data.items().append((pos, blk))
            # Append block to the end of chain
            if chain._len is not None:
                chain._len += 1
            return blk

    class BytesMapping(Inner['MsgBlkMapping']):

        def __contains__(self, key: int) -> bool:
            return self.get(key) is not None

        def __getitem__(self, key: int) -> MsgBlock:
            outer = self._outer
            mod = outer.module
            outer.rdig.get(key)
            alg = read_by_size(buf := BytesIO(key), not_none=False)
            if alg is None:
                blk = outer.rdig[buf.read()]
                logging.debug("read blk hash in bytes")
            else:
                prev_blks = [self[read_by_size(buf)]
                             for _ in range(read_integral(buf))]
                type_ = mod.restype_manager.mapping.bytes[
                    read_by_size(buf)]
                msg = type_.mapping.bytes[buf.read()]
                blk = outer.material[alg, prev_blks, msg]
                logging.debug("read blk materials in bytes")
            return blk

    @property
    def material(self) -> MaterialMapping:
        """Mapping using block materials as key."""
        return self.MaterialMapping(self)

    @property
    def rid(self) -> IDMapping:
        """Mapping using ID as key."""
        return self._id_map

    @property
    def rdig(self) -> HashMapping:
        return self.HashMapping(self)

    @property
    def bytes(self) -> BytesMapping:
        return self.BytesMapping(self)

    def spare(self) -> int | None:
        """Pop a block from ID-block dict if it is full."""
        if len(id_blks := self.rid.data) >= id_blks.maxsize:
            id_, blk = id_blks.popitem(False)
            if blk.loaded_chain:
                del blk.chain.data[blk.position]
            if blk.loaded_hash:
                del self.hash.data[blk.hash]
            return id_
        return None

    def read(self, con: Session, buf: BufferedReader) -> MsgBlock:
        return self.rdig[con.syncs[self._mod, 'msgblk'].read(buf)]

    @property
    def rtype(self) -> ResType:
        """.msgblk"""
        return self._mod.restype_manager.mapping.str['.msgblk']


class ChainMapping(Mapping[int, Chain], Bound):

    """Chain Mapping class."""

    def __init__(self, mod: 'ABCMM'):
        super().__init__(mod)
        self._data = WeakValueDictionary[int, Chain]()
        self._lost_ids = SortedSet[int]()
        self._max_id = 0

    def load_data(self):
        with self._mod.sql_conn as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS soblock(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain INTEGER NOT NULL,
                    pos INTEGER NOT NULL,
                    hash BLOB NOT NULL UNIQUE,
                    
                    alg TEXT,
                    owner INTEGER,
                    salt BLOB,
                    
                    mtype INTEGER,
                    msg INTERGER,
                    
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
                
                CREATE TABLE IF NOT EXISTS signed_chain(
                    chain INTEGER NOT NULL,
                    start INTEGER NOT NULL,
                    end INTEGER NOT NULL,
                    signer INTEGER NOT NULL
                );
                
                CREATE UNIQUE INDEX IF NOT EXISTS chain_index
                ON soblock(chain, pos);
                CREATE UNIQUE INDEX IF NOT EXISTS hash_index ON soblock(hash);
                CREATE INDEX IF NOT EXISTS owner_index ON soblock(owner);
                CREATE INDEX IF NOT EXISTS mtype_index ON soblock(mtype);
                
                CREATE INDEX IF NOT EXISTS branch_prev_index
                ON branch(prev_chain, prev_pos);
                CREATE INDEX IF NOT EXISTS branch_next_index
                ON branch(next_chain, next_pos);
                
                CREATE INDEX IF NOT EXISTS signed_block_index
                ON signed_block(blk);
            """)

            last, = next(conn.execute("SELECT MAX(chain) FROM soblock"))
            if last is None:
                last = 0
            self._max_id = last
            (chains := SortedSet())[:] = conn.execute(
                "SELECT DISTINCT chain FROM soblock ORDER BY chain")

        (losts := self._lost_ids)[:] = range(1, last)
        losts -= chains

    def __len__(self) -> int:
        return self._max_id - len(self._lost_ids)

    def __iter__(self) -> Iterator[int]:
        i = 1
        while i <= self._max_id:
            if i not in self._lost_ids:
                yield i
            i += 1

    def __contains__(self, id_: int) -> bool:
        return id_ not in self._lost_ids and id_ <= self._max_id

    def get(self, id_: int, default: None) -> Chain:
        if (chain := (chains := self._chains).get(id_)) is None:
            if id_ not in self:
                return default
            chains[id_] = chain = Chain(self, id_)
        return chain

    def __getitem__(self, id_: int) -> Chain:
        if (chain := (chains := self._chains).get(id_)) is None:
            chains[id_] = chain = Chain(self, id_)
        return chain

    def __delitem__(self, id_: int):
        if id_ >= self._max_id:
            self._max_id -= 1
        else:
            self._lost_ids.add(id_)

    @property
    def new_chain_id(self):
        """Return a new chain ID."""
        if losts := self._lost_ids:
            return losts.pop(0)
        self._max_id = chain_id = self._max_id + 1
        return chain_id

    @property
    def data(self) -> WeakValueDictionary[int, Chain]:
        """ID-to-chain dictionary of loaded chains."""
        return self._data

    @property
    def lost_ids(self) -> SortedSet[int]:
        return self._lost_ids

    @property
    def max_id(self) -> int:
        return self._max_id


def ser_hashalg(str_: str, buf: BufferedIOBase) -> int:
    """Serialize a hash algorithm into buffer."""
    return ser_str(get_hasher(str_).name, buf)


def deser_hashalg(buf: BufferedReader) -> str:
    """Deserialize a hash algorithm from buffer."""
    return get_hasher(deser_str(buf)).name


class _MsgBlkSer(Bound):

    def __init__(self, mod: 'ABCMM'):
        super().__init__(mod)
        self._sync: Sync = None

    @staticmethod
    def ser(hash_: bytes, buf: BufferedIOBase) -> int:
        return buf.write(NULL) + write_with_size(hash_, buf)

    def deser(self, buf: BufferedIOBase) -> bytes:
        mod = self._mod
        maps = mod.mapping_msgblk
        if (alg := read_by_size(buf, not_none=False)) is None:
            logging.debug("read blk hash")
            hash_ = read_by_size(buf)
        else:
            sync = self._sync
            con = sync.session
            prev_blks = [sync.read(buf) for _ in range(read_integral(buf))]
            msg = (mod.restype_manager
                   .mapping.read(con, buf)
                   .mapping.read(con, buf))
            hash_ = MsgBlock.compute_hash(alg, prev_blks, msg)
            logging.debug("read blk materials")
        if hash_ not in (rid_map := maps.rid):
            mod.new_blocks.put(rid_map[hash_] if alg is None else
                               maps.material[alg, prev_blks, msg, hash_])
        return hash_

    @property
    def sync(self) -> Sync:
        """The Sync object bound."""
        return self._sync

    @sync.setter
    def sync(self, sync: Sync):
        """Set sync."""
        self._sync = sync


in_queue = in_queue('_queue')


class ABCMM(DataBased):

    """Advanced, block-chained, message manager."""

    name = 'abcmm'

    def __init__(
        self,
        blocks_maxlen=1024,
        sync_blocks_maxlen=128,
        chain_compatability=0,
        find_to_load=TotalToLoadFinder(16)
    ):
        super().__init__()

        self._syncblks_maxlen = sync_blocks_maxlen
        self._chain_cmpt = chain_compatability
        self.find_to_load = find_to_load

        self._rtyper: ResTypeManager = None
        self._singer: SigningManager = None
        self._maps_msgblk = MsgBlkMapping(self, blocks_maxlen)
        self._maps_salted = SaltedMapping(self)
        self._maps_owned = OwnedMapping(self)
        self._chains = ChainMapping(self)

        self._new_blks: Queue[MsgBlock] = Queue()
        self._queue = Queue()
        self._thread = Thread(target=call_forever, args=(self._queue,))
        self._lock = RLock()

    def load_data(self, conn):
        """Load data from database."""
        super().__init__(conn)

        mods = self._account.modules
        self._singer = mods[SigningManager.name]
        self._rtyper = rtyper = mods[ResTypeManager.name]
        str_types = rtyper.mapping
        str_types.mapping.str['.msgblk'].mapping = self._maps_msgblk
        str_types.mapping.str['.salted'].mapping = self._maps_salted
        str_types.mapping.str['.owned'].mapping = self._maps_owned

        self._chains.load_data()

    def start(self):
        """Start the module."""
        name = self.name
        load = self._account.load_service
        load(name + '.msgblk', self._serv_blk)
        load(name + '.algsync',
             get_servfunc(concat_varname(self, 'alg')))
        self._thread.start()
        logging.debug("module abcmm started")

    @in_queue
    def setup_session(self, con):
        """Session starts."""
        super().setup_session(con)
        syncs = con.syncs
        syncs[self, 'alg'] = Sync(con, ser_hashalg, deser_hashalg)
        mbser = _MsgBlkSer(self)
        syncs[self, 'msgblk'] = mbser.sync = Sync(
            con,
            mbser.ser,
            mbser.deser,
            SendDict(lru=True),
            RecvList(lru=True),
            SYNC_MARK
        )

    def stop(self):
        """Stop the thread."""
        super().stop()
        self._queue.put(None)

    def close(self):
        """Close the module."""
        super().close()
        self._chains.data.clear()

    @in_queue
    def _serv_msgblk(self, con, buf):
        """Handle received block data."""
        try:
            self._maps_msgblk.read(con, buf)
            logging.debug("handled blk")
        except ValueError as e:
            logging.debug("recv blk failed %r", e)
            buf.read()
            con.close()

    def sync_alg(self, con: Session, *algs: str):
        """Send hash algorithms."""
        con.service_sync.write(self.name + '.alg', buf := BytesIO())
        sync = con.syncs[self, 'alg']
        for alg in algs:
            sync.send(alg, buf)
        con.send(buf.getvalue())

    def to_sob(self, msg: Resource) -> tuple[
            bytes | None, Signer | None, Resource]:
        """Convert message of SOBlock into salt-owner-body row."""
        owner = None
        if str(msg.rtype) == 'salted' and msg.is_decrypted:
            salt = msg.salt
            msg = msg.msg
            if str(msg.rtype) == 'owned':
                owner = msg.owner
                msg = msg.msg
        else:
            salt = None
        return salt, owner, msg

    def from_row(self, blk_id: int, alg: str,
                 salt: bytes | None, owner_id: int | None,
                 body_type_id: int, body_id: int) -> Resource:
        """Construct message of SOBlock from data row."""
        type_ = self._rtyper.mapping.rid[body_type_id]
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
        return self._maps_msgblk.rdig[token_bytes(hash_size)]

    def pack_blocks(self, graph: Graph) -> Fillers:
        """Pack blocks into fillers."""
        fillers = []
        check = BrokenCheck((start := graph.start) | graph.end)
        for blk in start:
            blk.to_fillers(fillers, check)
        return fillers

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
    def chain_compatability(self) -> int:
        """Chain compatability."""
        return self._chain_cmpt

    @chain_compatability.setter
    def chain_compatability(self, compatability: int):
        """Set chain_compatability."""
        self._chain_cmpt = compatability

    @property
    def chains(self) -> ChainMapping[int, Chain]:
        """Chains mapping."""
        return self._chains

    @property
    def mapping_owned(self) -> ResType:
        """.owned mapping."""
        return self._maps_owned

    @property
    def mapping_salted(self) -> ResType:
        """.salted mapping."""
        return self._maps_salted

    @property
    def mapping_msgblk(self) -> ResType:
        """.msgblk mapping."""
        return self._maps_msgblk

    @property
    def restype_manager(self) -> ResTypeManager:
        """RTypeMapping instance bound."""
        return self._rtyper

    @property
    def signing_manager(self) -> ResTypeManager:
        """SigningManager instance bound."""
        return self._singer
