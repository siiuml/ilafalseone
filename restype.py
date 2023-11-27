# Copyright (c) 2023 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilafalseone.restype

Resource type manager.

"""

import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Iterator, Mapping
from io import BufferedIOBase, BufferedReader, BytesIO
from threading import RLock

from .basemodule import Bound, DataBased
from .session import Session
from .session import Sync, concat_varname, get_servfunc
from .session import Fillers, Syncable, SyncFiller
from .utils import FuncWrapper, WrappedMapping

from .ilfocore.constants import BYTEORDER
from .ilfocore.utils import pack_with_size, read_by_size, write_with_size


ENCODING = 'utf-8'


def encode(data: str) -> bytes:
    """Decode string using UTF-8."""
    return bytes(data, ENCODING)


def decode(data: bytes) -> str:
    """Decode bytes using UTF-8."""
    return str(data, ENCODING)


decodewrap = FuncWrapper[bytes, str](decode, encode, "decodewrap")


class _IOSerializable(ABC):

    """Serializable object class."""

    __slots__ = ()

    @abstractmethod
    def _to_buffered_io(self) -> BufferedIOBase:
        """Return a buffered IO."""


class Serializable(_IOSerializable, Syncable):

    """Serializable class."""

    __slots__ = ()

    def _to_buffered_io(self) -> BufferedIOBase:
        return BytesIO(self.to_bytes())

    def to_fillers(self, fillers: Fillers):
        fillers.append(pack_with_size(self.to_bytes()))

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Convert all data to bytes."""

    @property
    def rdig(self) -> bytes:
        """Digested bytes."""
        return self.to_bytes()

    @property
    @abstractmethod
    def rtype(self) -> 'ResType':
        """Resource type."""

    def __eq__(self, other) -> bool:
        return (self is other
                or isinstance(other, Serializable)
                and self.rtype == other.rtype and self.rdig == other.rdig)

    def __hash__(self) -> int:
        return hash((self.rtype, self.rdig))

    def __str__(self) -> str:
        return self.rdig.hex()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self}>"

    def __index__(self) -> int:
        return int.from_bytes(self.rdig, BYTEORDER)


class Resource(Serializable):

    """Resource class."""

    __slots__ = ()

    def __eq__(self, other) -> bool:
        return (self is other
                or self.rtype == other.rtype and self.rid == other.rid)

    def __hash__(self) -> int:
        return hash((self.rtype, self.rid))

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.rid}>"

    @property
    @abstractmethod
    def rid(self) -> int:
        """Resource ID."""


class TypedMapping[T: Serializable](ABC):

    """Typed resources mapping."""

    __slots__ = ()

    def __contains__(self, res: T):
        return isinstance(res, Serializable) and res.rtype == self.rtype

    def __len__(self) -> int:
        return len(self.rdig)

    def __iter__(self) -> Iterator[T]:
        yield from self.rdig.values()

    def read(self, con: Session, buf: BufferedReader) -> T:
        """Read resource from received buffer."""
        return self.bytes[read_by_size(buf)]

    @property
    @abstractmethod
    def bytes(self) -> Mapping[bytes, T]:
        """Mapping using serialized bytes as key."""

    @property
    def rdig(self) -> Mapping[bytes, T]:
        """Mapping using digested bytes as key."""
        return self.bytes

    @property
    @abstractmethod
    def rtype(self) -> 'ResType[T]':
        """Resource type of the keys in mapping."""


class ResType[T: Serializable](Resource, Bound):

    """Resource type class."""

    __slots__ = '_mod', '_id', '__data', '_mapping'

    def __init__(self, mod: 'ResTypeManager', id_: int, type_str: str):
        self._mod = mod
        Resource.__init__(self, id_)
        self.__data = type_str

    def to_fillers(self, fillers: Fillers):
        fillers.append(SyncFiller((self._mod, 'type'), self))

    def to_bytes(self) -> bytes:
        return encode(str(self))

    def __str__(self) -> str:
        return self.__data

    __repr__ = __str__

    def __eq__(self, other) -> bool:
        return self is other or str(self) == str(other)

    def __hash__(self) -> int:
        return hash(str(self))

    @property
    def mapping(self) -> TypedMapping[T]:
        """Mapping."""
        return self._mapping

    @mapping.setter
    def mapping(self, mapping: TypedMapping[T]):
        """Set maps."""
        self._mapping = mapping

    @property
    def rtype(self) -> 'ResType[ResType]':
        """.type"""
        return self._mod.type

    @property
    def rid(self) -> int:
        return self._id

    @property
    def module(self) -> 'ResTypeManager':
        return self._mod


class WithMsg[T: Serializable](Serializable):

    """Serializable object with an inner message."""

    __slots__ = ()

    def to_fillers(self, fillers: Fillers):
        msg = self.msg
        msg.rtype.to_fillers(fillers)
        msg.to_fillers(fillers)

    def to_bytes(self) -> bytes:
        msg = self.msg
        return pack_with_size(msg.rtype.to_bytes()) + msg.to_bytes()

    @property
    def rdig(self) -> bytes:
        msg = self.msg
        return pack_with_size(msg.rtype.rdig) + msg.rdig

    @property
    @abstractmethod
    def msg(self) -> T:
        """Inner serializable message."""


class RTypeMapping(TypedMapping[ResType], Bound):

    """Type mapping."""

    __slots__ = '_mod', '_id_map', '_str_map'

    def __init__(self, mod: 'ResTypeManager'):
        self._mod = mod
        self._id_map = {}
        self._str_map = defaultdict(self._factory)

    def _factory(self, type_str: str) -> ResType:
        mod = self._mod
        with mod.sql_conn as conn:
            rowid = conn.execute(
                "INSERT INTO res_type(type) VALUE(?)", (type_str,)).lastrowid
            id_, = next(conn.execute(
                "SELECT id FROM res_type WHERE rowid = ?", (rowid,)))
        self.add(type_ := ResType(mod, id_, type_str))
        return type_

    def add(self, type_: ResType):
        self._id_map[type_.rid] = type_
        self._str_map[str(type_)] = type_

    def read(self, con: Session, buf: BufferedReader) -> ResType:
        """Read resource from received buffer."""
        return con.syncs[self._mod, 'type'].read(buf)

    @property
    def rid(self) -> dict[int, ResType]:
        """ID-to-rtype Mapping."""
        return self._id_map

    @property
    def str(self) -> defaultdict[str, ResType]:
        """Type-string-to-rtype Mapping."""
        return self._str_map

    @property
    def bytes(self) -> WrappedMapping[bytes, ResType, str, ResType]:
        return WrappedMapping(self._str_map, decodewrap)

    @property
    def rtype(self) -> ResType[ResType]:
        """.type"""
        return self._mod.type

    @property
    def module(self) -> 'ResTypeManager':
        return self._mod


class ResTypeManager(DataBased):

    """Global resource manager."""

    name = '.restype'

    def __init__(self, sync_blocks_maxlen=128):
        super().__init__()
        self._type = type_ = ResType[ResType](self, None, '.type')
        self._mapping = type_.mapping = RTypeMapping(self)
        self._lock = RLock()

    def load_data(self, conn):
        """Load data from database."""
        super().load_data(conn)
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS res_type(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type INTEGER NOT NULL UNIQUE
                )""")
            row = next(conn.execute("SELECT id FROM res_type WHERE type = ",
                                    ('.type',)), None)
            type_ = self._type
            type_._rid, = next(conn.execute(
                "SELECT id FROM res_type WHERE rowid = ", (
                    conn.execute("INSERT INTO res_type(type) VALUES(?)",
                                 ('.type',)).lastrowid,
                ))) if row is None else row
            type_.mapping.rid.update(
                row for row in conn.execute(
                    "SELECT id, type FROM res_type WHERE type != ?",
                    ('.type',)))

    def start(self):
        """Account starts."""
        super().start()
        self._account.load_service(self.name + 'typesync',
                                   get_servfunc(concat_varname(self, 'type')))
        logging.debug("module rtyper started")

    def setup_session(self, con):
        """Session starts."""
        super().setup_session(con)
        con.syncs[self, 'type'] = Sync(con, self._ser_type, self._deser_type)

    @staticmethod
    def _ser_type(self, type_: ResType, buf: BufferedIOBase) -> int:
        """Serialize a ResType object into buffer."""
        return write_with_size(type_.to_bytes(), buf)

    def _deser_type(self, buf: BufferedReader) -> ResType:
        """Deserialize a ResType object from buffer."""
        return self._type.mapping.bytes[read_by_size(buf)]

    def sync_type(self, con: Session, *types: ResType):
        """Send data types."""
        con.service_sync.write(self.name + '.type', buf := BytesIO())
        sync = con.syncs[self, 'type']
        for typ in types:
            sync.send(typ, buf)
        con.send(buf.getvalue())

    @property
    def mapping(self) -> RTypeMapping:
        """.type mapping."""
        return self._mapping

    @property
    def type(self) -> ResType[ResType]:
        """.type"""
        return self._type
