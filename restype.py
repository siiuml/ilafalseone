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
from collections.abc import Mapping
from io import BufferedIOBase, BufferedReader, BytesIO
from threading import RLock

from .basemodule import Bounded, DataBased
from .session import Session
from .session import Sync, concat_varname, get_servfunc
from .session import Fillers, Syncable, SyncFiller
from .utils import Wrapper, WrappedMapping

from .ilfocore.constants import BYTEORDER
from .ilfocore.utils import pack_with_size, read_by_size, write_with_size


# IDE
T = None

ENCODING = 'utf-8'


def encode(data: str) -> bytes:
    """Decode string using UTF-8."""
    return bytes(data, ENCODING)


def decode(data: bytes) -> str:
    """Decode bytes using UTF-8."""
    return str(data, ENCODING)


class DecodingWrapper(Wrapper):

    """Bytes to string."""

    __slots__ = ()

    extract = decode
    expand = encode

    def __repr__(self) -> str:
        return 'decodewrap'


decodewrap = DecodingWrapper()


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
        """Convert to bytes."""

    @property
    @abstractmethod
    def rtype(self) -> 'ResType':
        """Resource type."""

    def __eq__(self, other) -> bool:
        return (self is other
                or self.rtype == other.rtype
                and self.to_bytes() == other.to_bytes())

    def __hash__(self) -> int:
        return hash((self.rtype, self.to_bytes()))

    def __str__(self) -> str:
        return self.to_bytes().hex()

    def __index__(self) -> int:
        return int.from_bytes(self.to_bytes(), BYTEORDER)


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
    @abstractmethod
    def msg(self) -> T:
        """Inner serializable message."""


class Cryptic(Serializable):

    """Cryptic class."""

    __slots__ = ()

    @property
    @abstractmethod
    def material(self) -> Serializable | None:
        """Material."""

    def is_decrypted(self) -> bool:
        """If self is decrypted."""
        return self.material is not None


class Resource(Serializable):

    """Resource class."""

    def __init__(self, id_: int):
        self._rid = id_

    def __eq__(self, other) -> bool:
        return (self is other
                or self.rtype == other.rtype and self._rid == other._rid)

    def __hash__(self) -> int:
        return hash((self.rtype, self._rid))

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self._rid}>"

    @property
    def rid(self) -> int:
        """Resource ID."""
        return self._rid


class TypedMapping[T: Serializable](ABC):

    """Typed resources mapping."""

    __slots__ = ()

    def __contains__(self, res):
        return isinstance(res, Serializable) and res.rtype == self.rtype

    def __len__(self):
        return len(self.bytes)

    def __iter__(self):
        yield from self.bytes.values()

    def read(self, con: Session, buf: BufferedReader) -> T:
        """Read resource from received buffer."""
        return self.bytes[read_by_size(buf)]

    @property
    @abstractmethod
    def bytes(self) -> Mapping[bytes, T]:
        """Mapping using serialized bytes as key."""

    @property
    @abstractmethod
    def rtype(self) -> 'ResType':
        """Resource type of the keys in mapping."""


class ResType(Resource, Bounded):

    """Resource type class."""

    __slots__ = '_mod', '__data', '_mapping'

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
    def mapping(self) -> 'TypedMapping':
        """Mapping."""
        return self._mapping

    @mapping.setter
    def mapping(self, mapping: 'TypedMapping'):
        """Set maps."""
        self._mapping = mapping

    @property
    def rtype(self) -> 'ResType':
        """.type"""
        return self._mod.type

    @property
    def module(self) -> 'ResTypeManager':
        return self._mod


class RTypeMapping(TypedMapping[ResType], Bounded):

    """Type mapping."""

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

    def read(self, con: Session, buf: BufferedReader) -> T:
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
    def rtype(self) -> 'ResType':
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
        self._type = type_ = ResType(self, None, '.type')
        type_.mapping = RTypeMapping(self)
        self._lock = RLock()

    def load_data(self, database: str):
        """Load data from database."""
        super().__init__(database, check_same_thread=False)
        with self._sql_conn as conn:
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
        self._account.load_service(
            self.name, get_servfunc(concat_varname(self, 'type_sync')))
        logging.debug("module rtyper started")

    def setup_session(self, con):
        """Session starts."""
        super().setup_session(con)
        con.sync_service(serv := self._account.services[self.name + '.type'])
        con.syncs[self, 'type'] = Sync(
            con, serv, self._ser_type, self._deser_type)

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
    def type(self) -> ResType:
        """.type"""
        return self._type
