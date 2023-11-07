# Copyright (c) 2023 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilafalseone.session

Ilafalseone session.

"""

import logging
import traceback
from abc import ABC, abstractmethod
from collections import OrderedDict, deque
from collections.abc import Callable, Hashable, MutableSequence
from io import BufferedIOBase, BufferedReader, BytesIO
from typing import TYPE_CHECKING, Any, Union

from .ilfocore.constants import ENCODING
from .ilfocore.ilfonode import BaseSession
from .ilfocore.utils import (
    read_by_size,
    read_integral,
    write_integral,
    write_with_size
)

from .utils import OrderedList

if TYPE_CHECKING:
    from .basemodule import Module


# IDE
T = None
type Serialization[T] = Callable[[T, BufferedIOBase], int]
type Deserialization[T] = Callable[[BufferedIOBase], T | None]


class Sync[T: Hashable]:

    """Synchronized factors in sessions."""

    __slots__ = '_con', '_serv', '_senddict', '_recvlist', '_ser', '_deser'

    def __init__(self, con: 'Session', serv: 'Service',
                 serialization: Serialization[T] = None,
                 deserialization: Deserialization[T] = None):
        self._con = con
        self._serv = serv
        self._senddict: dict[T, int] = {}
        self._recvlist: list[T] = []
        self._ser = serialization
        self._deser = deserialization

    def send(self, obj: T | None, buf: BufferedIOBase) -> int:
        """Write synchronizations of new objects into buffer.

        Returns the number of bytes written.

        """
        if obj is None:
            return 0
        send[obj] = len(send := self._senddict)
        if (ser := self._ser) is None:
            return write_with_size(obj, buf)
        return ser(obj, buf)

    def recv(self, buf: BufferedReader) -> T:
        """Read a synchronization of a new object from buffer."""
        self._recvlist.append(
            obj := read_by_size(buf)
            if (deser := self._deser) is None else deser(buf))
        return obj

    def write(self, obj: T | None, buf: BufferedIOBase) -> int:
        """Write a synchronized object into buffer.

        Returns the number of bytes written.

        """
        if obj is None:
            return buf.write(b'\xff')
        return write_integral(self._senddict[obj], buf)

    def read(self, buf: BufferedIOBase, *, not_none=True) -> T | None:
        """Get a synchronized object from buffer."""
        if (i := read_integral(buf, not_none)) is None:
            return None
        if (i < len(recvlist := self._recvlist)
                and (obj := recvlist[i]) is not None):
            return obj
        raise ValueError("Read an unknown object")

    @property
    def senddict(self) -> dict[T, int]:
        """Return the objects sent."""
        return self._senddict

    @property
    def recvlist(self) -> list[T]:
        """Return the objects received."""
        return self._recvlist

    @property
    def session(self) -> 'Session':
        """Bounding session."""
        return self._con

    @property
    def service(self):
        """Service to send synchronization."""
        return self._serv


def ser_str(str_: str, buf: BufferedIOBase) -> int:
    """Serialize a data type into buffer."""
    return write_with_size(bytes(str_, ENCODING), buf)


def deser_str(buf: BufferedReader) -> str | None:
    """Deserialize a string from buffer."""
    return str(read_by_size(buf), ENCODING)


class DynamicSync[T: Hashable](Sync[T]):

    """Dynamic synchronized factors in sessions."""

    __slots__ = '_senddict_rem', '_recvlist_rem'

    def __init__(self, con: 'Session',
                 serialization: Serialization[T] = None,
                 deserialization: Deserialization[T] = None,
                 send_maxlen: int = 128, recv_maxlen: int = 128):
        super().__init__(con, None, serialization, deserialization)
        self._senddict: OrderedDict[T, int] = OrderedDict(self._senddict)
        self._recvlist: OrderedList[T] = OrderedList(self._recvlist)
        self._senddict_rem = send_maxlen
        self._recvlist_rem = recv_maxlen

    def write(self, obj: T | None, buf: BufferedIOBase) -> int:
        """Write a synchronized object into buffer.

        Returns the number of bytes written.

        """
        if obj is None:
            return buf.write(b'\xff')
        if (i := (senddict := self._senddict).get(obj)) is None:
            self.add_to_senddict(obj)
            if (ser := self._ser) is None:
                return write_with_size(obj, buf)
            return ser(obj)
        senddict.move_to_end(obj)
        return write_integral(i, buf)

    def read(self, buf: BufferedIOBase, *, not_none=True) -> T | None:
        """Get a synchronized object from buffer."""
        if (size := read_integral(buf, not_none)) is None:
            return None
        if size:
            self.add_to_recvlist(obj := (
                buf.read(size)
                if (deser := self._deser) is None else deser(buf)
            ))
            return obj
        if (i := read_integral(buf, not_none)) is None:
            return None
        if (i < len(recvlist := self._recvlist)
                and (obj := recvlist[i]) is not None):
            recvlist.move_to_end(i)
            return obj
        raise ValueError

    def add_to_senddict(self, obj: T) -> int:
        """Add an object to self.senddict.

        Return the object index.

        """
        senddict = self._senddict
        if self._senddict_rem:
            self._senddict_rem -= 1
            i = len(self._senddict)
        else:
            _, i = senddict.popitem(False)
        senddict[obj] = i
        return i

    def add_to_recvlist(self, obj: T) -> int:
        """Add an object to self.recvlist.

        Return the object index.

        """
        recvlist = self._recvlist
        if self._recvlist_rem:
            self._recvlist_rem -= 1
            i = len(recvlist)
            recvlist.append(obj)
        else:
            recvlist[i := next(iter(recvlist.keys()))] = obj
            recvlist.move_to_end(i)
        return i

    @property
    def senddict_remaining(self) -> int:
        """Return the size available for new objects in self.senddict."""
        return self._senddict_rem

    @property
    def recvlist_remaining(self) -> int:
        """Return the size available for new objects in self.recvlist."""
        return self._recvlist_rem

    senddict: OrderedDict
    recvlist: OrderedList


type ServiceFunction = Callable[['Session', BufferedReader], None]


class Service:

    """Named service class."""

    __slots__ = '_name', '_func'

    def __init__(self, name: str, func: ServiceFunction):
        self._name = name
        self._func = func

    def __call__(self, con: 'Session', buf: BufferedReader, *args, **kwargs):
        self._func(con, buf)

    def __eq__(self, obj):
        return self._name == obj

    def __hash__(self) -> int:
        return hash(self._name)

    def __repr__(self) -> str:
        return f"Service({self._name}, ...)"

    def __str__(self) -> str:
        return self._name

    @property
    def name(self) -> str:
        """Service name."""
        return self._name

    @property
    def function(self) -> ServiceFunction:
        """Service function."""
        return self._func


def concat_varname(cls: Union[str, type, 'Module'], name: str) -> str:
    """Get full key name in var(con := Session())."""
    if isinstance(cls, str):
        pass
    elif isinstance(cls, type):
        cls = cls.__name__
    else:
        cls = cls.__class__.__name__
    return cls + '_' + name


type _VarNameType = str | tuple[Union[str, type, 'Module'], str]


def get_servfunc(key: _VarNameType) -> ServiceFunction:
    """Get service function from sync.recv."""
    def serv_func(con: 'Session', buf: BufferedReader):
        """Synchronize object from target."""
        try:
            con.syncs[key].recv(buf)
        except ValueError:
            buf.read()
            con.close()
    return serv_func


class _VarsDict[T: Any](dict[_VarNameType, T]):

    _marker = object()

    @staticmethod
    def _get_str_key(key: _VarNameType) -> str:
        if isinstance(key, str):
            return key
        return concat_varname(*key)

    def __getitem__(self, key: _VarNameType, /) -> T:
        return super().__getitem__(self._get_str_key(key))

    def get(self, key: _VarNameType, default: Any = None, /) -> T:
        return super().get(self._get_str_key(key), default)

    def __setitem___(self, key: _VarNameType, value: T, /):
        super().__setitem__(self._get_str_key(key), value)

    def __delitem__(self, key: _VarNameType, /):
        super().__setitem__(self._get_str_key(key))

    def __contains__(self, obj: Any, /) -> bool:
        try:
            obj = self._get_str_key(obj)
        except (AttributeError, TypeError, ValueError):
            return False
        return super().__contains__(obj)

    def pop(self, key: _VarNameType, default: Any = _marker, /) -> T:
        value = super().pop(key, default)
        if value is not self._marker:
            return value
        raise KeyError(key)

    def setdefault(self, key: _VarNameType, default: Any = None, /) -> T:
        return super().setdefault(self._get_str_key(key), default)


class Filler(ABC):

    """Filler to fill block packs."""

    __slots__ = ()

    @abstractmethod
    def fill(self, con: 'Session', buf: BytesIO) -> int:
        """Fill into buffer."""


class DSyncFiller[T: Hashable](Filler):

    """Dynamically synchronizing filler."""

    __slots__ = '_name', '_obj'

    def __init__(self, sync_name: _VarNameType, obj: T):
        self._name = sync_name
        self._obj = obj

    def fill(self, con: 'Session', buf: BytesIO) -> int:
        """Write the object to be synchorized."""
        return con.syncs[self._name].write(self._obj, buf)

    @property
    def name(self) -> _VarNameType:
        """Variable name of the Sync object."""
        return self._name

    @property
    def obj(self) -> T:
        """The object to be synchorized."""
        return self._obj


class SyncFiller[T: Hashable](DSyncFiller[T]):

    """Synchronizing filler."""

    __slots__ = ()

    def fill(self, con: 'Session', buf: BytesIO) -> int:
        """Write the object to be synchorized."""
        if (obj := self._obj) is None:
            return write_with_size(None, buf)

        sync: Sync[T] = con.syncs[sync_name := self._name]
        if obj not in sync.sendmap:
            prep = con.preparing
            if (sync_buf := prep.get(serv := sync.service)) is None:
                con.service_sync.write(serv, sync_buf := BytesIO())
                prep[str(serv)] = sync_buf
            sync.send(obj, sync_buf)
        return con.syncs[sync_name].write(obj, buf)


type Fillers = MutableSequence[bytes | Filler]


class Syncable(ABC):

    """Syncable class."""

    __slots__ = ()

    def to_fillers(self, fillers: Fillers):
        """Convert object into fillers, preparing to send abbreviated data."""


class Session(BaseSession):

    """Ilafalseone session class."""

    def __init__(self, conn):
        super().__init__(conn)
        account = self.node.account
        self.__mods = account.modules.values()
        self.__mods_lock = account.modules_lock
        self.__servs = servs = account.services
        self.__serv = serv = servs['.servsync']

        self._serv_sync = sync = Sync(
            self, serv, self._ser_serv, self._deser_serv)
        self._syncs = syncs = _VarsDict[Sync]()
        syncs[self, 'serv'] = sync

        self._seqs_to_ack: deque[tuple[int, 'Module']] = deque()
        self._preparing: dict[str, BytesIO] = {}
        self._dict = _VarsDict[Any]()

    def setup_common(self):
        """Setup the session."""
        self.handle = self.handle_common
        send = self._serv_sync.senddict
        send[serv := self.__servs['.servsync']] = len(send)
        self._serv_sync.recvlist.append(serv)
        with self.__mods_lock:
            for mod in self.__mods:
                mod.setup_session(self)
                if self.is_finished:
                    break

    def acknowledged(self, seq: int):
        """Received ACK message from target."""
        if self._seqs_to_ack:
            send_seq, mod = self._seqs_to_ack[0]
            if seq >= send_seq:
                self._seqs_to_ack.popleft()
                mod.acknowledged(self, seq)

    def handle_common(self, buf: BufferedReader):
        """Handle package data."""
        logging.debug("handle data %s", buf.peek())
        serv = self._serv_sync.read(buf)
        logging.debug("call service %s", serv)
        while buf.peek():
            serv(self, buf)

    def finish(self):
        """Finish the session."""
        logging.debug("finish session by %s",
                      traceback.extract_stack()[-2][2])
        with self.__mods_lock:
            for mod in self.__mods:
                mod.finish_session(self)
        super().finish()

    def close(self):
        with self.__mods_lock:
            for mod in self.__mods:
                mod.close_session(self)

    def _serv_servsync(self, buf: BufferedReader):
        """Synchronize services from target."""
        try:
            self._serv_sync.recv(buf)
        except ValueError:
            buf.read()
            self.close()

    @staticmethod
    def _ser_serv(serv: Service, buf: BufferedIOBase):
        """Serialize a service into buffer."""
        write_with_size(bytes(serv.name, ENCODING), buf)

    def _deser_serv(self, buf: BufferedIOBase) -> Service | None:
        """Deserialize a service from buffer."""
        return self.__servs.get(str(read_by_size(buf), ENCODING))

    def sync_service(self, *services: Service):
        """Synchronize services to target."""
        (sync := self._serv_sync).write('.servsync', buf := BytesIO())
        for serv in services:
            sync.send(serv, buf)
            logging.debug("try sync serv %r", serv)
        self.send(buf.getvalue())

    def fill(self, fillers: Fillers, buf: BytesIO) -> int:
        """Fill the fillers into a pack."""
        return sum(
            buf.write(filler)
            if isinstance(filler, bytes) else filler.fill(self, buf)
            for filler in fillers
        )

    @property
    def seqs_to_ack(self) -> deque[tuple[int, 'Module']]:
        """Return the sequence numbers which should be checked
        if the ACK messages with them were sent by target.

        """
        return self._seqs_to_ack

    @property
    def service_sync(self) -> Sync[Service]:
        """Service synchronization."""
        return self._serv_sync

    @property
    def syncs(self) -> _VarsDict[Sync]:
        """Session synchronizations."""
        return self._sync

    @property
    def preparing(self) -> dict[str, BytesIO]:
        """Service buffer preparing to send."""
        return self._preparing

    @property
    def __dict__(self) -> _VarsDict[Any]:
        """Variables bounded to the session."""
        return self._dict
