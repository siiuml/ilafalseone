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
from collections import OrderedDict, UserDict, UserList, deque
from collections.abc import Callable, MutableSequence
from io import BufferedIOBase, BufferedReader, BytesIO
from typing import TYPE_CHECKING

from .ilfocore.constants import ENCODING
from .ilfocore.ilfonode import BaseSession
from .ilfocore.utils import (
    NULL,
    read_by_size,
    read_integral,
    write_integral,
    write_with_size
)

from .utils import OrderedList

if TYPE_CHECKING:
    from collections.abc import Hashable
    from .account import Account
    from .basemodule import Module


class SendDict[T: Hashable](UserDict[T, int]):

    """Sending dictionary in synchronization."""

    def __init__(self, maxlen=128, lru=False):
        self._data: dict[T, int] = OrderedDict() if lru else {}
        self._maxlen = maxlen

    def popitem(self) -> tuple[T, int]:
        if isinstance(data := self._data, OrderedDict):
            return data.popitem(False)
        key = next(iter(data))
        return key, data.pop(key)

    def get(self, key: T, default=None) -> int:
        return self._data.get(T, default)

    def __getitem__(self, key: T) -> int:
        if (i := self.get(key)) is not None:
            return i
        if (i := len(self)) >= self.maxlen:
            _, i = self.popitem(False)
        self[key] = i
        return i

    @property
    def data(self) -> dict[T, int]:
        """Inner collection."""
        return self._data

    @property
    def maxlen(self) -> int:
        """Maximum length."""
        return self._maxlen


class RecvList[T: Hashable](UserList[T]):

    """Receiving list in synchronization."""

    def __init__(self, maxlen=128, lru=False):
        if lru:
            self._data = OrderedList[T]()
        else:
            self._data: list[T] = []
            self._popidx = 0
        self._maxlen = maxlen

    def move_to_end(self, i: T):
        """Move an existing element to the end."""
        if isinstance(data := self._data, OrderedList):
            data.move_to_end(i)

    def add(self, obj: T) -> int:
        """Add an object to recvlist."""
        if (i := len(data := self.data)) < self._maxlen:
            data.append(obj)
        else:
            if isinstance(data, OrderedList):
                data.move_to_end(i := next(iter(data.keys())))
            else:
                i = self._popidx
                self._popidx += 1
            data[i] = obj
        return i

    @property
    def data(self) -> dict[T, int]:
        """Inner collection."""
        return self._data

    @property
    def maxlen(self) -> int:
        """Maximum length."""
        return self._maxlen

    @property
    def popindex(self) -> int:
        """The index of the object to pop next."""
        if isinstance(data := self.data, OrderedList):
            return next(iter(data.keys()))
        return self._popidx


class Unreadable:

    """Unreadble class."""

    __slots__ = ()

    def __repr__(self) -> str:
        return 'Unreadble'


unreadble = Unreadable()
SYNC_MARK = b'\xfe'

type Serialization[T] = Callable[[T, BufferedIOBase], int]
type Deserialization[T] = Callable[[BufferedIOBase], T | None]


class Sync[T: Hashable]:

    """Synchronized factors in sessions."""

    __slots__ = ('_con', '_ser', '_deser',
                 '_senddict', '_recvlist', '_sync_mark')

    def __init__(self, con: 'Session',
                 serialization: Serialization[T] = write_with_size,
                 deserialization: Deserialization[T] = read_by_size,
                 senddict: SendDict[T] = None, recvlist: RecvList[T] = None,
                 sync_mark: bytes | None = None):
        self._con = con
        self._ser = serialization
        self._deser = deserialization
        self._senddict = SendDict[T]() if senddict is None else senddict
        self._recvlist = RecvList[T]() if recvlist is None else recvlist
        self._sync_mark = sync_mark

    def send(self, obj: T, buf: BufferedIOBase) -> int:
        """Write a new object into buffer for synchronization.

        Returns the number of bytes written.

        """
        self._senddict[obj]
        return self._ser(obj, buf)

    def recv(self, buf: BufferedReader) -> T:
        """Read a new object from buffer with synchronization."""
        self._recvlist.add(obj := self._deser(buf))
        return obj

    def write(self, obj: T, buf: BufferedIOBase) -> int:
        """Write a synchronized object into buffer.

        Returns the number of bytes written.

        """
        i = self._senddict.get(obj)
        if (mark := self._sync_mark) is not None:
            if i is None:
                return self.send(obj, buf)

            return buf.write(mark) + write_integral(i, buf)

        if i is None:
            return buf.write(NULL) + self.send(obj, buf)

        return write_integral(i, buf)

    def read(self, buf: BufferedIOBase) -> T:
        """Get a synchronized object from buffer."""
        recvlist = self._recvlist
        if (mark := self._sync_mark) is not None:
            pos = buf.tell()
            if buf.read(len(mark)) != mark:
                buf.seek(pos)
                return self.recv(buf)

        elif (i := read_integral(buf, not_none=False)) is None:
            return self.recv(buf)

        if ((i := read_integral(buf)) < len(recvlist)
                and (obj := recvlist[i]) is not unreadble):
            recvlist.move_to_end(i)
            return obj

        raise ValueError(f"Read an unreadable object {i}")

    @property
    def senddict(self) -> SendDict[T]:
        """Return the objects sent."""
        return self._senddict

    @property
    def recvlist(self) -> RecvList[T]:
        """Return the objects received."""
        return self._recvlist

    @property
    def session(self) -> 'Session':
        """Bounding session."""
        return self._con


def ser_str(str_: str, buf: BufferedIOBase) -> int:
    """Serialize a data type into buffer."""
    return write_with_size(bytes(str_, ENCODING), buf)


def deser_str(buf: BufferedReader) -> str:
    """Deserialize a string from buffer."""
    return str(read_by_size(buf), ENCODING)


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


def concat_varname(cls: 'str | type | Module', name: str) -> str:
    """Get full key name in session dictionaries like vars(con)."""
    if isinstance(cls, str):
        pass
    elif isinstance(cls, type):
        cls = cls.__name__
    else:
        cls = cls.__class__.__name__
    return cls + '_' + name


type _VarNameType = str | tuple['str | type | Module', str]


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


class _VarsDict[T](dict[_VarNameType, T]):

    _marker = object()

    @staticmethod
    def _get_str_key(key: _VarNameType) -> str:
        if isinstance(key, str):
            return key
        return concat_varname(*key)

    def __getitem__(self, key: _VarNameType, /) -> T:
        return super().__getitem__(self._get_str_key(key))

    def get(self, key: _VarNameType, default=None, /) -> T:
        return super().get(self._get_str_key(key), default)

    def __setitem__(self, key: _VarNameType, value: T, /):
        super().__setitem__(self._get_str_key(key), value)

    def __delitem__(self, key: _VarNameType, /):
        super().__setitem__(self._get_str_key(key))

    def __contains__(self, obj, /) -> bool:
        try:
            obj = self._get_str_key(obj)
        except (AttributeError, TypeError, ValueError):
            return False
        return super().__contains__(obj)

    def pop(self, key: _VarNameType, default=_marker, /) -> T:
        value = super().pop(key, default)
        if value is not self._marker:
            return value
        raise KeyError(key)

    def setdefault(self, key: _VarNameType, default=None, /) -> T:
        return super().setdefault(self._get_str_key(key), default)


class Filler(ABC):

    """Filler to fill block packs."""

    __slots__ = ()

    @abstractmethod
    def fill(self, con: 'Session', buf: BytesIO) -> int:
        """Fill into buffer."""

    __call__ = fill


class SyncFiller[T: Hashable](Filler):

    """Synchronizing filler."""

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
        self._serv_sync = sync = Sync(self, self._ser_serv, self._deser_serv)
        self._syncs = syncs = _VarsDict[Sync]()
        syncs[self, 'serv'] = sync

        self._seqs_to_ack: deque[tuple[int, 'Module']] = deque()
        self._preparing: dict[str, BytesIO] = {}
        self._dict = _VarsDict()

    def setup_common(self):
        """Setup the session."""
        self.handle = self.handle_common
        acct = self.account
        with acct.modules_lock:
            for mod in acct.modules.values():
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
        acct = self.account
        with acct.modules_lock:
            for mod in acct.modules.values():
                mod.finish_session(self)
        super().finish()

    def close(self):
        acct = self.account
        with acct.modules_lock:
            for mod in acct.modules.values():
                mod.close_session(self)

    def _serv_servsync(self, buf: BufferedReader):
        """Synchronize services from target."""
        try:
            self._serv_sync.recv(buf)
        except ValueError:
            buf.read()
            self.close()

    @staticmethod
    def _ser_serv(serv: Service, buf: BufferedIOBase) -> int:
        """Serialize a service into buffer."""
        return ser_str(serv.name, buf)

    def _deser_serv(self, buf: BufferedIOBase) -> Service:
        """Deserialize a service from buffer."""
        return self.account.services.get(deser_str(buf), unreadble)

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
        return self._syncs

    @property
    def preparing(self) -> dict[str, BytesIO]:
        """Service buffer preparing to send."""
        return self._preparing

    @property
    def __dict__(self) -> _VarsDict:
        """Variables binding to the session."""
        return self._dict

    @property
    def account(self) -> 'Account':
        return self.node.account
