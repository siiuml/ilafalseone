# Copyright (c) 2023 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilafalseone.signing

Signing manager.

"""

import logging
from collections.abc import Iterable, Mapping
from io import BufferedIOBase, BufferedReader, BytesIO
from reprlib import recursive_repr
from threading import RLock
from typing import Self

from .basemodule import Bounded, DataBased
from .session import Session
from .session import Sync, concat_varname, get_servfunc
from .session import Fillers, SyncFiller
from .utils import Inner

from .ilfocore.constants import ENCODING
from .ilfocore.lib.signature import (
    PrivateKey,
    PublicKey,
    get_sign,
    get_verify
)
from .ilfocore.utils import read_by_size, write_with_size
from .restype import ResType, ResTypeManager, Resource, TypedMapping, WithMsg

# IDE
T = None


class Signer(Resource, Bounded):

    __slots__ = '_mod', '_pub', '_priv'

    def __init__(self, mod: 'SigningManager', id_: int, pub_key: PublicKey,
                 priv_key: PrivateKey | None = None):
        super().__init__(id_)
        self._mod = mod
        if priv_key is not None and priv_key.public_key != pub_key:
            raise ValueError(priv_key)
        self._pub = pub_key
        self._priv = priv_key

    def to_fillers(self, fillers: Fillers):
        fillers.append(SyncFiller((self._mod, 'signer'), self))

    def to_bytes(self) -> bytes:
        """Public key in bytes."""
        return self._pub.to_bytes()

    def __repr__(self) -> str:
        return f"<Signer {self._rid}: {self}>"

    @property
    def public(self) -> PublicKey:
        return self._pub

    @property
    def private(self) -> PrivateKey | None:
        return self._priv

    @private.setter
    def private(self, priv: PrivateKey | None):
        id_ = self._rid
        conn = self._mod.sql_conn
        if priv is None:
            if self._priv is not None:
                with conn:
                    conn.execute(
                        "UPDATE signer SET priv_key = NULL WHERE id = ?",
                        (id_,))
            return
        if self._priv.public_key != self._pub:
            raise ValueError(priv)

        with conn:
            conn.execute(
                "UPDATE signer SET priv_key = ? WHERE id = ?",
                (priv.to_bytes(), id_))

    @property
    def rtype(self) -> ResType:
        """.signer"""
        return self._mod.type_signer

    @property
    def module(self) -> 'SigningManager':
        return self._mod


type KeyLike = bytes | PublicKey | tuple[str, bytes]


class SignerMapping(TypedMapping[Signer], Bounded):

    """Signer mapping."""

    class KeyMapping(dict[bytes, Signer], Inner['SignerMapping']):

        def __init__(self, outer: 'SignerMapping'):
            super().__init__()
            Inner.__init__(self, outer)

        def __contains__(self, key) -> bool:
            if isinstance(key, Iterable):
                _, key = key
            return super().__contains__(key)

        def get(self, key: KeyLike, default=None):
            if isinstance(key, Iterable):
                _, key = key
            return super().get(key, default)

        def __getitem__(self, key: KeyLike):
            pub_key = key if isinstance(key, PublicKey) else None
            if pub_key is not None or isinstance(key, Iterable):
                alg, key = key
            else:
                alg = None
            if alg is not None:
                if (signer := super().get(key)) is not None:
                    return signer
                if pub_key is None:
                    pub_key = get_verify(alg).from_bytes(key)
                self[key] = signer = self._outer._add_key(pub_key)
                return signer
            else:
                return super().__getitem__(key)

    def __init__(self, mod: 'SigningManager'):
        self._mod = mod
        self._id_map = {}
        self._key_map = self.KeyMapping(self)

    def _add_key(self, pub_key: PublicKey) -> Signer:
        mod = self._mod
        with mod.sql_conn as conn:
            rowid = conn.execute(
                "INSERT INTO signer(alg, pub_key) VALUE(?, ?)",
                pub_key).lastrowid
            id_, = next(conn.execute(
                "SELECT id FROM signer WHERE rowid = ?", (rowid,)))
        self._id_map[id_] = signer = Signer(mod, id_, pub_key)
        return signer

    @property
    def rid(self) -> dict[int, Signer]:
        """ID-to-signer mapping."""
        return self._id_map

    @property
    def key(self) -> KeyMapping:
        """Key-signer mapping."""
        return self._key_map

    bytes = key

    def read(self, con: Session, buf: BufferedReader) -> Signer:
        return con.syncs[self._mod, 'signer'].read(buf)

    @property
    def rtype(self) -> ResType:
        """.signer"""
        return self._mod.type_signer

    @property
    def module(self) -> 'SigningManager':
        return self._mod


class Signature[T: Resource](WithMsg[T], Resource, Bounded):

    """Signature class."""

    __slots__ = '_sig', '_owner'

    def __init__(self, mod: 'SigningManager', id_: int, inner: Resource,
                 owner: Signer, sig: bytes):
        super().__init__(inner)
        Resource.__init__(self, id_)
        Bounded.__init__(self, mod)
        self._sig = sig
        self._owner = owner

    @classmethod
    def from_row(cls, mod: 'SigningManager',
                 id_, int, sig: bytes, signer_id: int,
                 res_type_id: int, res_id: int) -> Self:
        """Construt from row."""
        signer = mod.type_signer.mapping.rid[signer_id]
        res_type = mod.restype_manager.type.mapping.rid[res_type_id]
        res = res_type.mapping.rid[res_id]
        return cls(mod, id_, signer, res)

    def to_bytes(self) -> bytes:
        """Public key in bytes."""
        return self._sig

    @recursive_repr()
    def __repr__(self) -> str:
        return f"<Signature to {self._res!r} by {self._signer!r}>"

    @property
    def owner(self) -> Signer:
        return self._owner

    @property
    def rtype(self) -> ResType:
        """.sig"""
        return self._mod.type_sig

    @property
    def module(self) -> 'SigningManager':
        return self._mod


class SignatureMapping(TypedMapping[Signer], Bounded):

    """Signature mapping."""

    class IDMapping(Mapping[int, Signature], Inner['SignatureMapping']):

        def __len__(self) -> int:
            return len(self._outer)

        def __getitem__(self, key: int) -> Signature:
            mod = self._outer.module
            row = mod.sql_conn.execute(
                "SELECT * FROM signature WHERE id = ?", (key,))
            if row is None:
                raise KeyError(key)
            return Signature.from_row(mod, *row)

    class SigMapping(Mapping[bytes, Signature], Inner['SignatureMapping']):

        def __len__(self) -> int:
            return len(self._outer)

        def __getitem__(self, key: bytes) -> Signature:
            mod = self._outer.module
            row = mod.sql_conn.execute(
                "SELECT * FROM signature WHERE sig = ?", (key,))
            if row is None:
                raise KeyError(key)
            return Signature.from_row(mod, *row)

    class OwnedMsgMapping(
            Mapping[Resource, Signature], Inner['SignatureMapping']):

        def __len__(self) -> int:
            return len(self._outer)

        def get(self, key: tuple[Signer, Resource], default=None) -> Signature:
            signer, res = key
            mod = self._outer.module
            row = mod.sql_conn.execute(
                "SELECT * FROM signature WHERE signer = ?, type = ?, res = ?",
                (signer.rid, res.rtype.rid, res.rid))
            if row is None:
                return default
            return Signature.from_row(mod, *row)

        def __getitem__(self, key: tuple[Signer, Resource]) -> Signature:
            if (sig := self.get(key)) is not None:
                return sig

            signer, res = key
            if (priv_key := signer.private) is None:
                raise KeyError(key)
            sig_bytes = priv_key.sign(res.to_bytes())
            return self._outer.add_sig(sig_bytes, signer, res)

    def __len__(self) -> int:
        cnt, = self._mod.sql_conn.execute("SELECT COUNT(*) FROM signature")
        return cnt

    def add_sig(self, sig_bytes: bytes, signer: Signer, res: Resource
                ) -> Signature:
        with self._mod.sql_conn as conn:
            rowid = conn.execute("""
                INSERT INTO signature(sig, signer, type, res)
                VALUES(?, ?, ?, ?)""", (sig_bytes, signer.rid,
                res.rtype.rid, res.rid)).lastrowid
            id_ = conn.execute(
                "SELECT id FROM signature WHERE rowid = ?", (rowid,))
        return Signature(id_, sig_bytes, signer, res)

    @property
    def rid(self) -> dict[int, Signer]:
        """Mapping using ID as key."""
        return self.IDMapping(self)

    @property
    def bytes(self) -> SigMapping:
        return self.SigMapping(self)

    @property
    def owned_msg(self) -> OwnedMsgMapping:
        """Mapping using owner-message pair as key."""
        return self.OwnedMsgMapping(self)

    def read(self, con: Session, buf: BufferedReader) -> Signer:
        mod = self._mod
        sig_bytes = read_by_size(buf)
        signer = mod.type_signer.mapping.read(buf)
        res_type = mod.restype_manager.type.mapping.read(buf)
        res = res_type.mapping.read(buf)
        if (sig := self.bytes.get(sig_bytes)) is not None:
            return sig
        return self.add_sig(sig_bytes, signer, res)

    @property
    def rtype(self) -> 'ResType':
        """.sig"""
        return self._mod.type_sig

    @property
    def module(self) -> 'SigningManager':
        return self._mod


class SigningManager(DataBased):

    """Signing manager."""

    name = '.signing'

    def __init__(self, database: str):
        super().__init__()
        self._type_signer: ResType = None
        self._type_sig: ResType = None
        self._lock = RLock()

    def load_data(self, conn):
        """Load data from database."""
        super().__init__(conn)
        self._rtyper = rtyper = self._account.modules[ResTypeManager.name]
        self._type_signer = type_ = rtyper.type.mapping.str['.signer']
        type_.mapping = mapping = SignerMapping(self)
        with conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS signer(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alg TEXT NOT NULL
                    pub_key BLOB NOT NULL UNIQUE,
                    priv_key BLOB,
                );
                
                CREATE TABLE IF NOT EXISTS signature(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sig BLOB NOT NULL UNIQUE,
                    signer INTEGER NOT NULL,
                    type INTEGER NOT NULL,
                    res INTEGER NOT NULL
                );
                
                CREATE INDEX IF NOT EXISTS res_index
                ON signature(type, res);
                CREATE INDEX IF NOT EXISTS sig_index
                ON signature(sig);
            """)

            for id_, alg, pub_bytes, priv_bytes in conn.execute(
                    "SELECT id, alg, pub_key, priv_key FROM signer"):
                if priv_bytes is None:
                    priv_key = None
                    pub_key = get_verify(alg).from_bytes(pub_bytes)
                else:
                    priv_key = get_sign(alg).from_bytes(priv_bytes, pub_bytes)
                    pub_key = priv_key.public_key
                mapping.key[pub_bytes] = Signer(self, id_, pub_key, priv_key)

    def start(self):
        """Account starts."""
        name = self.name
        load = self._account.load_service
        load(name + '.alg', get_servfunc(concat_varname(self, 'alg_sync')))
        load(name, get_servfunc(concat_varname(self, 'key_sync')))
        load(name + '.sig', self._serv_sig)
        self._type_signer.mapping.key[self._account.node.sig_key]
        logging.debug("module singer started")

    def setup_session(self, con):
        """Session starts."""
        super().setup_session(con)
        name = self.name
        servs = self._account.services
        serv_sig = servs[name + '.sig']
        serv_signer = servs[name + '.signer']
        con.synchronize_service(serv_sig, serv_signer)
        con.syncs[self, 'signer'] = Sync(
            con, serv_signer, self._ser_signer, self._deser_signer)

    def close(self):
        """Close the module."""
        super().close()
        self._type_signer = None
        self._type_sig = None

    def _serv_sig(self, con, buf):
        """Handle received signatures."""
        try:
            self._type_sig.read(con, buf)
        except ValueError:
            buf.read()
            return
        logging.debug("handled sig")

    def _serv_key(self, con, buf):
        """Synchronize key from target."""
        try:
            con.syncs[self, 'signer'].recv(buf)
        except ValueError:
            buf.read()
            con.close()

    def _ser_signer(self, signer: Signer, buf: BufferedIOBase) -> int:
        """Serialize a public key into buffer."""
        pub_key = signer.public
        return (write_with_size(bytes(pub_key.name, ENCODING), buf)
                + write_with_size(pub_key.to_bytes(), buf))

    def _deser_key(self, buf: BufferedReader) -> Signer | None:
        """Deserialize a public key from buffer."""
        return self._type_signer.mapping.key[
            str(read_by_size(buf), ENCODING), read_by_size(buf)]

    def sync_signer(self, con: Session, *signers: Signer):
        """Send public keys."""
        con.service_sync.write(self.name + '.signer', buf := BytesIO())
        sync = con.syncs[self, 'signer']
        for signer in signers:
            sync.send(signer, buf)
        con.send(buf.getvalue())

    @property
    def type_signer(self) -> ResType:
        """.signer"""
        return self._type_signer

    @property
    def type_sig(self) -> ResType:
        """.sig"""
        return self._type_sig

    @property
    def restype_manager(self) -> ResTypeManager:
        """RTypeMapping instance bounded."""
        return self._rtyper
