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

from .ilfocore.constants import ENCODING
from .ilfocore.lib.signature import (
    PrivateKey,
    PublicKey,
    get_sign,
    get_verify
)
from .ilfocore.utils import (
    NULL,
    pack_with_size,
    read_by_size,
    write_with_size
)

from .basemodule import Bound, DataBased
from .session import Session
from .session import Sync, concat_varname, get_servfunc
from .session import Fillers, SyncFiller

from .decreq import InnerRes
from .restype import ResType, ResTypeManager, Resource, TypedMapping, WithMsg
from .restype import encode

from .utils import Inner
from .utils import FuncWrapper, Wrapper, WrappedMapping


class Signer(Resource, Bound):

    __slots__ = '_id', '_mod', '_pub', '_priv'

    def __init__(self, mod: 'SigningManager', id_: int, pub_key: PublicKey,
                 priv_key: PrivateKey | None = None):
        self._mod = mod
        self._id = id_
        if priv_key is not None and priv_key.public_key != pub_key:
            raise ValueError(priv_key)
        self._pub = pub_key
        self._priv = priv_key

    @property
    def public(self) -> PublicKey:
        return self._pub

    @property
    def private(self) -> PrivateKey | None:
        return self._priv

    @private.setter
    def private(self, priv: PrivateKey | None):
        id_ = self._id
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

    def __repr__(self) -> str:
        return f"<Signer {self._id}: {self}>"

    def to_fillers(self, fillers: Fillers):
        fillers.append(SyncFiller((self._mod, 'signer'), self))

    def to_bytes(self) -> bytes:
        return pack_with_size(encode(self._pub.name)) + self._pub.to_bytes()

    @property
    def rdig(self) -> bytes:
        return self._pub.to_bytes()

    @property
    def rtype(self) -> ResType['Signer']:
        """.signer"""
        return self._mod.restype_manager.mapping.str['.signer']

    @property
    def module(self) -> 'SigningManager':
        return self._mod


type KeyLike = bytes | PublicKey | tuple[str, bytes]


class SignerMapping(TypedMapping[Signer], Bound):

    """Signer mapping."""

    noalgwrap = FuncWrapper[bytes, [str | None, bytes]](
        lambda key: (None, key), lambda pair: pair[1], "noalgwrap")

    class KeyMapping(Mapping[KeyLike, Signer],
                     dict[bytes, Signer], Inner['SignerMapping']):

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
                buf = BytesIO(key)
                alg, key = read_by_size(buf, not_none=False), buf.read()
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
        return self.KeyMapping(self)

    bytes = key

    @property
    def rdig(self) -> Mapping[bytes, ResType, KeyLike, ResType]:
        return WrappedMapping(self.key, self.noalgwrap)

    def read(self, con: Session, buf: BufferedReader) -> Signer:
        return con.syncs[self._mod, 'signer'].read(buf)

    @property
    def rtype(self) -> ResType[Signer]:
        """.signer"""
        return self._mod.restype_manager.mapping.str['.signer']

    @property
    def module(self) -> 'SigningManager':
        return self._mod


class Signature[T: Resource](WithMsg[T], Resource, Bound):

    """Signature class."""

    __slots__ = '_mod', '_id', '_sig', '_signer', '_msg'

    def __init__(self, mod: 'SigningManager', id_: int,
                 sig: bytes, signer: Signer, msg: Resource):
        self._mod = mod
        self._id = id_
        self._sig = sig
        self._signer = signer
        self._msg = msg

    @classmethod
    def from_row(cls, mod: 'SigningManager',
                 id_, int, sig: bytes, signer_id: int,
                 res_type_id: int, res_id: int) -> Self:
        """Construt from row."""
        signer = mod.mapping_signer.rid[signer_id]
        msg = mod.restype_manager.mapping.rid[res_type_id].mapping.rid[res_id]
        return cls(mod, id_, sig, signer, msg)

    class Material(InnerRes['Signature']):

        """Material class."""

        def to_fillers(self, fillers: Fillers):
            outer = self._outer
            fillers.append(outer.rdig)
            fillers.append(SyncFiller(
                ('SigningManager', 'signer'), signer := outer.signer))
            if signer is not None:
                WithMsg.to_fillers(outer)

        def to_bytes(self) -> bytes:
            outer = self._outer
            if (signer := outer.signer) is None:
                return outer.to_bytes()
            return (pack_with_size(outer.rdig)
                    + pack_with_size(signer.to_bytes())
                    + WithMsg.to_bytes(outer))

    def to_bytes(self) -> bytes:
        return self._sig + NULL

    @recursive_repr()
    def __repr__(self) -> str:
        return f"<Signature to {self._msg!r} by {self._signer!r}>"

    @property
    def signer(self) -> Signer:
        return self._signer

    @property
    def rid(self) -> int:
        return self._id

    @property
    def rdig(self) -> bytes:
        return self._sig

    @property
    def rtype(self) -> ResType['Signature']:
        """.sig"""
        return self._mod.restype_manager.mapping.str['.sig']

    @property
    def module(self) -> 'SigningManager':
        return self._mod


type SigParams = tuple[bytes, Signer, Resource]


class SignatureMapping(TypedMapping[Signer], Bound):

    """Signature mapping."""

    class IDMapping(Mapping[int, Signature], Inner['SignatureMapping']):

        def __len__(self) -> int:
            return len(self._outer)

        def __iter__(self):
            for id_, in self._outer.module.sql_conn.execute(
                    "SELECT id FROM signature"):
                yield id_

        def __getitem__(self, key: int) -> Signature:
            mod = self._outer.module
            row = mod.sql_conn.execute(
                "SELECT * FROM signature WHERE id = ?", (key,))
            if row is None:
                raise KeyError(key)
            return Signature.from_row(mod, *row)

    class SigMapping(Mapping[SigParams, Signature], Inner['SignatureMapping']):

        def __len__(self) -> int:
            return len(self._outer)

        def __iter__(self) -> Iterable[SigParams]:
            mod = self._outer.module
            signer_id_map = mod.mapping_signer.rid
            type_id_map = mod.restype_manager.mapping.rid
            for sig_bytes, signer_id, type_id, msg_id in mod.sql_conn.execute(
                    "SELECT sig, signer, mtype, msg FROM signature"):
                signer = signer_id_map[signer_id]
                msg = type_id_map[type_id].mapping.rid[msg_id]
                yield sig_bytes, signer, msg

        def get(self, key: SigParams, default=None) -> Signature:
            sig_bytes, signer, msg = key
            mod = self._outer.module
            row = mod.sql_conn.execute(
                "SELECT * FROM signature WHERE signer = ?, mtype = ?, msg = ?",
                (signer.rid, msg.rtype.rid, msg.rid)
            ) if sig_bytes is None else mod.sql_conn.execute(
                "SELECT * FROM signature WHERE sig = ?", (key,))
            if row is None:
                return default
            return Signature.from_row(mod, *row)

        def __getitem__(self, key: SigParams) -> Signature:
            sig_bytes, signer, msg = key
            mod = self._outer.module
            if (sig := self.get(key)) is not None:
                if sig.is_decrypted or signer is None or msg is None:
                    return sig
                signer.public.verify(sig_bytes, WithMsg.rdig.fget(msg))
                sig._signer = signer
                sig._msg = msg
                return sig
            if sig_bytes is None:
                if (priv_key := signer.private) is None:
                    raise ValueError(f"Private key is absent: {signer!r}")
                sig_bytes = priv_key.sign(WithMsg.rdig.fget(msg))
            else:
                signer.public.verify(sig_bytes, WithMsg.rdig.fget(msg))
            with mod.sql_conn as conn:
                rowid = conn.execute("""
                    INSERT INTO signature(sig, signer, mtype, msg)
                    VALUES(?, ?, ?, ?)
                    """, (sig_bytes, signer.rid, msg.rtype.rid, msg.rid)
                ).lastrowid
                id_ = conn.execute(
                    "SELECT id FROM signature WHERE rowid = ?", (rowid,))
            return Signature(mod, id_, sig_bytes, signer, msg)

    def __len__(self) -> int:
        cnt, = self._mod.sql_conn.execute("SELECT COUNT(*) FROM signature")
        return cnt

    @property
    def rid(self) -> dict[int, Signer]:
        """Mapping using ID as key."""
        return self.IDMapping(self)

    @property
    def sig(self) -> SigMapping:
        """Mapping using signature-signer-message pair as key."""
        return self.SigMapping(self)

    sigbyteswrap = FuncWrapper(lambda sig_bytes: (sig_bytes, None, None),
                               lambda params: params[0],
                               "sigbyteswrap")

    class BytesWrapper(Wrapper, Inner['SignatureMapping']):

        def extract(self, data: bytes) -> SigParams:
            sig_bytes = read_by_size(buf := BytesIO(data))
            signer = read_by_size(buf, not_none=False)
            msg = (None if signer is None else
                   self._outer.module.restype_manager
                   .mapping.bytes[read_by_size(buf)]
                   .mapping.bytes[buf.read()])
            return sig_bytes, signer, msg

        @staticmethod
        def expand(params: SigParams) -> bytes:
            sig_bytes, signer, msg = params
            if signer is None:
                return sig_bytes + NULL
            return pack_with_size(signer.to_bytes()) + WithMsg.to_bytes(msg)

        def __repr__(self):
            return f"{self.__class.__name__}.byteswrap"

    @property
    def byteswrap(self) -> BytesWrapper:
        """byteswrap"""
        return self.BytesWrapper(self)

    def read(self, con: Session, buf: BufferedReader) -> Signature:
        mod = self._mod
        sig_bytes = read_by_size(buf)
        signer = mod.mapping_signer.read(buf, not_none=False)
        msg = (None if signer is None else
               mod.restype_manager.mapping.read(buf).mapping.read(buf))
        return self.sig[sig_bytes, signer, msg]

    @property
    def bytes(self) -> WrappedMapping[bytes, Signature, SigParams, Signature]:
        return WrappedMapping(self.sig, self.byteswrap)

    @property
    def rdig(self) -> WrappedMapping[bytes, Signature, SigParams, Signature]:
        return WrappedMapping(self.sig, self.sigbyteswrap)

    @property
    def rtype(self) -> ResType[Signature]:
        """.sig"""
        return self._mod.restype_manager.mapping.str['.sig']

    @property
    def module(self) -> 'SigningManager':
        return self._mod


class SigningManager(DataBased):

    """Signing manager."""

    name = '.signing'

    def __init__(self):
        super().__init__()
        self._maps_signer = SignerMapping(self)
        self._maps_sig = SignatureMapping(self)
        self._lock = RLock()

    def load_data(self, conn):
        """Load data from database."""
        super().__init__(conn)
        self._rtyper = rtyper = self._account.modules[ResTypeManager.name]
        str_types = rtyper.mapping
        str_types['.sig'].mapping = self._maps_sig
        str_types['.signer'].mapping = signers = self._maps_signer
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
                    signer INTEGER,
                    mtype INTEGER,
                    msg INTEGER
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
                signers.key[pub_bytes] = Signer(self, id_, pub_key, priv_key)

    def start(self):
        """Account starts."""
        account = self._account
        load = account.load_service
        name = self.name
        load(name + '.signersync',
             get_servfunc(concat_varname(self, 'signer')))
        load(name + '.sigsync', self._serv_sig)
        self._maps_signer.key[account.node.sig_key]
        logging.debug("module singer started")

    def setup_session(self, con):
        """Session starts."""
        super().setup_session(con)
        con.syncs[self, 'signer'] = Sync(
            con, self._ser_signer, self._deser_signer)

    def _serv_sig(self, con, buf):
        """Handle received signatures."""
        try:
            self._maps_sig.read(con, buf)
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

    def _deser_key(self, buf: BufferedReader) -> Signer:
        """Deserialize a public key from buffer."""
        return self._maps_signer.key[
            str(read_by_size(buf), ENCODING), read_by_size(buf)]

    def sync_signer(self, con: Session, *signers: Signer):
        """Send public keys."""
        con.service_sync.write(self.name + '.signer', buf := BytesIO())
        sync = con.syncs[self, 'signer']
        for signer in signers:
            sync.send(signer, buf)
        con.send(buf.getvalue())

    def sign(self, signer: Signer, res: Resource) -> Signature:
        """Create a signature of the resource."""
        return self._maps_sig.sig[None, signer, res]

    def verify(self, sig_bytes: bytes, signer: Signer, res: Resource):
        """Verify a signature of the resource."""
        return self._maps_sig.sig[sig_bytes, signer, res]

    @property
    def mapping_signer(self) -> SignerMapping:
        """.signer"""
        return self._maps_signer

    @property
    def mapping_sig(self) -> SignatureMapping:
        """.sig"""
        return self._maps_sig

    @property
    def restype_manager(self) -> ResTypeManager:
        """RTypeMapping instance bound."""
        return self._rtyper
