# Copyright (c) 2023 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilafalseone.basemodule

Abstract ilafalseone module.

"""

import sqlite3
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Iterable

from .session import Session

from .ilfocore.constants import Key

if TYPE_CHECKING:
    from .account import Account
    T = None


class Module(ABC):

    """Base module."""

    def __init__(self):
        """Init the module.

        May be overriden.

        """
        self._account: 'Account' = None

    def start(self):
        """Called when local account has been initialized and starts.

        May be overriden.

        """

    def connect(self):
        """Account online.

        May be overriden.

        """

    def setup_session(self, con: Session):
        """Called by ilafalseone.session.Session.setup_common(con).

        May be overriden.

        """

    # def init(self, con: Session, buf: BufferedReader) -> bool:
    #     """Handle port setting, return False if not accepted.

    #     May be overriden.

    #     """
    #     return True

    def acknowledged(self, con: Session, seq: int):
        """Received ACK message from target.

        May be overriden.

        """

    def finish_session(self, con: Session):
        """Called when the session is about to finish.

        May be overriden.

        """

    def close_session(self, con: Session):
        """Called when the session is about to finish.

        May be overriden.

        """

    def disconnect(self):
        """Called when account offline.

        May be overriden.

        """

    def stop(self):
        """Stop the threads, called by close().

        May be overriden.

        """

    def close(self):
        """Close.

        May be overriden.

        """
        self.stop()

    def send_packages_to(
        self,
        packages: Iterable[bytes],
        target: Session | int,
        check_ack=False
    ) -> int | dict[Session, int]:
        """Send a list of module packages.

        Return the sequence number of the last module
        packet sent, or the sequence numbers of the last
        module packets sent in different sessions.

        """
        if isinstance(target, Session):
            seq = target.send_packages(packages)
            if check_ack:
                target.seqs_to_ack.append((seq, self))
            return seq

        if isinstance(target, Key):
            seqs = self._account.node.send_packages_to(packages, target)
            if check_ack:
                for con, seq in seqs.items():
                    con.seqs_to_ack.append((seq, self))
            return seqs

        raise TypeError

    def sendto(self, package: bytes, target: Session | Key
               ) -> int | dict[Session, int]:
        """Send a module package.

        Return the sequence number of the last module
        packet sent, or the sequence numbers of the last
        module packets sent in different sessions.

        """
        if isinstance(target, Session):
            seq = target.send(package)
            target.seqs_to_ack.append((seq, self))
            return seq

        if isinstance(target, Key):
            seqs = self._account.node.sendto(package, target)
            for con, seq in seqs.items():
                con.seqs_to_ack.append((seq, self))
            return seqs

        raise TypeError

    @property
    def account(self) -> 'Account':
        """Return the local account."""
        return self._account

    @account.setter
    def account(self, account: 'Account'):
        """Set the local account."""
        self._account = account

    @classmethod
    @property
    @abstractmethod
    def name(cls) -> str:
        """Module name."""

    def __repr__(self) -> str:
        return f"module {self.name}"


class Bounded(ABC):

    """Object bounded with a module."""

    __slots__ = ()

    @property
    @abstractmethod
    def module(self) -> Module:
        """The Module which object bounded with."""


class DataBased(Module):

    """Module with a database connection."""

    def __init__(self):
        super().__init__()
        self._sql_conn: sqlite3.Connection = None

    def load_data(self, conn: sqlite3.Connection):
        """Load data from database."""
        self._sql_conn = conn

    def start(self):
        """Start the module thread after local account has been initialized.
        Call load_data() if module has not connect to the database.

        May be overriden.

        """
        if self._sql_conn is None:
            raise ValueError("Database not loaded")

    def close(self):
        """Close the module and the DB connection."""
        super().close()
        self._sql_conn.close()

    @property
    def sql_conn(self) -> sqlite3.Connection:
        """Return SQLite database connection."""
        return self._sql_conn
