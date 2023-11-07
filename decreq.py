# Copyright (c) 2023
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilafalseone.decreq

Decrypting request manager.

"""

import logging
from abc import abstractmethod

from .basemodule import Module
from .session import Session
from .restype import ResTypeManager, Serializable


class Cryptic(Serializable):

    """Cryptic class."""

    __slots__ = ()

    @property
    @abstractmethod
    def material(self) -> Serializable:
        """Material."""

    def is_decrypted(self) -> bool:
        """If self is decrypted."""
        return self.material is not None

    def has_access(self, con: Session) -> bool:
        """If other has access to the material."""
        raise NotImplementedError


class ResReqManager(Module):

    """Cryptic resource request manager."""

    name = '.decreq'

    def __init__(self):
        super().__init__()
        self._rtyper: ResTypeManager = None

    def start(self):
        """Start the module."""
        account = self._account
        self._rtyper = account.modules[ResTypeManager.name]
        logging.debug("module decreq started")

    def serv_req(self, con, buf):
        try:
            type_ = self.restype_manager.type.mapping.read(con, buf)
            res = type_.mapping.read(con, buf)
            if isinstance(res, Cryptic) and res.has_access(con):
                raise NotImplementedError
        except ValueError:
            buf.read()
            return
        logging.debug("handled req")

    @property
    def restype_manager(self) -> ResTypeManager:
        """RTypeMapping instance bounded."""
        return self._rtyper
