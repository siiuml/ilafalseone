# Copyright (c) 2023 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilafalseone.account

Ilafalseone account.

"""

import logging
import traceback
from threading import RLock, Thread

from .basemodule import Module
from .session import Service, ServiceFunction, Session

from .ilfocore import signature
from .ilfocore.constants import Address
from .ilfocore.ilfonode import Node


class IlafalseoneNode(Node):

    """
    class.
    """

    def __init__(self, priv_key: signature.PrivateKey, account: 'Account'):
        self.account = account
        self.thread: Thread = None
        super().__init__(priv_key, None, Session, False)


class Account:

    """
    Account class.
    """

    NodeClass = IlafalseoneNode

    def __init__(
        self,
        alg: str,
        priv_bytes: bytes,
        pub_bytes: bytes | None = None
    ):
        self._mods: dict[str, Module] = {}
        self._servs: dict[str, Service] = {}
        self._mods_lock = RLock()
        priv_key = signature.get_sign(alg).from_bytes(priv_bytes, pub_bytes)
        self._node = self.NodeClass(priv_key, self)
        self._is_started = False
        self._is_online = False

    def start(self):
        """Start."""
        self._is_started = True
        self.load_service(Service('.servsync', Session._serv_servsync))
        for mod in self._mods.values():
            mod.start()

    def connect(self, local_address: Address, poll_interval=0.1):
        """Connect to internet."""
        if self._is_online:
            return
        if not isinstance(local_address, Address):
            local_address = Address(*local_address)
        self._is_online = True
        self._node.server_address = local_address
        self._node.server_bind()
        self._node.server_activate()
        self._node.thread = Thread(
            target=self._node.serve_forever,
            args=(poll_interval,),
            name=f"Serving thread on port {self._node.server_address[1]}",
            daemon=True
        )
        # self._node.thread.start()
        for mod in self._mods.values():
            mod.connect()
        logging.debug("login successful")

    def start_thread(self):
        self._node.thread.start()

    def disconnect(self):
        """Disconnect from internet."""
        if not self._is_online:
            return
        self._is_online = False
        for mod in self._mods.values():
            mod.disconnect()
        self._node.close()
        self._node = IlafalseoneNode(self._node.sig_key, self)

    def close(self):
        """Disconnect and close modules."""
        logging.debug("account closed by %s",
                      traceback.extract_stack()[-2][2])
        self._is_started = False
        self.disconnect()
        for mod in self._mods.values():
            mod.close()

    def load_module(self, module: Module):
        """Initialize a module."""
        module.account = self
        self._mods[module.name] = module
        if self._is_started:
            module.start()
            if self._is_online:
                module.connect()
                node = self._node
                with node.group_lock:
                    for con in node.sessions.values():
                        module.setup(con)

    def offload_module(self, name: str) -> Module:
        """Offload a module.

        Return the module removed.

        """
        if name in (mods := self._mods):
            mod = mods.pop(name)
            if self._is_started:
                if self._is_online:
                    mod.disconnect()
                mod.stop()
            return mod
        return None

    def load_service(self, service: Service | str,
                     func: ServiceFunction = None):
        """Load a service."""
        if func is None:
            name = service.name
        else:
            name = service
            service = Service(service, func)
        self._servs[name] = service

    def offload_service(self, name: str) -> Service:
        """Offload a service.

        Return the service removed.

        """
        if name in (servs := self._servs):
            return servs.pop(name)
        return None

    @property
    def modules(self) -> dict[str, Module]:
        """Return modules."""
        return self._mods

    @property
    def services(self) -> dict[str, Service]:
        """Return services."""
        return self._servs

    @property
    def modules_lock(self) -> RLock:
        """Lock of self.modules."""
        return self._mods_lock

    @property
    def node(self) -> IlafalseoneNode:
        """Return local node."""
        return self._node

    @property
    def is_started(self) -> bool:
        """Return if start() has been called."""
        return self._is_started

    @property
    def is_online(self) -> bool:
        """Return online status."""
        return self._is_online
