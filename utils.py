# Copyright (c) 2023
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
ilafalseone.utils

Ilafalseone utilities.

"""

__all__ = [
    'distinguish_adjacent',
    'from_inplace',

    'OrderedSet',
    'OrderedList',

    'Sorted',
    'SortedSet',
    'SortedDict',

    'Wrapper',
    'NoWrapper',
    'nowrap',
    'WrappedMapping',

    'Inner'
]

from abc import ABCMeta as _ABCMeta, abstractmethod as _abstractmethod
from bisect import bisect_left as _bisect_left
from collections import _Link
from collections.abc import (
    Callable as _Callable,
    Collection as _Collection,
    ItemsView as _ItemsView,
    Iterable as _Iterable,
    Iterator as _Iterator,
    KeysView as _KeysView,
    Mapping as _Mapping,
    MutableMapping as _MutableMapping,
    MutableSequence as _MutableSequence,
    MutableSet as _MutableSet,
    Set as _Set,
    ValuesView as _ValuesView
)
from copy import copy as _copy
from inspect import get_annotations as _get_annotations
from operator import eq as _eq
from reprlib import recursive_repr as _recursive_repr
from sys import getsizeof as _sizeof
from types import (
    FunctionType as _FunctionType,
    NotImplementedType as _NotImplementedType
)
from typing import Any as _Any, Self as _Self
from weakref import proxy as _proxy

# IDE
T, CT, DT, KT, VT = None, None, None, None, None
WT, WKT, WVT = None, None, None


def distinguish_adjacent[T](iterable: _Iterable[T]) -> _Iterator[T]:
    """Get an iterator whose adjacent items are distinct."""
    last = object()
    for item in iterable:
        if item != last:
            yield (last := item)


type InPlaceOperator[T, CT: type[_Collection]] = _Callable[
    [CT[T], _Iterable[T]], CT[T]]
type MathOperator[T, CT: type[_Collection]] = _Callable[
    [CT[T], _Iterable[T]], CT[T] | _NotImplementedType]


def from_inplace[T, CT: type[_Collection[T]]](
    operator: InPlaceOperator[T, CT],
    impl_type: CT,
    from_iterable: _Callable[[_Iterable[T]], CT] | None = None
) -> tuple[MathOperator[T, CT], MathOperator[T, CT]]:
    """Generates mathematical operators from an in-place operator."""

    def forward(self, other, /):
        return (operator(_copy(self), other)
                if isinstance(other, impl_type) else NotImplemented)

    part = operator.__name__[3:]
    forward.__name__ = '__' + part
    if from_iterable is None:
        # Invertible operation
        reverse = _FunctionType(
            forward.__code__,
            globals(),
            '__r' + part,
            None,
            forward.__closure__
        )
    else:
        def reverse(self, other, /):
            return (operator(from_iterable(other), self)
                    if isinstance(other, impl_type) else NotImplemented)
        reverse.__name__ = '__r' + part

    if 'return' in (anon := _get_annotations(operator)):
        anon['return'] |= _NotImplementedType
        forward.__annotations__ = reverse.__annotations__ = anon

    return forward, reverse


_from_iterable = _Set._from_iterable.__func__


def _check_iterable(other: _Iterable):
    if not isinstance(other, _Iterable):
        raise TypeError(
            f"{other.__class__.__name__!r} object is not iterable")


@_recursive_repr()
def __repr__(self):
    if not self:
        return f"{self.__class__.__name__}()"
    return f"{self.__class__.__name__}({list(self)!r})"


class OrderedSet[T](set[T]):

    """Set that remembers insertion order."""

    __slots__ = '__hardroot', '__root', '__map'

    def __init__(self, other=(), /):
        self.__hardroot = _Link()
        self.__root = root = _proxy(self.__hardroot)
        root.prev = root.next = root
        self.__map: dict[T, _Link] = {}
        self |= (other)

    def __iter__(self) -> _Iterator[T]:
        root = self.__root
        curr = root.next
        while curr is not root:
            yield curr.key
            curr = curr.next

    def __reversed__(self) -> _Iterator[T]:
        root = self.__root
        curr = root.prev
        while curr is not root:
            yield curr.key
            curr = curr.prev

    def add(self, element: T, /):
        if element not in self:
            self.__map[element] = link = _Link()
            root = self.__root
            last = root.prev
            link.prev, link.next, link.key = last, root, element
            last.next = link
            root.prev = _proxy(link)
        super().add(element)

    def discard(self, element: T, /):
        super().discard(element)
        link = self.__map.pop(element)
        link_prev = link.prev
        link_next = link.next
        link_prev.next = link_next
        link_next.prev = link_prev
        link.prev = None
        link.next = None

    def clear(self):
        root = self.__root
        root.prev = root.next = root
        self.__map.clear()
        super().clear()

    def pop(self, last=True) -> T:
        if not self:
            raise KeyError("pop from an empty set")
        root = self.__root
        if last:
            link = root.prev
            link_prev = link.prev
            link_prev.next = root
            root.prev = link_prev
        else:
            link = root.next
            link_next = link.next
            root.next = link_next
            link_next.prev = root
        element = link.key
        del self.__map[element]
        super().discard(element)
        return element

    def move_to_end(self, element: T, /, last=True):
        """Move an existing element to the end (or beginning if last is false).

        Raise KeyError if the element does not exist.
        """
        link = self.__map[element]
        link_prev = link.prev
        link_next = link.next
        soft_link = link_next.prev
        link_prev.next = link_next
        link_next.prev = link_prev
        root = self.__root
        if last:
            last = root.prev
            link.prev = last
            link.next = root
            root.prev = soft_link
            last.next = link
        else:
            first = root.next
            link.prev = root
            link.next = first
            first.prev = soft_link
            root.next = link

    __repr__ = __repr__

    __from_iterable = classmethod(_from_iterable)

    def copy(self):
        return self.__from_iterable(self)

    __copy__ = copy

    def __eq__(self, other: _Any, /) -> bool:
        if isinstance(other, OrderedSet):
            return all(map(_eq, self, other))
        return super().__eq__(other)

    __or__, __ror__ = from_inplace(
        __ior__ := _MutableSet.__ior__, set, __from_iterable)

    __and__, __rand__ = from_inplace(
        __iand__ := _MutableSet.__iand__, set, __from_iterable)

    __xor__, __rxor__ = from_inplace(
        __ixor__ := _MutableSet.__ixor__, set, __from_iterable)

    __sub__, __rsub__ = from_inplace(
        __isub__ := _MutableSet.__isub__, set, __from_iterable)

    @staticmethod
    def _get_operators(
            operator: InPlaceOperator[T, _Self], name: str = None, /
        ) -> tuple[_Callable[[_Self, _Iterable[T]], None],
                   _Callable[[_Self, _Iterable[T]], _Self]]:
        def update(self, other: _Iterable[T], /) -> None:
            _check_iterable(other)
            operator(self, other)

        def func(self, other: _Iterable[T], /) -> _Self:
            _check_iterable(other)
            return operator(_copy(self), other)

        if name is not None:
            update.__name__ = name + '_update'
            func.__name__ = name

        return update, func

    update, union = _get_operators(__ior__)
    update.__name__ = 'update'
    union.__name__ = 'union'

    intersection_update, intersection = _get_operators(
        __iand__, 'intersection')

    symmetric_difference_update, symmetric_difference = _get_operators(
        __ixor__, 'symmetric_difference')

    difference_update, difference = _get_operators(__isub__, 'difference')


class _OrderedListKeysView(_KeysView[int]):

    __slots__ = ()

    def __contains__(self, i: int, /) -> bool:
        if isinstance(i, int):
            len_ = len(self._mapping)
            return -len_ <= i < len_
        return False

    def __iter__(self) -> _Iterator[int]:
        curr = root = self._mapping._OrderedList__root
        while (curr := curr.next) is not root:
            yield curr.key

    def __reversed__(self) -> _Iterator[int]:
        curr = root = self._mapping._OrderedList__root
        while (curr := curr.prev) is not root:
            yield curr.key

    __repr__ = __repr__


class _OrderedListItemsView[T](_ItemsView[int, T]):

    __slots__ = ()

    type _IT = tuple[int, T]

    def __contains__(self, item: _IT, /) -> bool:
        i, value = item
        return self._mapping[i] == value

    def __iter__(self) -> _Iterator[_IT]:
        for i in (mapping := self._mapping).keys():
            yield i, mapping[i]

    def __reversed__(self) -> _Iterator[_IT]:
        for i in reversed((mapping := self._mapping).keys()):
            yield i, mapping[i]

    __repr__ = __repr__


class _OrderedListValuesView[T](_ValuesView[T]):

    __slots__ = ()

    def __contains__(self, obj: T, /) -> bool:
        return obj in self._mapping

    def __iter__(self) -> _Iterator[int]:
        for i in (mapping := self._mapping).keys():
            yield mapping[i]

    def __reversed__(self) -> _Iterator[int]:
        for i in reversed((mapping := self._mapping).keys()):
            yield mapping[i]

    __repr__ = __repr__


class OrderedList[T](list[T]):

    """List that remembers insertion order."""

    __slots__ = '__hardroot', '__root', '__list'

    def __init__(self, iterable: _Iterable[T] = (), /):
        self.__hardroot = _Link()
        self.__root = root = _proxy(self.__hardroot)
        root.prev = root.next = root
        self.__list: list[_Link] = []
        self.__extend(iterable)

    def __setitem__(self, key: int | slice, value: T | _Iterable[T], /):
        if isinstance(key, int):
            super().__setitem__(key, value)
            return

        start, stop, step = key.indices(len(self))
        idxs = range(start, stop, step)
        range_len = len(idxs)
        value_len = len(value)
        if range_len == value_len:
            for _ in map(super().__setitem__, idxs, value):
                pass
            return

        if step != 1:
            raise ValueError(
                f"attempt to assign sequence of size {len(idxs)}"
                f" to extended slice of size {len(value)}"
            )

        add = value_len - range_len
        end = stop + add
        if add > 0:
            list_ = self.__list
            for link in list_[stop:]:
                link.key += add
            root = self.__root
            last = root.prev
            for i in range(stop, end):
                last.next = link = _Link()
                link.prev, link.next, link.key = last, root, i
                list_.insert(i, last := link)
            root.prev = _proxy(last)
            super().__setitem__(key, value)
        else:
            del self[end: stop]
            super().__setitem__(slice(start, end), value)

    def __delitem__(self, key: int | slice, /):
        if isinstance(key, int):
            link = self.__list.pop(key)
            for link_ in self.__list[key:]:
                link_.key -= 1
            link_prev = link.prev
            link_next = link.next
            link_prev.next = link_next
            link_next.prev = link_prev
            link.prev = None
            link.next = None
            super().__delitem__(key)
            return

        start, stop, step = key.indices(len(self))
        if step == 1:
            for link in self.__list[stop:]:
                link.key -= 1
            link = self.__list[start]
            link_next = self.__list[stop]
            del self.__list[key]
            link_prev = link.prev
            link_prev.next = link_next
            link_next.prev = link_prev
            link.prev = None
            link.next = None
            super().__delitem__(key)
            return

        to_del = range(start, stop, step)
        if step > 0:
            to_del = reversed(to_del)
        for i in to_del:
            del self[i]

    def insert(self, i: int, obj: T, /):
        """Insert object before index."""
        for link in self.__list[i:]:
            link.key += 1
        root = self.__root
        last = root.prev
        self.__list.insert(i, link := _Link())
        link.prev, link.next, link.key = last, root, i
        root.prev = _proxy(link)
        super().insert(i, obj)

    def append(self, obj: T, /):
        """Append object to the end of the list."""
        self.__list.append(link := _Link())
        root = self.__root
        last = root.prev
        link.prev, link.next, link.key = last, root, len(self)
        last.next = link
        root.prev = _proxy(link)
        super().append(obj)

    def clear(self):
        """Remove all items from list."""
        root = self.__root
        root.prev = root.next = root
        self.__list.clear()
        super().clear()

    def popitem(self, last=True) -> tuple[int, T]:
        """Remove and return a (index, object) pair as a 2-tuple."""
        if not self:
            raise IndexError("pop from empty list")
        root = self.__root
        if last:
            link = root.prev
            link_prev = link.prev
            link_prev.next = root
            root.prev = link_prev
        else:
            link = root.next
            link_next = link.next
            root.next = link_next
            link_next.prev = root
        del self.__list[i := link.key]
        for link in self.__list[i:]:
            link.key -= 1
        return i, super().pop(i)

    def move_to_end(self, i: int, /, last=True):
        """Move an existing element to the end (or beginning if last is false).

        Raise IndexError if the element does not exist.
        """
        link = self.__list[i]
        link_prev = link.prev
        link_next = link.next
        soft_link = link_next.prev
        link_prev.next = link_next
        link_next.prev = link_prev
        root = self.__root
        if last:
            last = root.prev
            link.prev = last
            link.next = root
            root.prev = soft_link
            last.next = link
        else:
            first = root.next
            link.prev = root
            link.next = first
            first.prev = soft_link
            root.next = link

    extend = __extend = _MutableSequence.extend

    def keys(self):
        """Return the ordered list indices."""
        return _OrderedListKeysView(self)

    def items(self) -> _OrderedListItemsView[T]:
        """Return the ordered (index, object) pairs."""
        return _OrderedListItemsView(self)

    def values(self) -> _OrderedListValuesView[T]:
        """Return the ordered objects in the list."""
        return _OrderedListValuesView(self)

    def pop(self, i=-1, /) -> T:
        """Remove and return item at index."""
        if i < 0:
            i += len(self)
        obj = super().pop(i)
        link = self.__list.pop(i)
        link_prev = link.prev
        link_next = link.next
        link_prev.next = link_next
        link_next.prev = link_prev
        link.prev = None
        link.next = None
        return obj

    @_recursive_repr()
    def __repr__(self) -> str:
        if not self:
            return f"{self.__class__.__name__}()"
        return f"{self.__class__.__name__}({super().__repr__()})"

    def __eq__(self, other: _Any, /) -> bool:
        if other is self:
            return True
        if isinstance(other, OrderedList):
            return (super().__eq__(other)
                    and all(map(_eq, self.keys(), other.keys())))
        return super().__eq__(other)

    __add__, __radd__ = from_inplace(__iadd__ := _MutableSequence.__iadd__,
                                     list, classmethod(_from_iterable))

    def __imul__(self, n: int, /) -> _Self:
        self.extend(super().__mul__(n - 1))
        return self

    def __mul__(self, n: int, /) -> _Self:
        return self.copy().__imul__(n)

    __rmul__ = _FunctionType(
        __mul__.__code__, globals(), '__rmul__', None, __mul__.__closure__)

    def copy(self) -> _Self:
        """Return a shallow copy of self."""
        return self.__class__(self)

    __copy__ = copy


type _KeyType[T] = _Callable[[T], _Any] | None


class Sorted[T](_Collection[T]):
    """Sorted iterable class."""

    __slots__ = ()

    @property
    @_abstractmethod
    def key(self) -> _KeyType[T]:
        """A function of one argument that is used to extract
        a comparison key from each element in iterable."""


class SortedSet[T](list[T], _MutableSet[T], Sorted[T]):
    """Sorted set class."""

    __slots__ = '__key'

    def __init__(self, other: _Iterable[T] = (),
                 /, *, key: _KeyType[T] = None):
        self.__key = key
        self[:] = self._get_material(other)

    def _get_material(self, other: _Iterable[T], /) -> _Iterable[T]:
        always_distinct = isinstance(other, (_Set, _Mapping))
        if not isinstance(other, Sorted) or other.key != self.__key:
            other = sorted(other, key=self.__key)
        if not always_distinct:
            other = distinguish_adjacent(other)
        return other

    def __contains__(self, obj: T, /) -> bool:
        return self.exist(self.bisect(obj), obj)

    def __sizeof__(self):
        return sum(_sizeof(getattr(self, name)) for name in self.__slots__)

    def bisect(self, obj: T, start=0, stop: int = None, /) -> int:
        """Return the index where to insert item in self."""
        return _bisect_left(self, obj, start, stop, key=self.__key)

    def exist(self, i: int, obj: T, /) -> bool:
        """Return self[i] == obj.
        Return False if index not out of range.

        """
        return i < len(self) and self[i] == obj

    def index(self, obj: T, start=0, stop: int = None, /) -> int:
        if self.exist(i := self.bisect(obj, start, stop), obj):
            return i
        raise ValueError(obj)

    def count(self, obj: T, /) -> int:
        return int(obj in self)

    def _from_iterable(self, other: _Iterable, /) -> _Self:
        return self.__class__(other, key=self.__key)

    def add(self, obj: T, /):
        """Add an element."""
        if not self.exist(i := self.bisect(obj, False), obj):
            self.insert(i, obj)

    def discard(self, obj: T, /):
        """Remove an element. Do not raise an exception if absent."""
        if self.exist(i := self.bisect(obj, False), obj):
            del self[i]

    def remove(self, obj: T, /):
        if self.exist(i := self.bisect(obj, False), obj):
            del self[i]
            return
        raise KeyError(obj)

    @_recursive_repr()
    def __repr__(self) -> str:
        if not self:
            return f"{self.__class__.__name__}(key={self.__key!r})"
        return (f"{self.__class__.__name__}"
                f"({super().__repr__()}, key={self.__key!r})")

    def copy(self):
        return self._from_iterable(self)

    __copy__ = copy

    def __iand__(self, other: _Iterable[T], /) -> _Self:
        if other is self:
            return self
        i = 0
        for obj in self._get_material(other):
            if (j := self.bisect(obj, i)) >= len(self):
                break
            if self[j] == obj:
                del self[i: j]
            i = j + 1
        del self[i:]
        return self

    __and__, __rand__ = from_inplace(__iand__, _Set)

    def isdisjoint(self, other: _Iterable[T], /) -> bool:
        "Return True if two sets have a null intersection."
        if other is self:
            return False
        i = 0
        for obj in self._get_material(other):
            if (i := self.bisect(obj, i)) >= len(self):
                return True
            if self[i] == obj:
                return False
        return True

    def __ior__(self, other: _Iterable[T], /) -> _Self:
        if other is self:
            return self
        i = 0
        for obj in (other := iter(self._get_material(other))):
            if (i := self.bisect(obj, i)) >= len(self):
                self.append(obj)
                self += other
                break
            if self[i] != obj:
                self.insert(i, obj)
                i += 1
        return self

    __or__, __ror__ = from_inplace(__ior__, _Set)

    def __isub__(self, other: _Iterable[T], /) -> _Self:
        if other is self:
            self.clear()
            return self
        i = 0
        for obj in self._get_material(other):
            if (i := self.bisect(obj, i)) >= len(self):
                break
            if self[i] == obj:
                del self[i]
            else:
                i += 1
        return self

    __sub__, __rsub__ = from_inplace(__isub__, _Set, _from_iterable)

    def __ixor__(self, other: _Iterable[T], /) -> _Self:
        if other is self:
            self.clear()
            return self
        i = 0
        for obj in (other := iter(self._get_material(other))):
            if (i := self.bisect(obj, i)) >= len(self):
                self.append(obj)
                self += other
                break
            if self[i] == obj:
                del self[i]
            else:
                self.insert(i, obj)
                i += 1
        return self

    __xor__, __rxor__ = from_inplace(__ixor__, _Set)

    @property
    def key(self) -> _KeyType[T]:
        return self.__key

    @key.setter
    def key(self, key: _KeyType[T], /):
        self.__key = key


_marker = object()


class _SortedDictKeysView[KT](SortedSet[KT]):

    __slots__ = ()


_ABCMeta.register(_KeysView, _SortedDictKeysView)


class _SortedDictValuesView[VT](list[VT]):

    __slots__ = ()


_ABCMeta.register(_ValuesView, _SortedDictValuesView)


class _SortedDictItemsView[KT, VT](
        _ItemsView[KT, VT], _MutableSequence[tuple[KT, VT]]):

    __slots__ = ()

    type _IT = tuple[KT, VT]

    def __getitem__(self, i: int | slice, /) -> _IT | _Iterator[_IT]:
        map_ = self._mapping
        if isinstance(i, int):
            return map_.keys()[i], map_.values()[i]

        if isinstance(i, slice):
            return zip(map_.keys()[i], map_.values()[i])

        raise TypeError(type(i))

    def __setitem__(self, i: int | slice, item: _IT | _Iterator[_IT], /):
        map_ = self._mapping
        if isinstance(i, int):
            key, value = item
            map_.keys()[i] = key
            map_.values()[i] = value
            return

        if isinstance(i, slice):
            map_.keys()[i] = (key for key, _ in item)
            map_.values()[i] = (value for _, value in item)
            return

        raise TypeError(type(i))

    def __delitem__(self, i: int | slice, /):
        del (map_ := self._mapping).keys()[i], map_.values()[i]

    def __iter__(self) -> _Iterator[_IT]:
        return zip(map_ := self._mapping, map_.values())

    def __contains__(self, item: KT, /):
        key, value = item
        return self._mapping.get(key, _marker) == value

    def __reversed__(self) -> _Iterator[_IT]:
        return zip(reversed(map_ := self._mapping), reversed(map_.values()))

    def index(self, item: _IT, start=0, stop=None, /) -> int:
        key, value = item
        try:
            if (map_ := self._mapping).values[i := map_.index(key)] == value:
                return i
        except ValueError:
            pass
        raise ValueError(item)

    def count(self, item: _IT, /) -> int:
        return int(item in self)

    def insert(self, i: int, item: _IT, /):
        key, value = item
        (map_ := self._mapping).keys().insert(i, key)
        map_.value().insert(i, value)

    def append(self, item: _IT, /):
        key, value = item
        (map_ := self._mapping).keys().append(key)
        map_.values().append(value)

    def clear(self):
        self._mapping.clear()

    def reverse(self):
        (map_ := self._mapping).keys().reverse()
        map_.value().reverse()

    def pop(self, i=-1, /) -> _IT:
        return (map_ := self._mapping).keys().pop(i), map_.values().pop(i)

    def remove(self, item: _IT, /):
        del ((map_ := self._mapping).keys()[i := self.index(item)],
             map_.values()[i])


type _IT = tuple[KT, VT]
type _ItemsType = _Mapping[KT, VT] | _Iterable[_IT]


class SortedDict[KT, VT](_MutableMapping[KT, VT], Sorted[KT]):
    """Sorted dictionary class."""

    __slots__ = '__key', '__keys', '__values'

    def __init__(self, other: _ItemsType = (), /, *, key: _KeyType[T] = None):
        self.__key = key

        if isinstance(other, SortedDict):
            self.__keys = other.keys().copy()
            self.__values = other.values().copy()
            return

        self.__keys: SortedSet[KT] = SortedSet(key=key)
        self.__values: list[VT] = []
        if isinstance(other, _Mapping):
            other = other.items()
        for k, value in other:
            self[k] = value

    def __getitem__(self, key: KT, /) -> VT:
        if self.exist(i := self.bisect(key), key):
            return self.__values[i]
        raise KeyError(key)

    def get[DT](self, key: KT, default: DT = None) -> VT | DT:
        """Get a value by key."""
        if self.exist(i := self.bisect(key), key):
            return self.__values[i]
        return default

    def __setitem__(self, key: KT, value: VT, /):
        if self.exist(i := self.bisect(key), key):
            self.__values[i] = value
        else:
            self.__keys.insert(i, key)
            self.__values.insert(i, value)

    def __delitem__(self, key: KT, /):
        if self.exist(i := self.bisect(key), key):
            del self.__keys[i]
            del self.__values[i]
        else:
            raise KeyError(key)

    def __contains__(self, key: KT, /) -> bool:
        return self.exist(self.bisect(key), key)

    def __iter__(self) -> _Iterator[KT]:
        yield from self.__keys

    def __reversed__(self):
        yield from reversed(self.__keys)

    def __len__(self) -> int:
        return len(self.__keys)

    def __sizeof__(self):
        return sum(_sizeof(getattr(self, name)) for name in self.__slots__)

    def keys(self) -> SortedSet[KT]:
        return self.__keys

    def items(self) -> _SortedDictItemsView[KT, VT]:
        return _SortedDictItemsView(self)

    def values(self) -> list[VT]:
        return self.__values

    def bisect(self, obj: T, start=0, stop: int = None, /) -> int:
        """Return the index where to insert item in self."""
        return self.keys().bisect(obj, start, stop)

    def exist(self, i: int, key: T, /) -> bool:
        """Return self.keys()[i] == key.
        Return False if index not out of range.

        """
        return self.keys().exist(i, key)

    def index(self, key: T, start=0, stop: int = None, /) -> int:
        """Return the index of the key in self.keys()."""
        return self.keys().index(key, start, stop)

    def pop[DT](self, key: KT, default: DT = _marker) -> VT | DT:
        if self.exist(i := self.bisect(key), key):
            del self.__keys[i]
            return self.__values[i].pop(i)
        if default is not _marker:
            return default
        raise KeyError(key)

    def popitem(self) -> _IT:
        if self.__keys:
            return self.__keys.pop(), self.__values.pop()
        raise KeyError

    def clear(self):
        self.__keys.clear()
        self.__values.clear()

    def update(self, other: _ItemsType = (), /, **kwds):
        if is_sorted_dict := isinstance(other, SortedDict):
            other = other.items()
        if is_sorted_dict or isinstance(other, _SortedDictItemsView):
            start = 0
            for key, value in (iter_ := iter(other)):
                if (i := self.bisect(key, start)) >= len(self):
                    self.keys().append(key)
                    self.values().append(value)
                    self.items().extend(iter_)
                    break
                if self.__keys[i] != key:
                    start = i + 1
                    self.keys().append(key)
                    self.values().append(value)
            return

        if isinstance(other, _Mapping):
            other = other.items()
        for key, value in other:
            self[key] = value
        for key, value in kwds.items():
            self[key] = value

    def setdefault(self, key: KT, default: VT = None) -> VT:
        if self.exist(i := self.bisect(key), key):
            return self.__values[i]
        self.__values[i] = default
        return default

    @_recursive_repr()
    def __repr__(self) -> str:
        if not self:
            return f"{self.__class__.__name__}(key={self.__key!r})"
        return (f"{self.__class__.__name__}"
                f"({list(self.items())!r}, key={self.__key!r})")

    def _from_iterable(self, other: _ItemsType, /) -> _Self:
        return self.__class__(other, key=self.__key)

    def copy(self) -> _Self:
        """Return a shallow copy of self."""
        return self._from_iterable(self)

    __copy__ = copy

    @classmethod
    def fromkeys(cls, iterable: _Iterable[KT], value: VT = None,
                 *, key: _KeyType[KT] = None) -> _Self:
        """Create a new ordered dictionary with keys
        from iterable and values set to value.
        """
        self = cls(key=key)
        self.__keys = keys = sorted(iterable, key=key)
        self.__values = [value] * len(keys)
        return self

    def __eq__(self, other: _Any, /) -> bool:
        if other is self:
            return True
        if isinstance(other, _Mapping):
            return (self.__keys == list(other.keys())
                    and self.__values == list(other.values()))
        return NotImplemented

    def __ior__(self, other: _ItemsType, /) -> _Self:
        self.update(other)
        return self

    __or__, __ror__ = from_inplace(__ior__, _Mapping, _from_iterable)

    @property
    def key(self) -> _KeyType[KT]:
        return self.__key

    @key.setter
    def key(self, key: _KeyType[KT], /):
        self.__key = key


class Wrapper[T, WT](metaclass=_ABCMeta):

    """Object wrapper class."""

    __slots__ = ()

    @_abstractmethod
    def extract(self, obj: T) -> WT:
        """Extract object into wrapped object."""

    @_abstractmethod
    def expand(self, obj: WT) -> T:
        """Expand wrapped object."""

    def __call__(self, obj: T) -> WT:
        return self.extract(obj)


class NoWrapper[T](Wrapper[T, T]):

    """NoWrapper class."""

    __slots__ = ()

    extract = expand = staticmethod(lambda obj: obj)

    def __repr__(self) -> str:
        return "nowrap"


nowrap = NoWrapper()


class WrappedMapping[KT, VT, WKT, WVT](_MutableMapping[KT, VT]):

    """WrappedMapping class."""

    __slots__ = 'data', 'key', 'value'

    def __init__(self, data: _MutableMapping[WKT, WVT],
                 key: Wrapper[KT, WKT] = nowrap,
                 value: Wrapper[VT, WVT] = nowrap):
        self.data = data
        self.key = key
        self.value = value

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, key: KT, /) -> VT:
        return self.value.expand(self.data[self.key(key)])

    def __setitem__(self, key: KT, value: VT) -> VT:
        self.data[self.key(key)] = self.value(value)

    def __delitem__(self, key: KT, /):
        del self.data[self.key(key)]

    def __iter__(self) -> _Iterable[KT]:
        return map(self.key.expand, self.data)

    def __contains__(self, key: KT, /) -> bool:
        return self.key(key) in self.data

    def get[DT](self, key: KT, default: DT = None, /) -> VT:
        return self.value.expand(self.data.get(self.key(key), default))

    @_recursive_repr()
    def __repr__(self) -> bool:
        if self.value is nowrap:
            return f"WrappedMapping(data={self.data!r}, key={self.key!r})"
        return (f"WrappedMapping(data={self.data!r}, "
                f"key={self.key!r}, value=self.value!r)")

    def __or__(self, other: _Mapping[KT, VT], /
               ) -> _Self | _NotImplementedType:
        key = self.key
        value = self.value
        cls = self.__class__
        if (isinstance(other, WrappedMapping)
            and key == other.key
                and value == other.value):
            return cls(self.data | other.data, key, value)

        if isinstance(other, _Mapping):
            copy = _copy(other)
            copy.clear()
            new = cls(copy, key, value)
            new |= other
            return self | new

        return NotImplemented

    __ror__ = __or__

    def update(self, other: _ItemsType, /):
        data = self.data
        key = self.key
        value = self.value
        if (isinstance(other, WrappedMapping)
            and key == other.key
                and value == other.value):
            data.update(other.data)
            return

        data.update(zip(map(key, other), map(value, other.values())))

    def __ior__(self, other: _ItemsType, /) -> _Self:
        self.update(other)
        return self

    def copy(self) -> _Self:
        """Return a shallow copy of self."""
        return self.__class__(
            _copy(self.data), self.key, self.value)

    __copy__ = copy


class Inner[T]:

    """Inner class."""

    def __init__(self, outer: T):
        self._outer = outer

    @property
    def outer(self) -> T:
        """Outer class."""
        return self._outer
