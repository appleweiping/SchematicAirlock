"""Static conditions under which a simulator cannot solve the operating point.

The gate already refuses artifacts that are unreadable, unbounded, or
structurally incoherent. It said nothing about a netlist that parses cleanly,
describes a plausible circuit, and then makes the first DC solve fail. Those
are the runs a pre-simulation boundary exists to save.

Two conditions account for most of them, and both are properties of the
flattened connectivity graph rather than of any device model:

- a node with no conducting path to ground has no reference, so its row in the
  nodal matrix is singular;
- a loop made only of ideal voltage sources over-determines the loop, so the
  matrix is singular again. `SRC001` already catches the two-node case where
  the sources sit in parallel; a loop of three or more is the same defect
  spread further apart.

What conducts at DC is a convention, and this module states it rather than
implying it. Resistors, inductors, and voltage sources tie their nodes
together. Capacitors do not, which is the whole point of the check. Ideal
current sources do not either: forcing a current through a node says nothing
about its potential, which is exactly why a simulator refuses one that has no
other path. Transistor gates are insulated, and every other transistor terminal
is connected through the channel or a junction.

A subcircuit call that could not be expanded is the case where being wrong
matters, so it is treated as connecting all of its pins. That is the assumption
that cannot produce a false accusation: it can hide a real defect inside an
unresolvable subcircuit, and it will never refuse an artifact because part of
it was unreadable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from schematic_airlock.parse import Element

#: Nodes named in one finding before the list is abbreviated. A component with
#: no path to ground can be most of a large netlist, and a finding is meant to
#: be read.
MAX_REPORTED_NODES = 12

#: Elements whose two terminals are tied together at DC.
TWO_TERMINAL_CONDUCTORS = frozenset({"R", "L", "V", "E", "H", "D", "S", "W"})

#: Elements that carry no DC path between their nodes. Capacitors are open, and
#: an ideal current source constrains a current rather than a potential.
NON_CONDUCTORS = frozenset({"C", "I", "G", "F", "K"})

#: Transistor terminal positions that a channel or junction ties together. A
#: MOS gate is insulated, so index 1 is excluded; a bipolar base is not, so
#: every terminal of a `Q` conducts.
TRANSISTOR_CONDUCTING_INDICES: Mapping[str, tuple[int, ...]] = {
    "M": (0, 2, 3),
    "J": (0, 2),
    "Z": (0, 2),
    "Q": (0, 1, 2, 3),
}


@dataclass(frozen=True, slots=True)
class FloatingIsland:
    """A set of nodes with no conducting path to any ground net."""

    nodes: tuple[str, ...]
    devices: tuple[str, ...]

    @property
    def summary(self) -> str:
        shown = list(self.nodes[:MAX_REPORTED_NODES])
        if len(self.nodes) > MAX_REPORTED_NODES:
            shown.append(f"and {len(self.nodes) - MAX_REPORTED_NODES} more")
        return ", ".join(shown)


@dataclass(frozen=True, slots=True)
class SourceLoop:
    """A cycle of ideal voltage sources, which over-determines its loop."""

    devices: tuple[str, ...]
    nodes: tuple[str, ...]


class _Union:
    """Disjoint sets over node names, by union by size with path halving."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._size: dict[str, int] = {}

    def add(self, node: str) -> None:
        if node not in self._parent:
            self._parent[node] = node
            self._size[node] = 1

    def find(self, node: str) -> str:
        self.add(node)
        root = node
        while self._parent[root] != root:
            self._parent[root] = self._parent[self._parent[root]]
            root = self._parent[root]
        return root

    def union(self, left: str, right: str) -> bool:
        first, second = self.find(left), self.find(right)
        if first == second:
            return False
        if self._size[first] < self._size[second]:
            first, second = second, first
        self._parent[second] = first
        self._size[first] += self._size[second]
        return True

    def groups(self) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for node in sorted(self._parent):
            found.setdefault(self.find(node), []).append(node)
        return found


def conducting_pairs(element: Element) -> tuple[tuple[str, str], ...]:
    """Return the node pairs this element ties together at DC.

    An unknown element kind is treated as conducting between all of its nodes,
    for the same reason an unexpanded subcircuit is: an assumption that hides a
    defect is recoverable, and one that invents a defect is not.
    """

    nodes = [node.lower() for node in element.nodes]
    kind = element.kind.upper()
    if kind in NON_CONDUCTORS or len(nodes) < 2:
        return ()
    if kind in TRANSISTOR_CONDUCTING_INDICES:
        indices = [index for index in TRANSISTOR_CONDUCTING_INDICES[kind] if index < len(nodes)]
        return tuple(
            (nodes[first], nodes[second])
            for position, first in enumerate(indices)
            for second in indices[position + 1 :]
        )
    if kind in TWO_TERMINAL_CONDUCTORS:
        return ((nodes[0], nodes[1]),)
    # `X` calls that survived expansion, and anything unrecognized.
    return tuple(
        (nodes[first], nodes[second])
        for first in range(len(nodes))
        for second in range(first + 1, len(nodes))
    )


def _ground_nodes(nodes: Iterable[str], ground_names: Iterable[str]) -> set[str]:
    grounds = {name.lower() for name in ground_names} | {"0"}
    found = set()
    for node in nodes:
        bare = node.rsplit(":", 1)[-1]
        if node in grounds or bare in grounds:
            found.add(node)
    return found


def floating_islands(
    elements: Sequence[tuple[str, Element]],
    ground_names: Iterable[str] = ("0",),
) -> tuple[FloatingIsland, ...]:
    """Group nodes that no conducting path connects to a ground net.

    Nodes are grouped rather than listed one by one, because a single missing
    connection strands a whole island and a finding per node would report one
    defect many times.
    """

    union = _Union()
    for _name, element in elements:
        for node in element.nodes:
            union.add(node.lower())
        for first, second in conducting_pairs(element):
            union.union(first, second)

    # Ownership is resolved after every union: a root recorded while the sets
    # were still merging would name an island that no longer exists.
    owners: dict[str, set[str]] = {}
    for name, element in elements:
        for node in element.nodes:
            owners.setdefault(union.find(node.lower()), set()).add(name)

    groups = union.groups()
    every_node = {node for nodes in groups.values() for node in nodes}
    grounded = {union.find(node) for node in _ground_nodes(every_node, ground_names)}
    return tuple(
        FloatingIsland(nodes=tuple(nodes), devices=tuple(sorted(owners.get(root, set()))))
        for root, nodes in sorted(groups.items())
        if root not in grounded
    )


def has_ground(elements: Sequence[tuple[str, Element]], ground_names: Iterable[str]) -> bool:
    """Whether any element touches a ground net at all."""

    nodes = {node.lower() for _name, element in elements for node in element.nodes}
    return bool(_ground_nodes(nodes, ground_names))


def voltage_source_loops(
    elements: Sequence[tuple[str, Element]],
) -> tuple[SourceLoop, ...]:
    """Find cycles made only of ideal voltage sources.

    A spanning forest is grown over the source edges; an edge joining two nodes
    already connected closes a loop. One loop is reported per closing edge,
    which is the number of independent cycles, so a mesh of sources does not
    produce a finding for every path around it.
    """

    union = _Union()
    tree: dict[str, list[tuple[str, str]]] = {}
    loops = []
    for name, element in sorted(elements, key=lambda item: item[0].lower()):
        if element.kind.upper() != "V" or len(element.nodes) < 2:
            continue
        first, second = (node.lower() for node in element.nodes[:2])
        if first == second:
            continue
        if union.union(first, second):
            tree.setdefault(first, []).append((second, name))
            tree.setdefault(second, []).append((first, name))
            continue
        path_devices, path_nodes = _tree_path(tree, first, second)
        loops.append(
            SourceLoop(
                devices=tuple(sorted({name, *path_devices})),
                nodes=tuple(path_nodes),
            )
        )
    return tuple(loops)


def _tree_path(
    tree: Mapping[str, list[tuple[str, str]]], start: str, goal: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Walk the accepted edges from `start` to `goal`.

    The closing edge alone names one source of a loop, which is not enough to
    act on: the engineer has to see which sources form the cycle. Every edge
    already accepted forms a forest, so the path between the two ends is unique
    and a breadth-first walk finds it.
    """

    previous: dict[str, tuple[str, str]] = {start: (start, "")}
    queue = [start]
    while queue:
        node = queue.pop(0)
        if node == goal:
            break
        for neighbour, device in tree.get(node, ()):
            if neighbour not in previous:
                previous[neighbour] = (node, device)
                queue.append(neighbour)
    if goal not in previous:
        return (), (start, goal)
    devices: list[str] = []
    nodes = [goal]
    cursor = goal
    while cursor != start:
        cursor, device = previous[cursor]
        devices.append(device)
        nodes.append(cursor)
    return tuple(devices), tuple(reversed(nodes))
