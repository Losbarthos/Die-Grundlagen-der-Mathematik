"""Exhaustively verify the small finite examples used in the B37 revision."""
from itertools import permutations, product


def associative(table, n):
    return all(table[table[x*n+y]*n+z] == table[x*n+table[y*n+z]]
               for x, y, z in product(range(n), repeat=3))


def power_table(table, n):
    subsets = [frozenset(i for i in range(n) if mask & (1 << i))
               for mask in range(1, 1 << n)]
    index = {subset: i for i, subset in enumerate(subsets)}
    values = tuple(index[frozenset(table[x*n+y] for x in a for y in b)]
                   for a in subsets for b in subsets)
    return values, len(subsets)


def signature(table, n):
    return (
        sum(table[x*n+x] == x for x in range(n)),
        all(table[x*n+y] == table[y*n+x] for x, y in product(range(n), repeat=2)),
        all(table[x*n+y] == x for x, y in product(range(n), repeat=2)),
        all(table[x*n+y] == y for x, y in product(range(n), repeat=2)),
    )


def verify():
    tables = list(product(range(2), repeat=4))
    good = {table for table in tables if associative(table, 2)}
    expected = {tuple(map(int, word)) for word in (
        "0000", "0001", "0011", "0101", "0110", "0111", "1001", "1111")}
    assert good == expected
    witnesses = {
        "0010": (1, 0, 1), "0100": (1, 0, 1),
        "1000": (0, 0, 1), "1110": (0, 0, 1),
        "1010": (0, 0, 0), "1011": (0, 0, 0),
        "1100": (0, 0, 0), "1101": (0, 0, 0),
    }
    for word, (x, y, z) in witnesses.items():
        table = tuple(map(int, word))
        assert table[table[2*x+y]*2+z] != table[2*x+table[2*y+z]]
    orbits = {frozenset((table, tuple(1-table[2*(1-x)+(1-y)]
                                     for x, y in product(range(2), repeat=2))))
              for table in good}
    assert len(orbits) == 5
    orbit_signatures = []
    for orbit in orbits:
        signatures = {signature(*power_table(table, 2)) for table in orbit}
        assert len(signatures) == 1
        orbit_signatures.append(signatures.pop())
    assert len(set(orbit_signatures)) == 5

    # a=0, b=1, c=2; a^2=b, a^3=c, a^4=b.
    example = (1, 2, 1, 2, 1, 2, 1, 2, 1)
    assert associative(example, 3)
    sequence, value = [0], 0
    for _ in range(7):
        value = example[3*value]
        sequence.append(value)
    assert sequence == [0, 1, 2, 1, 2, 1, 2, 1]
    assert {x for x in range(3) if example[3*x+x] == x} == {1}
    subsets = [set(i for i in range(3) if mask & (1 << i)) for mask in range(1, 8)]
    ideals = [subset for subset in subsets
              if all(example[3*x+y] in subset and example[3*y+x] in subset
                     for x in range(3) for y in subset)]
    assert ideals == [{1, 2}, {0, 1, 2}]
    assert associative(*power_table(example, 3))
    relabelled = []
    for numbering in permutations(range(3)):
        inverse = {value: i for i, value in enumerate(numbering)}
        relabelled.append(tuple(inverse[example[3*numbering[x]+numbering[y]]]
                               for x, y in product(range(3), repeat=2)))
    assert min(relabelled) == (0, 1, 1, 1, 0, 0, 1, 0, 0)
    power, order = power_table(example, 3)
    subset_list = [frozenset(i for i in range(3) if mask & (1 << i))
                   for mask in range(1, 8)]
    left, right = subset_list.index(frozenset({0})), subset_list.index(frozenset({0, 2}))
    swap = list(range(order))
    swap[left], swap[right] = right, left
    assert all(swap[power[order*x+y]] == power[order*swap[x]+swap[y]]
               for x, y in product(range(order), repeat=2))
    print("Verified: all 16 binary tables, eight associative tables, five orbits,")
    print("distinct power-semigroup invariants, the three-element reading example,")
    print("its canonical minimum and its singleton-changing power automorphism.")


if __name__ == "__main__":
    verify()
