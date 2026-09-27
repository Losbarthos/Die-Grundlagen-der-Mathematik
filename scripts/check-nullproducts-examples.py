"""Finite sanity checks for the null-product reconstruction supplement.

This checks examples and profile identities, not the general theorem.
It uses no third-party packages and does not modify manuscript files.
"""
from itertools import product


def associative(table):
    n = len(table)
    return all(
        table[table[x][y]][z] == table[x][table[y][z]]
        for x, y, z in product(range(n), repeat=3)
    )


def power_table(table):
    n = len(table)
    subsets = range(1, 1 << n)
    result = {}
    for a, b in product(subsets, repeat=2):
        value = 0
        for x, y in product(range(n), repeat=2):
            if a & (1 << x) and b & (1 << y):
                value |= 1 << table[x][y]
        result[a, b] = value
    return result


def verify_profiles(table):
    powers = power_table(table)
    subsets = list(range(1, 1 << len(table)))
    signatures = {
        a: (
            frozenset(x for x in subsets if powers[a, x] == 1),
            frozenset(x for x in subsets if powers[x, a] == 1),
        )
        for a in subsets
    }
    profiles = set(signatures.values())

    def below(a, b):
        return b[0] <= a[0] and b[1] <= a[1]

    for p in profiles:
        lower = {a for a in subsets if below(signatures[a], p)}
        carrier = sum(
            1 << x
            for x in range(len(table))
            if below(signatures[1 << x], p)
        )
        expected = {a for a in subsets if a & carrier == a}
        assert lower == expected, "L_p != P*(D_p)"
        assert len(lower) == (1 << carrier.bit_count()) - 1

        fiber_size = sum(signatures[1 << x] == p for x in range(len(table)))
        smaller_fibers = sum(
            sum(signatures[1 << x] == q for x in range(len(table)))
            for q in profiles
            if q != p and below(q, p)
        )
        assert fiber_size == carrier.bit_count() - smaller_fibers
    return powers, signatures


def main():
    checked = 0
    for n in (2, 3, 4):
        count = 0
        for entries in product((0, 1), repeat=(n - 1) ** 2):
            table = [[0] * n for _ in range(n)]
            for (x, y), value in zip(
                product(range(1, n), repeat=2), entries, strict=True
            ):
                table[x][y] = value
            if {v for row in table for v in row} != {0, 1}:
                continue
            if not associative(table):
                continue
            powers, _ = verify_profiles(table)
            assert set(powers.values()) == {1, 2, 3}
            count += 1
        checked += count
        print(f"{n} elements: {count} associative two-product tables checked")

    # The reading edition uses 0,c,a with aa=c and all other products zero.
    example = [[0, 0, 0], [0, 0, 0], [0, 0, 1]]
    assert associative(example)
    _, signatures = verify_profiles(example)
    assert signatures[1] == signatures[2] != signatures[4]

    # An automorphism of P*({0,a}) need not preserve singleton subsets.
    null_power = power_table([[0, 0], [0, 0]])
    swap = {1: 1, 2: 3, 3: 2}
    assert all(
        swap[null_power[x, y]] == null_power[swap[x], swap[y]]
        for x, y in product(swap, repeat=2)
    )

    # Identical zero pattern need not determine the nonzero labels.
    # The element order is 0,a,b,u,v.
    s = [[0] * 5 for _ in range(5)]
    t = [[0] * 5 for _ in range(5)]
    for table, block in ((s, ((3, 4), (4, 3))), (t, ((3, 3), (4, 3)))):
        for i, j in product(range(2), repeat=2):
            table[i + 1][j + 1] = block[i][j]
        assert associative(table)
        assert {v for row in table for v in row} == {0, 3, 4}
    assert all((s[x][y] == 0) == (t[x][y] == 0) for x, y in product(range(5), repeat=2))
    assert all(s[x][y] == s[y][x] for x, y in product(range(5), repeat=2))
    assert t[1][2] != t[2][1]
    print(f"Passed: {checked} small tables and all three worked examples.")


if __name__ == "__main__":
    main()
