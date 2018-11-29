
# give credits to Basj https://stackoverflow.com/questions/3318625/efficient-bidirectional-hash-table-in-python

# This is a very useful class which enables searching/indexing using values or keys
class bidict(dict):
    def __init__(self, *args, **kwargs):
        super(bidict, self).__init__(*args, **kwargs)
        self.inverse = {}
        for key, value in self.items():
            self.inverse.setdefault(value,[]).append(key)

    def __setitem__(self, key, value):
        if key in self:
            self.inverse[self[key]].remove(key)
        super(bidict, self).__setitem__(key, value)
        self.inverse.setdefault(value,[]).append(key)

    def __delitem__(self, key):
        self.inverse.setdefault(self[key],[]).remove(key)
        if self[key] in self.inverse and not self.inverse[self[key]]:
            del self.inverse[self[key]]
        super(bidict, self).__delitem__(key)

if __name__ == "__main__":
    bd = bidict({'a': 1, 'b': 100})
    print(bd)                     # {'a': 1, 'b': 2}
    print(bd.inverse)             # {1: ['a'], 2: ['b']}
    bd['c'] = 1                   # Now two keys have the same value (= 1)
    print(bd)                     # {'a': 1, 'c': 1, 'b': 2}
    print(bd.inverse[100])
    print(bd.inverse)             # {1: ['a', 'c'], 2: ['b']}
    del bd['c']
    print(bd)                     # {'a': 1, 'b': 2}
    print(bd.inverse)             # {1: ['a'], 2: ['b']}
    del bd['a']
    print(bd)                     # {'b': 2}
    print(bd.inverse)             # {2: ['b']}
    bd['b'] = 3
    print(bd)                     # {'b': 3}
    print(bd.inverse)             # {2: [], 3: ['b']}
