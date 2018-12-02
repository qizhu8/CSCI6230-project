
class BlumBlumShub(object):
    def __init__(self, seed, p, q):
        if not (p % 4 == 3 and q % 4 == 3):
            raise ValueError("p and q must be blum integers.")

        self.p_ = p
        self.q_ = q

        self.M_ = p * q

        self.x_ = seed

        if self.x_ % p == 0 or self.x_ % q== 0:
            raise ValueError("seed must not be a multiple of p or q.")


    def random(self):
        self.x_ = (self.x_ ** 2) % self.M_
        return self.x_ % 2
