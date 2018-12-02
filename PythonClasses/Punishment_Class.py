import PythonClasses.Package_Class as pkg

class Punisher(object):
    def __init__(self):
        super().__init__()
        self.punishment_value_ = 0

    def get_punish_val(self):
        return self.punishment_value_

    def punish(self):
        self.punishment_value_ += 1

    def punish_by_package(self, package):
        if issubclass(type(package), pkg.ERR_PKG):
            self.punish()
        else: # no longer punished!
            self.punishment_value_ = 0

    def need_to_cooldown(self):
        return self.punishment_value_ > 10
