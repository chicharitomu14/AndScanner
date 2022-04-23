class SymbolInformation(object):
    def __init__(self, symbolName, pos=0, addr=0, length=0):
        self.symbolName = symbolName
        self.position = pos
        self.addr = addr
        self.length = length

    def __hash__(self):
        return (
            hash(self.symbolName)
            + int(self.position)
            + int(self.addr)
            + int(self.length)
        )
