from abc import ABC

from loguru import logger
from analysis import ProcessHelper


class Signature(object):
    def __init__(self, signatureString="", symbol="", filePath="", doStrip=False):
        self.signatureString = signatureString
        self.symbol = symbol
        self.filePath = filePath
        self.doStrip = doStrip
        self.symTable = dict()

    def parse(self, signatureString):
        raise NotImplementedError

    def getCodeLength(self):
        raise NotImplementedError

    def checkCodeBuf(self, code):
        raise NotImplementedError

    def readSymbolTable(self, filePath):
        symtable = ProcessHelper.readSymbolTable(filePath)
        self.symTable = symtable
        return symtable

    def getSymTable(self):
        return self.symTable

    def check(self):
        signature = self.parse(self.signatureString)
        self.symTable = self.readSymbolTable(self.filePath)
        symbolPos = self.symTable[self.symbol].position
        symbolLength = self.symTable[self.symbol].length
        
        file = open(self.filePath, "rb")
        file.seek(symbolPos)
        codeBuf = file.read(symbolLength)
        file.close()

        return signature.checkCodeBuf(codeBuf)

    @staticmethod
    def unpack(_bytes):
        value = _bytes[0] & 0xFF
        value |= (_bytes[1] << 8) & 0xFFFF
        value |= (_bytes[2] << 16) & 0xFFFFFF
        value |= (_bytes[3] << 24) & 0xFFFFFFFF
        return value

    @staticmethod
    def pack(value):
        result = []
        value = int(value)
        result.append((value >> 0) & 0xFF)
        result.append((value >> 8) & 0xFF)
        result.append((value >> 16) & 0xFF)
        result.append((value >> 24) & 0xFF)
        return bytearray(result)

    @staticmethod
    def bytesToHex(_bytes):
        Hex = "{:02x}".format(Signature.unpack(_bytes))
        return Hex.rjust(16, "0")
