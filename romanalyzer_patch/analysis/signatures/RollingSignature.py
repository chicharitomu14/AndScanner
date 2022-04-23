from analysis.signatures.Signature import Signature
from loguru import logger
import math
from hashlib import sha256
import tempfile
import os
from analysis.ProcessHelper import getSigToolCalcOutput


class RollingSignature(Signature):
    def __init__(self):
        super().__init__()
        self.SIGNATURE_TYPES = ["R_AARCH64_V1", "R_AARCH64_V2"]
        self.signatureType = ""
        self.checksumLen = 0
        self.checksumOffset = 0
        self.checksum1 = b""
        self.checksum2 = b""
        self.codeLen = 0

    def getCheckSumLen(self):
        return self.checksumLen

    def getCodeLength(self):
        return self.codeLen

    def getChecksumOffset(self):
        return self.checksumOffset

    def getChecksum1(self):
        return self.checksum1

    def getChecksum2(self):
        return self.checksum2

    # def setContext(self):
    # 	self.context = context

    def getArchArg(self):
        return self.getArchArgFromSigType()

    def getArchArgFromSigType(self):
        if self.signatureType not in self.SIGNATURE_TYPES:
            logger.exception("Invalid sigType {}".format(self.signatureType))
        elif self.signatureType == "R_AARCH64_V1":
            return "--aarch64v1"
        elif self.signatureType == "R_AARCH64_V2":
            return "--aarch64v2"

    def toString(self):
        if self.checksumOffset < 0:
            logger.exception(
                "Error while creating signatureString: checksumOffset < 0!"
            )
            return None

        x = int(math.log(self.checksumLen) / math.log(2))
        checksum1 = Signature.bytesToHex(self.checksum1)
        checksum2 = Signature.bytesToHex(self.checksum2)
        checksumOffsetHex = "{:06x}".format(self.checksumOffset)
        return "{}:{:02x}{}:{}{}".format(
            self.signatureType, x, checksumOffsetHex, checksum1, checksum2
        )

    def checkCodeBuf(self, code):
        try:
            tempFn = tempfile.NamedTemporaryFile(delete=False)
            tempFn.write(code)
            logger.debug("Created and wrote to temporary file: {}".format(tempFn.name))
        except Exception as e:
            logger.exception(
                "Error while creating or writing temporary file: {}".format(e)
            )
        finally:
            os.unlink(tempFn.name)
            tempFn.close()

        try:
            checksum1 = getSigToolCalcOutput(
                self.getArchArg(), tempFn.name, "0", str(self.checksumLen)
            )
            if checksum1 != self.checksum1:
                return False
            checksum2 = getSigToolCalcOutput(
                self.getArchArg(),
                tempFn.name,
                str(self.checksumOffset),
                str(self.checksumLen),
            )
            if checksum2 != self.checksum2:
                return False

        except Exception as e:
            logger.exception("Exception when running sigtool: {}".format(e))

        return True

    def parse(self, signatureString):
        if not signatureString:
            return None

        parts = signatureString.split(":")
        if not parts or len(parts) != 3:
            return None

        self.signatureType = parts[0]
        signatureData = parts[1] + parts[2]
        self.checksumLen = math.pow(2, int(signatureData[0:2], 16))
        self.checksumOffset = int(signatureData[2:8], 16)
        sigsBin = bytearray.fromhex(parts[2])
        if len(sigsBin) != 16:
            logger.exception("Malformated signatureString: sigsBin.length != 16")
            return None
        self.checksum1 = sigsBin[:8]
        self.checksum2 = sigsBin[8:]
        self.codeLen = self.checksumLen + self.checksumOffset
        if self.toString() != signatureString:
            logger.debug(signatureString)
            logger.debug(self.toString())

            logger.exception(
                "Error while parsing signatureString, reencoding not producing same signatureString"
            )

        return self
