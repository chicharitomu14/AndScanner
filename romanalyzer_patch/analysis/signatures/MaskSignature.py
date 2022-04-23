from analysis.signatures.Signature import Signature
from loguru import logger
from hashlib import sha256
from collections import namedtuple

Mask = namedtuple("Mask", ["mask", "position"])


class MaskSignature(Signature):
    def __init__(self):
        super().__init__()
        self.SIGNATURE_TYPE = "MASK"
        self.maskList = list()
        self.signatureType = ""
        self.architecture = ""
        self.codeLen = 0
        self.originalCode = b""
        self.checksumSha256 = ""

    def getCodeLength(self):
        return self.codeLen

    def getSignatureType(self):
        return self.signatureType

    def parse(self, signatureString):
        parts = signatureString.split(":")
        if len(parts) != 4 and len(parts) != 3:
            logger.exception(
                "Exception while parsing mask signature string: {}".format(
                    signatureString
                )
            )
            return
        self.signatureType = parts[0]
        self.codeLen = int(parts[1], 16)
        self.checksumSha256 = parts[2]
        maskStrList = list()
        if len(parts) == 4:
            maskString = parts[3]
            maskStrList = maskString.split("_")

        pos = 0
        for maskStr in maskStrList:
            if not maskStr:
                continue
            offset = int(maskStr[:4], 16)

            maskCode = maskStr[4:]
            mask = 0
            if maskCode == "A":
                mask = 0x9F00001F
            elif maskCode == "B":
                mask = 0xFFC003FF
            elif maskCode == "C":
                mask = 0xFC000000
            else:
                if len(maskCode) == 8:
                    mask = int(maskCode, 16)
                else:
                    logger.exception("Mask code not neccessary length!")
            pos += offset
            self.maskList.append(Mask(position=pos, mask=mask))
        return self

    def checkCodeBuf(self, code):
        maskedCode = bytearray()
        maskPos = 0
        for i in range(0, len(code), 4):
            instBytes = code[i : i + 4]
            if maskPos < len(self.maskList) and self.maskList[maskPos].position == i:
                inst = Signature.unpack(instBytes)
                inst = inst & self.maskList[maskPos].mask
                instBytes = Signature.pack(inst)
                maskPos += 1
            maskedCode += instBytes

        calculatedHash = sha256(maskedCode).hexdigest()
        if not self.checksumSha256:
            logger.debug("sha256 is null: parsed")
        if not calculatedHash:
            logger.debug("sha256 is null: calculated")
        return True if self.checksumSha256 == calculatedHash else False