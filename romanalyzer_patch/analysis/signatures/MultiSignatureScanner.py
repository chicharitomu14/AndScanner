from loguru import logger
from pathlib import Path
from analysis.signatures.MaskSignature import MaskSignature
from analysis.signatures.RollingSignature import RollingSignature
from analysis.signatures.Signature import Signature
from analysis.signatures.SymbolInformation import SymbolInformation
from analysis import ProcessHelper


def getSignatureInstance(signatureString):
    if not signatureString:
        return None

    signatureType = signatureString.split(":")[0]
    if signatureType == "MASK":
        return MaskSignature().parse(signatureString)
    elif signatureString in ("R_AARCH64_V1", "R_AARCH64_V2"):
        return RollingSignature().parse(signatureString)
    else:
        logger.exception("Invalid signature type: {}".format(signatureType))
        return None


class MultiSignatureScanner(object):
    def __init__(self):
        self.signatureChecker = set()

    def addSignatureChecker(self, signatureStringOrChecker):
        if isinstance(signatureStringOrChecker, RollingSignature):
            self.signatureChecker.add(signatureStringOrChecker)
        elif isinstance(signatureStringOrChecker, str):
            checker = getSignatureInstance(signatureStringOrChecker)
            self.signatureChecker.add(checker)
        else:
            logger.exception("Error: arguments must be of RollingSignature or str")

    def scanFile(self, filePath):
        # TODO
        targetFile = Path(filePath)
        if not targetFile.exists():
            logger.exception(
                "Scanning file not possible, cause the file does not exist!"
            )
            return None
        fileSize = targetFile.stat().st_size
        checksumLengths = dict()

        for checker in self.signatureChecker:
            checksumLength = checker.getCheckSumLen()
            if checksumLength not in checksumLengths:
                checksumLengths[checksumLength] = set()

            checksums = checksumLengths.get(checksumLength)

            checksums.add(bytes(checker.getChecksum1()))
            checksums.add(bytes(checker.getChecksum2()))

        buf = bytearray()
        buf += Signature.pack(len(checksumLengths.keys()))
        for checksumLen in checksumLengths:
            buf += Signature.pack(len(checksumLengths.get(checksumLen)))
            buf += Signature.pack(checksumLen)
            for checksum in checksumLengths.get(checksumLen):
                buf += checksum

        result = ProcessHelper.sendByteBufferToSigToolSearch(
            "sigtool", buf, "--aarch64v1", targetFile.absolute()
        )

        if self.isPermissionDeniedError(result):
            logger.debug(
                "Got 'permission denied error' when accessing file: {}".format(filePath)
            )
            logger.exception(
                "Error when scanning file: {} - Permission denied.".format(filePath)
            )
            return None

        result_length = len(result)
        if (result_length % 16) != 0:
            logger.exception(
                "Output length not a multiple of 16 bytes: {}".format(result_length)
            )

        checksumsFound = dict()
        try:
            for i in range(0, len(result), 16):
                position = Signature.unpack(result[i : i + 4])
                checksumLen = int(Signature.unpack(result[i + 4 : i + 8]))
                if position > fileSize:
                    logger.exception("Parsed symbol position exceeds file size.")
                    return None
                if checksumLen >= 1000000:
                    logger.exception("Length of checksum is too big (>= 1e6)")
                    return None

                checksum = result[i + 8 : i + 16]
                if checksumLen not in checksumsFound:
                    checksumsFound[checksumLen] = dict()
                if checksum not in checksumsFound[checksumLen]:
                    checksumsFound[checksumLen][Signature.bytesToHex(checksum)] = set()
                checksumsFound[checksumLen][Signature.bytesToHex(checksum)].add(
                    position
                )
        except Exception as e:
            logger.exception(e)

        foundItems = set()
        if len(checksumsFound):
            for checker in self.signatureChecker:
                checksumLen = checker.getCheckSumLen()
                if not checksumsFound.get(checksumLen).get(
                    Signature.bytesToHex(checker.getChecksum2())
                ):
                    continue
                if not checksumsFound.get(checksumLen).get(
                    Signature.bytesToHex(checker.getChecksum1())
                ):
                    continue

                for found1pos in checksumsFound.get(checksumLen).get(
                    Signature.bytesToHex(checker.getChecksum1())
                ):
                    wantedFound2pos = found1pos + checker.getChecksumOffset()
                    if wantedFound2pos in checksumsFound.get(checksumLen).get(
                        Signature.bytesToHex(checker.getChecksum2())
                    ):
                        foundItems.add(
                            SymbolInformation(checker.toString(), pos=found1pos)
                        )

        return foundItems

    def isPermissionDeniedError(self, result):
        if not result:
            return False
        resultString = Signature.bytesToHex(result)
        permissionDeniedHexMessages = [
            "4661696c656420746f206f70656e2066696c650a3a205065726d697373696f6e2064656e6965640a",
            "4661696c656420746f206f70656e2066696c653a205065726d697373696f6e2064656e6965640a",
        ]
        for permissionDeniedHexMessage in permissionDeniedHexMessages:
            if resultString == permissionDeniedHexMessage:
                return True
        return False
