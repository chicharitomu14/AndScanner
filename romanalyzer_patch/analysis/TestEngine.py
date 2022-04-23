import zipfile
import base64
import re
import os
from pathlib import Path

from rich import print as rich_print
from rich.progress import track

import lzma
import json
from loguru import logger
import multiprocessing

from analysis.BuildProperty import BuildProperty
from analysis.signatures.MaskSignature import MaskSignature
from analysis.signatures.RollingSignature import RollingSignature
from analysis.signatures.MultiSignatureScanner import MultiSignatureScanner
from analysis import ProcessHelper


def validateFilename(filename):
    if not filename.startswith("/system"):
        logger.exception("Filename {}  doesn't start with '/system/".format(filename))
        return False

    if "/../" in filename:
        logger.exception("Filename {} contains directory traversal".format(filename))
        return False

    return True


class TestEngine(object):
    def __init__(self, localFirmwareRoot, buildProperty=None):
        self._localFirmwareRoot = Path(localFirmwareRoot)
        if not buildProperty:
            buildProperty = self.searchBuildProperty()

        self._buildProperties = BuildProperty(buildProperty)

        self._buildtest_database = dict()
        self._vulnerabiliies_databse = dict()
        self._basicTestResultCache = dict()
        self.loadTestSuites()

    def searchBuildProperty(self):
        outputs = os.popen(f'find {self._localFirmwareRoot} -name "build.prop"').read()
        outputs = outputs.splitlines()
        if not outputs:
            return None
        for line in outputs:
            if "/system/build.prop" in line:
                logger.debug("Find build.prop location: {}".format(line))
                return line

        result = outputs.pop()
        logger.debug("Maybe build.prop location: {}".format(result))
        return result

    def localize(self, filePath):
        return self._localFirmwareRoot / filePath.lstrip("/")

    def loadAllBasicTests(self, allBasicTests):
        with open(allBasicTests) as fp:
            self._buildtest_database = json.load(fp)

    def loadChunks(self, chunks):
        for chunk in chunks:
            with open(chunk) as fp:
                data = json.load(fp)

            if "basicTests" in data:
                self._buildtest_database.update(data["basicTests"])

            elif "vulnerabilities" in data:
                self._vulnerabiliies_databse.update(data["vulnerabilities"])

    def loadTestSuites(self):
        allTestSuites = json.load(open("romanalyzer_patch/assets/allTestSuites.json"))
        apiVersion = self._buildProperties.getAndroidAPIVersion()
        
        
        logger.debug("API Version: {}".format(apiVersion))
        if apiVersion not in allTestSuites:
            logger.exception(
                "Current API version is not support: {}".format(apiVersion)
            )
            return
        testSuite = allTestSuites[apiVersion]
        basicTestChunks = [
            "romanalyzer_patch/" + url.replace("https://snoopsnitch-api.srlabs.de", "assets")
            for url in testSuite["basicTestUrls"]
        ]
        self.loadChunks(basicTestChunks)
        vulnChunks = [
            "romanalyzer_patch/" + url.replace("https://snoopsnitch-api.srlabs.de", "assets")
            for url in testSuite["vulnerabilitiesUrls"]
        ]
        self.loadChunks(vulnChunks)

    def getBasicTestByUUID(self, uuid):
        return self._buildtest_database.get(uuid)

    def getVulnLogicByCVE(self, cve):
        return self._vulnerabiliies_databse.get(cve)

    def getBasicTestResultByUUID(self, uuid):
        test = self.getBasicTestByUUID(uuid)
        return self.executeBasicTest(test) if test else None

    def show_results(self, reports):
        if not reports:
            return dict()

        TCnt = reports.count("T")
        FCnt = reports.count("F")
        NCnt = reports.count("N")
        _Cnt = reports.count("_")
        DCnt = reports.count("D")

        print("Total: {}".format(TCnt + FCnt + NCnt + _Cnt + DCnt))
        print("Patched: {}".format(TCnt))
        print("Missing: {}".format(FCnt))
        print("Claimed: {}".format(DCnt))
        print("Inconclusive: {}".format(_Cnt))
        print("NotAffected: {}".format(NCnt))

        #line = ""
        #for i, res in enumerate(reports):
        #    if i % 24 == 0:
        #       rich_print(line)
        #       #rich_print()
        #       line = ""

        #   if res == "T":
        #       line += "[green on green]T[/green on green]"
        #   elif res == "F":
        #       line += "[red on red]F[/red on red]"
        #   elif res == "N":
        #       line += "[white on white]N[/white on white]"
        #   elif res == "_":
        #       line += "[blue on blue]_[/blue on blue]"
        #   elif res == "D":
        #       line += "[yellow on yellow]D[/yellow on yellow]"
        #rich_print(line)
        
        return {
            "Summary": {
                "Patched": TCnt,
                "Missing": FCnt,
                "Claimed": DCnt,
                "Inconclusive": _Cnt,
                "NotAffected": NCnt,
            }
        }

    def testWorker(self, testArgs):
        cve, vulnObject = testArgs
        isNotAffected = self.runVulnLogicTest(vulnObject["testNotAffected"])

        if isNotAffected:
            return {cve: "N"}

        isVulnerable = self.runVulnLogicTest(vulnObject["testVulnerable"])
        isFixed = self.runVulnLogicTest(vulnObject["testFixed"])

        if isFixed == None or isVulnerable == None or (isFixed and isVulnerable):
            return {cve: "_"}
        elif isFixed and not isVulnerable:
            return {cve: "T"}
        elif not isFixed and isVulnerable:
            refPatchlevelDate = vulnObject.get("patchlevelDate") or vulnObject.get("category")
            if refPatchlevelDate and not self._buildProperties.isPatchDateClaimed(
                refPatchlevelDate
            ):
                return {cve: "D"}
            else:
                return {cve: "F"}
        else:
            return {cve: "_"}

    def runAllVulnLogicTest(self):
        reports = dict()
        totalTasks = len(self._vulnerabiliies_databse)
        logger.debug("Total number of testcase: {}".format(totalTasks))

        # pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
        pool = multiprocessing.Pool(processes=8)
        
        taskArgs = (
            [cve, vulnObject]
            for cve, vulnObject in self._vulnerabiliies_databse.items()
        )

        # for testResult in track(
        #     pool.imap_unordered(self.testWorker, taskArgs),
        #     total=totalTasks,
        #     description="Runing vulnerability testing...",
        # ):
        
        for testResult in pool.imap_unordered(self.testWorker, taskArgs):
            reports.update(testResult)

        pool.close()

        summary = self.show_results("".join(reports.values()))
        reports.update(summary)
        return reports

    def runVulnLogicTest(self, testObject):
        if isinstance(testObject, str):
            result = self.executeBasicTestByUUID(testObject)
            # logger.debug(f"UUID: {testObject} Result: {result}")
            return result

        test = testObject
        if "testType" not in test:
            logger.exception("basictest is missing testType field!")
            return None

        testType = test["testType"]
        # if testType in ("TRUE", "FALSE"):
        #     logger.debug(f"TestType: {testType}")
        # else:
        #     logger.debug(
        #         "TestType: {} Subtests: {}".format(testType, len(test["subtests"]))
        #     )

        if testType == "TRUE":
            return True
        elif testType == "FALSE":
            return False
        elif testType == "AND":
            subtests = test["subtests"]
            nullFound = False
            for subtest in subtests:
                subtestResult = self.runVulnLogicTest(subtest)
                if subtestResult == None:
                    nullFound = True
                elif not subtestResult:
                    return False
            if nullFound:
                return None
            return True
        elif testType == "NAND":
            subtests = test["subtests"]
            nullFound = False
            for subtest in subtests:
                subtestResult = self.runVulnLogicTest(subtest)
                if subtestResult == None:
                    nullFound = True
                elif not subtestResult:
                    return True
            if nullFound:
                return None
            return False
        elif testType == "OR":
            subtests = test["subtests"]
            nullFound = False
            for subtest in subtests:
                subtestResult = self.runVulnLogicTest(subtest)
                if subtestResult == None:
                    nullFound = True
                elif subtestResult == True:
                    return True
            if nullFound:
                return None
            return False
        elif testType == "NOR":
            subtests = test["subtests"]
            nullFound = False
            for subtest in subtests:
                subtestResult = self.runVulnLogicTest(subtest)
                if subtestResult == None:
                    nullFound = True
                elif subtestResult == True:
                    return False
            if nullFound:
                return None
            return True
        elif testType == "NOT":
            subtests = test["subtests"]
            subtestResult = self.runVulnLogicTest(subtests)
            if subtestResult == None:
                return None
            return not subtestResult
        else:
            logger.exception("Unknown testType: {}".format(testType))
            return None

    def threadExecuteBasicTestByUUID(self, uuid, queue):
        result = self.executeBasicTestByUUID(uuid)
        queue.put(result)

    def executeBasicTestByUUID(self, uuid):
        if uuid.startswith("!"):
            subtestResult = self.executeBasicTestByUUID(uuid[1:])
            if subtestResult == None:
                return None
            else:
                return not subtestResult
        if uuid not in self._basicTestResultCache:
            basicTestResult = self.getBasicTestResultByUUID(uuid)
            self._basicTestResultCache[uuid] = basicTestResult
            return basicTestResult
        else:
            # logger.debug("executeBasicTestByUUID hit cache!")
            return self._basicTestResultCache[uuid]

    def executeBasicTest(self, test):
        testType = test.get("testType")
        if not testType:
            logger.exception("basic test has no testtype information: {}".format(test))
            return None

        if testType == "CHIPSET_VENDOR":
            return self.runChipsetVendorTest(test)
        elif testType == "CHIPSET_VENDOR_OR_UNKNOWN":
            return self.runChipsetVendorOrUnknownTest(test)
        elif testType == "ANDROID_VERSION_EQUALS":
            return self.runAndroidVersionEqualsTest(test)
        elif testType == "FILE_EXISTS":
            return self.runFileExistsTest(test)
        elif testType == "FILE_CONTAINS_SUBSTRING":
            return self.runFileContainsSubstringTest(test)
        elif testType == "XZ_CONTAINS_SUBSTRING":
            return self.runXzContainsSubstringTest(test)
        elif testType == "ZIP_CONTAINS_SUBSTRING":
            return self.runZipContainsSubstringTest(test)
        elif testType == "ZIP_ENTRY_EXISTS":
            return self.runZipEntryExistsTest(test)
        elif testType == "BINARY_CONTAINS_SYMBOL":
            return self.runBinaryContainsSymbolTest(test)
        elif testType == "DISAS_FUNCTION_CONTAINS_STRING":
            return self.runDisasFunctionContainsStringTest(test)
        # elif testType == "DISAS_FUNCTION_MATCHES_REGEX":
        #     return self.runDisasFunctionMatchesRegexTest(test)
        elif testType == "BUILD_PROP_EQUALS":
            return self.runBuildPropEqualsTest(test)
        elif testType == "MASK_SIGNATURE_SYMBOL":
            return self.runMaskSignatureTest(test)
        elif testType == "ROLLING_SIGNATURE":
            return self.runRollingSignatureTest(test)
        # elif testType == "COMBINED_SIGNATURE":
        #     return self.runCombinedSignatureTest(test)
        else:
            # logger.exception(f"Unknown testType: {testType}")
            return None

    def is64BitSystem(self):
        indicatorFile1Path = Path("/system/lib64/libstagefright.so")
        indicatorFile2Path = Path("/system/lib64/libskia.so")
        return any(
            [
                self.localize(indicatorFile1Path).exists(),
                self.localize(indicatorFile2Path).exists(),
            ]
        )

    """ Basic Tests
        
    """

    def runChipsetVendorTest(self, test):
        return self._buildProperties.getChipVendor() == test["VENDOR"]

    def runChipsetVendorOrUnknownTest(self, test):
        vendor = self._buildProperties.getChipVendor()
        return any([vendor == "UNKNOWN", vendor == test["VENDOR"]])

    def runAndroidVersionEqualsTest(self, test):
        currentAndroidVersion = self._buildProperties.getAndroidVersion()
        return (
            currentAndroidVersion == test["androidVersion"]
            if currentAndroidVersion
            else None
        )

    def runFileExistsTest(self, test):
        filename = test["filename"]
        if not validateFilename(filename):
            return None
        filepath = self.localize(filename)
        if filepath.exists():
            return True
        else:
            logger.warning("Not exists: {}".format(filepath))
            return False

    def runFileContainsSubstringTest(self, test):
        filename = test["filename"]
        if not validateFilename(filename):
            return None

        needle = b""
        if "substring" in test:
            if "substringB64" in test:
                logger.exception(
                    "Test FILE_CONTAINS_SUBSTRING can only use SUBSTRING or SUBSTRING_B64, not both"
                )
                return None
            needle = test["substring"].encode()
        else:
            needle = base64.b64decode(test["substringB64"])

        # check the path relative the rom:  <18-11-20, Vancir> #
        f = self.localize(filename)
        if not f.exists():
            return None

        if "substring" in test:
            needle = test["substring"].encode()
        elif "substringB64" in test:
            needle = base64.b64decode(test["substringB64"])

        with f.open("rb") as fp:
            file_contents = fp.read()

        return needle in file_contents

    def runXzContainsSubstringTest(self, test):
        filename = test["filename"]
        needle = b""
        if "substring" in test:
            if "substringB64" in test:
                logger.exception(
                    "Test XZ_CONTAINS_SUBSTRING can only use SUBSTRING or SUBSTRING_B64, not both"
                )
                return None
            needle = test["substring"].encode()
        else:
            needle = base64.b64decode(test["substringB64"])

        if not validateFilename(filename):
            return None
        f = self.localize(filename)
        if not f.exists():
            return None

        data = lzma.open(str(f.absolute())).read()
        return needle in data

    def runZipContainsSubstringTest(self, test):
        filename = test["zipFile"]
        zipitem = test["zipItem"]
        needle = b""

        if "substring" in test:
            if "substringB64" in test:
                logger.exception(
                    "Test FILE_CONTAINS_SUBSTRING can only use SUBSTRING or SUBSTRING_B64, not both"
                )
                return None
            needle = test["substring"].encode()
        else:
            needle = base64.b64decode(test["substringB64"])

        if not validateFilename(filename):
            return None

        filepath = self.localize(filename)
        if not filepath.exists():
            return None

        with zipfile.ZipFile(str(filepath.absolute())) as zf:
            if zipitem not in zf.namelist():
                return None
            with zf.open(zipitem) as f:
                data = f.read()
                return True if needle in data else False

        return None

    def runZipEntryExistsTest(self, test):
        filename = test["zipFile"]
        zipitem = test["zipItem"]
        if not validateFilename(filename):
            return None
        filepath = self.localize(filename)
        if not filepath.exists():
            return None

        zf = zipfile.ZipFile(str(filepath.absolute()))
        return zipitem in zf.namelist()

    def runBuildPropEqualsTest(self, test):
        buildProperty = test["buildProperty"]
        expectedValue = test["value"]
        return self._buildProperties.checkBuildProperty(buildProperty, expectedValue)

    def runRollingSignatureTest(self, test):
        filename = test["filename"]
        filepath = self.localize(filename)
        rollingSignature = test["rollingSignature"]
        signature = self.getRollingSignatureForTest(test)

        scanner = MultiSignatureScanner()
        scanner.addSignatureChecker(signature)

        results = scanner.scanFile(filepath.absolute())
        for symbolInformation in results:
            if symbolInformation.symbolName == rollingSignature:
                return True
        return False

    def runCombinedSignatureTest(self, test):
        filename = test["filename"]
        filepath = self.localize(filename)
        maskSignatureString = test["maskSignature"]
        rollingSignature = self.getRollingSignatureForTest(test)
        scanner = MultiSignatureScanner()
        scanner.addSignatureChecker(rollingSignature)

        maskSignatureChecker = MaskSignature()
        maskSignatureChecker.parse(maskSignatureString)

        results = scanner.scanFile(filepath.absolute())
        for symbolInfo in results:
            symbolPos = symbolInfo.position
            symbolLength = symbolInfo.length

            codeBuf = b""
            file = filepath.open("rb")
            file.seek(symbolPos)
            codeBuf = file.read(symbolLength)
            file.close()

            if maskSignatureChecker.checkCodeBuf(codeBuf):
                return True
        return False

    def runBinaryContainsSymbolTest(self, test, objdumpLines=None):
        filename = test["filename"]
        symbol = test["symbol"]

        if not validateFilename(filename):
            return None

        filePath = self.localize(filename)
        if not filePath.exists():
            return None

        try:
            if objdumpLines:
                return ProcessHelper.getSymbolTableEntry(objdumpLines, symbol) != None
            else:
                return (
                    ProcessHelper.getSymbolTableEntry(str(filePath.absolute()), symbol)
                    != None
                )
        except Exception as e:
            logger.exception(e)
            return None

    def runDisasFunctionContainsStringTest(self, test, objdumpLines=None):
        filename = test["filename"]
        filepath = self.localize(filename)
        symbol = test["symbol"]
        # substringB64 = test["substringB64"]
        # substring = base64.b64decode(substringB64)
        substring = test["substring"]
        if not validateFilename(filename):
            return None

        if not filepath.exists():
            return None

        try:
            entry = None
            if objdumpLines:
                entry = ProcessHelper.getSymbolTableEntry(objdumpLines, symbol)
            else:
                entry = ProcessHelper.getSymbolTableEntry(
                    str(filepath.absolute()), symbol
                )

            if not entry:
                return False
            addr = int(entry["addr"])
            size = int(entry["len"])
            addrHex = "{:02x}".format(addr)
            addrEndHex = "{:02x}".format(addr + size)
            arguments = "-d --start-address=0x{} --stop-address=0x{} {}".format(
                addrHex, addrEndHex, filepath.absolute()
            )
            lines = ProcessHelper.runObjdumpCommand(arguments)
            return any([substring in str(line) for line in lines])
        except Exception as e:
            logger.exception(e)
            return None

    def runDisasFunctionMatchesRegexTest(self, test, objdumpLines=None):
        filename = test["filename"]
        filepath = self.localize(filename)
        symbol = test["symbol"]
        regex = test["regex"]
        p = re.compile(regex)
        if not validateFilename(filename):
            return None

        if not filepath.exists():
            return None

        try:
            entry = None
            if objdumpLines:
                entry = ProcessHelper.getSymbolTableEntry(objdumpLines, symbol)
            else:
                entry = ProcessHelper.getSymbolTableEntry(
                    str(filepath.absolute()), symbol
                )

            if entry == None:
                return None

            addr = int(entry["addr"])
            size = int(entry["len"])
            addrHex = "{:02x}".format(addr)
            addrEndHex = "{:02x}".format(addr + size)
            arguments = "-d --start-address=0x{} --stop-address=0x{} {}".format(
                addrHex, addrEndHex, filepath.absolute()
            )
            lines = ProcessHelper.runObjdumpCommand(arguments)
            builder = "\n".join(lines)

            # TODO: check if there regex correct?
            m = p.match(builder)
            return m.matches()
        except Exception as e:
            logger.exception(e)
            return None

    def runMaskSignatureTest(self, test, symbolTable=None):
        signature = test["signature"]
        filename = test["filename"]
        filepath = self.localize(filename)
        symbol = test["symbol"]
        if not validateFilename(filename):
            return None

        if not filepath.exists():
            return None

        signatureChecker = MaskSignature()
        signatureChecker.parse(signature)

        if not symbolTable:
            symbolTable = signatureChecker.readSymbolTable(filepath.absolute())

        if not symbolTable:
            logger.exception(
                "Error: creating symbol table failed for file: {}".format(filepath)
            )
            return None

        symbolInfo = symbolTable.get(symbol)
        if not symbolInfo:
            return None

        symbolPos = symbolInfo.position
        symbolLength = symbolInfo.length

        codeBuf = b""
        file = filepath.open("rb")
        file.seek(symbolPos)
        codeBuf = file.read(symbolLength)
        file.close()

        return signatureChecker.checkCodeBuf(codeBuf)

    def getRollingSignatureForTest(self, test):
        try:
            testType = test["testType"]
            if test != None and (
                testType == "ROLLING_SIGNATURE" or testType == "COMBINED_SIGNATURE"
            ):
                rollingSignature = test["rollingSignature"]
                signatureType = rollingSignature.split(":")[0]
                if signatureType not in RollingSignature().SIGNATURE_TYPES:
                    logger.exception(
                        "ROLLING_SIGNATURE: Not a valid rolling signature string!"
                    )
                    return None
                signature = RollingSignature().parse(rollingSignature)
                return signature
        except Exception as e:
            logger.exception(e)
            return None
