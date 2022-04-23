import subprocess as sp
import re
import os
from pathlib import Path
from loguru import logger
from collections import namedtuple

from analysis.signatures.SymbolInformation import SymbolInformation

OBJDUMP_PATH = "romanalyzer_patch/assets/objdump"
# OBJDUMP_PATH = "objdump"
SIGTOOL_PATH = "romanalyzer_patch/assets/sigtool"


Section = namedtuple("Section", ["size", "vma", "fileOffset"])


def execProcessAndGetStdout(cmd):
    return runCommand(cmd)


def execProcessAndGetExitValue(cmd):
    child = sp.Popen(cmd, stdout=sp.PIPE)
    _ = child.communicate()[0]
    return child.returncode


def getObjDumptTOutput(filepath):
    return execProcessAndGetStdout("{} -tT {}".format(OBJDUMP_PATH, filepath))


def getObjDumpHW(filepath):
    return execProcessAndGetStdout("{} -h -w {}".format(OBJDUMP_PATH, filepath))


def getObjDumpHWwithCheck(filepath):
    return getObjDumpHW(filepath)


def getFileArchitecture(filepath):
    lines = execProcessAndGetStdout("file {}".format(filepath))
    if lines:
        return lines[0]
    else:
        return None


def stripSymbolsFromObjFile(filepath, tempFilePath):
    exitValue = execProcessAndGetExitValue(["strip", "-o", tempFilePath, filepath])
    return exitValue == 0


def runObjdumpCommand(params):
    return runCommand(OBJDUMP_PATH + " " + params)


def runCommand(cmd):
    try:
        outputs = sp.check_output(cmd, shell=True)
        # outputs = os.popen(cmd, shell)
        return outputs.splitlines()
    except Exception as e:
        if "objdump" not in cmd:
            logger.exception(e)


def getSymbolTableEntry(fileOrLines, symbol):
    objdumpLines = None
    if isinstance(fileOrLines, list):
        objdumpLines = fileOrLines
    elif isinstance(fileOrLines, str):
        objdumpLines = runObjdumpCommand("-tT {}".format(fileOrLines))

    if not objdumpLines:
        logger.exception(
            "Exception in ProcessHelper.getSymbolTableEntry(): objdumpLines == null"
        )
        return None

    # logger.info(fileOrLines)
    pattern = re.compile("\\s+")

    for line in objdumpLines:
        line = line.decode("utf-8").strip()
        if not line:
            continue
        if symbol not in line:
            continue
        components = pattern.split(line)
        if components[-1] == symbol:
            addrHex = components[0]
            lenHex = 0
            if components[-2] == "Base":
                lenHex = components[-3]
            else:
                lenHex = components[-2]
            addr = int(addrHex, 16)
            length = int(lenHex, 16)
            return {"addr": addr, "len": length}
    return None


def readSymbolTable(filePath):
    symtable = dict()
    if not filePath:
        logger.exception("filePath argument == null!")
        return None
    patternWhitespaces = re.compile("\\s+")
    lines = getObjDumptTOutput(filePath)
    for line in lines:
        line = line.decode("utf-8").strip()
        if not line:
            continue

        if any([".text" not in line, ".text.unlikely" in line, ".text." in line]):
            continue
        components = patternWhitespaces.split(line)
        if len(components) < 4:
            continue
        symbolName = components[len(components) - 1]
        addrHex = components[0]
        lenHex = ""
        for i in range(len(components) - 1):
            if components[i] == ".text":
                lenHex = components[i + 1]
        if not lenHex:
            logger.exception("Invalid line: {}".format(line))
            return None
        addr = int(addrHex, 16)
        length = int(lenHex, 16)
        symtable[symbolName] = SymbolInformation(symbolName, addr=addr, length=length)
    sections = list()
    for line in getObjDumpHW(filePath):
        line = line.decode("utf-8").strip()
        if not line:
            continue
        if "CODE" in line:
            items = patternWhitespaces.split(line)
            size = int(items[2], 16)
            vma = int(items[3], 16)
            fileOffset = int(items[5], 16)
            sections.append(Section(size, vma, fileOffset))
    for symbolInformation in symtable.values():
        addr = symbolInformation.addr
        pos = addr
        for section in sections:
            if addr >= section.vma and addr < (section.vma + section.size):
                pos = section.fileOffset + (addr - section.vma)
                symbolInformation.position = pos

    if Path(filePath).suffix == ".o":
        for line in getObjDumpHWwithCheck(filePath):
            line = line.strip()
            if ".text." not in line:
                continue
            components = patternWhitespaces.split(line)
            for i in range(len(components)):
                symbolName = components[i][len(".text.") :]
                codeLen = int(components[i + 1], 16)
                pos = int(components[i + 4], 16)
                symbolInformation = SymbolInformation(
                    symbolName, addr=pos, length=codeLen
                )
                symbolInformation.position = pos
                symtable[symbolName] = symbolInformation
    return symtable


def getSigToolCalcOutput(archArg, filePath, startPos, endPos):
    stdOutLines = execProcessAndGetStdout(
        " ".join([SIGTOOL_PATH, archArg, "calc", filePath, startPos, endPos])
    )
    if stdOutLines:
        return stdOutLines[0]
    else:
        logger.exception("Empty stdout response from sigtool!")
        return None


def sendByteBufferToSigToolSearch(name, bytesToSendToStdin, archArg, filePath):
    # TODO
    return []
