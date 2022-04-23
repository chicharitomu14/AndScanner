from datetime import datetime
from loguru import logger

AndroidVersionSDK = {
    "11": "30",
    "10": "29",
    "9": "28",
    "8.1.0": "27",
    "8.0.0": "26",
    "7.1": "25",
    "7.0": "24",
    "6.0": "23",
    "5.1": "22",
    "5.0": "21",
}

def loadBuildProperties(filePath):
    buildProperties = dict()
    if not filePath:
        return buildProperties

    with open(filePath) as fp:
        data = fp.readlines()

    for line in data:
        line = line.strip()
        if not line or line[0] == "#" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        buildProperties[key] = value
    return buildProperties


class BuildProperty(object):
    def __init__(self, filePath):
        self.buildProperties = loadBuildProperties(filePath)

    def checkBuildProperty(self, buildProperty, expectedValue):
        return self.buildProperties.get(buildProperty) == expectedValue

    def getChipVendor(self):
        platform = self.buildProperties.get("ro.board.platform", "UNKNOWN").upper()
        if platform.startswith("MSM"):
            return "QUALCOMM"
        elif platform.startswith("MT"):
            return "MTK"
        elif platform.startswith("TEGRA"):
            return "NVIDIA"
        elif any([platform.startswith("EXYNOS"), platform.startswith("UNIVERSAL98")]):
            return "SAMSUNG"
        elif platform.startswith("SC"):
            return "SPREADTRUM"
        else:
            return "UNKNOWN"

    def getAndroidVersion(self):
        version = self.buildProperties.get("ro.build.version.release")
        if not version:
            version = self.buildProperties.get("ro.system.build.version.release")
        return version

    def getBuildDateUtc(self):
        return self.buildProperties.get("ro.build.date.utc")

    def getBuildFingerprint(self):
        return self.buildProperties.get("ro.build.fingerprint", "None")

    def getDeviceModel(self):
        return self.buildProperties.get("ro.product.model")

    def getBuildDisplayName(self):
        return self.buildProperties.get("ro.build.display.id")

    def getPatchlevelDate(self):
        result = self.buildProperties.get("ro.build.version.security_patch")
        if result == None or not result.startswith("20"):
            return None
        else:
            return result

    def isPatchDateClaimed(self, patchReleaseDate):
        patchLevelDate = self.getPatchlevelDate()

        if patchLevelDate == None:
            return False
        try:
            if patchReleaseDate and len(patchReleaseDate) == 7:
                patchReleaseDate += "-01"

            requestedDate = datetime.strptime(patchReleaseDate, "%Y-%m-%d")
            claimedDate = datetime.strptime(patchLevelDate, "%Y-%m-%d")
            return claimedDate >= requestedDate
        except Exception as e:
            logger.exception(e)

        return False

    def getAndroidAPIVersion(self):
        sdk = self.buildProperties.get("ro.build.version.sdk")
        if not sdk:
            version = self.getAndroidAPIVersion()
            sdk = AndroidVersionSDK.get(version)

        return sdk

    def isTooOldAndroidAPIVersion(self):
        return int(self.getAndroidAPIVersion()) < 21
