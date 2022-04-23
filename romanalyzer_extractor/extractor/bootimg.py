from pathlib import Path
from utils import execute
from extractor.base import Extractor
class BootImgExtractor(Extractor):
    tool = Path('romanalyzer_extractor/tools/bootimg_tools/split_boot').absolute()

    def extract(self):
        if not self.chmod(): return
        self.log.debug("Bootimg extract: {}".format(self.target))
        self.log.debug("\tstart extract target")

        workdir = self.target.parents[0]
        #extract_cmd = '{split_boot} "{boot_img}"'.format(
        extract_cmd = 'cd {workdir} && {split_boot} "{boot_img}"'.format(
                        workdir=workdir,
                        split_boot=self.tool, 
                        boot_img=self.target.absolute())
        execute(extract_cmd)

        self.extracted = workdir / 'boot'
        if not self.extracted.exists(): 
            self.log.warn("\tfailed to extract {}".format(self.target))
            return None
        else:
            self.log.debug("\textracted path: {}".format(self.extracted))
            return self.extracted
