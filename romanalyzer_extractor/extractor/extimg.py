from pathlib import Path
from utils import execute
from extractor.base import Extractor
class ExtImgExtractor(Extractor):

    tool = Path('romanalyzer_extractor/tools/extfstools/ext2rd').absolute()

    def extract(self):
        if not self.chmod(): return
        self.extracted = self.target.parents[0] / (self.target.name+'.extracted')
        if not self.extracted.exists(): self.extracted.mkdir()

        extract_cmd = '{extfstool} "{extimg}" "./:{outdir}"'.format(
            extfstool = self.tool,
            extimg = self.target,
            outdir = self.extracted)

        execute(extract_cmd)

        if self.extracted and self.extracted.exists(): 
            self.log.debug("\textracted path: {}".format(self.extracted))
            return self.extracted
        else:
            self.log.warn("\tfailed to extract {}".format(self.target))
            return None
