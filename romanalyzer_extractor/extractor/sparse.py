from pathlib import Path
from utils import execute
from extractor.base import Extractor
from extractor.extimg import ExtImgExtractor
from extractor.archive import ArchiveExtractor

class SparseImgExtractor(Extractor):
    
    tool = Path('romanalyzer_extractor/tools/android-simg2img/simg2img').absolute()

    def extract(self):
        if not self.chmod(): return None

        self.log.debug("sparse image: {}".format(self.target))
        self.log.debug("\tstart convert sparse img to ext4 img")
        
        ext4img = self.target.parents[0] / (self.target.name+'.ext4')
        convert_cmd = '{simg2img} "{sparse_img}" "{output}"'.format(
                    simg2img=self.tool, 
                    sparse_img=self.target.absolute(), 
                    output=ext4img)
        execute(convert_cmd)

        self.log.debug("\tconverted ext4 image: {}".format(ext4img))

        #extractor = ExtImgExtractor(ext4img)
        extractor = ArchiveExtractor(ext4img)
        self.extracted =  extractor.extract()

        if not self.extracted.exists(): 
            self.log.warn("\tfailed to extract {}".format(self.target))
            return None
        else:
            self.log.debug("\textracted path: {}".format(self.extracted))
            return self.extracted
