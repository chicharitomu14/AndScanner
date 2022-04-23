from pathlib import Path

from analysis_extractor.classifier import Classify

from extractor.base import Extractor
from extractor.archive import ArchiveExtractor
from extractor.binwalk import BinwalkExtractor
from extractor.bootimg import BootImgExtractor
from extractor.brotli import BrotliExtractor
from extractor.extimg import ExtImgExtractor
from extractor.newdat import NewDatExtractor
from extractor.ota import AndrOtaPayloadExtractor
from extractor.ozip import OZipExtractor
from extractor.sparse import SparseImgExtractor
from extractor.dir import DirExtractor

class ROMExtractor(Extractor):

    process_queue = []

    extractor_map = {
        'ozip': OZipExtractor,
        'archive': ArchiveExtractor,
        'otapayload': AndrOtaPayloadExtractor,
        'bootimg': BootImgExtractor,
        'sparseimg': SparseImgExtractor,
        # 'dataimg': BinwalkExtractor,
        'extimg': ExtImgExtractor,
        'brotli': BrotliExtractor,
        'newdat': NewDatExtractor,
        'dir': DirExtractor
    }

    def enqueue(self, target):
        if isinstance(target, list): 
            self.process_queue.extend(target)
        elif isinstance(target, Path): 
            self.process_queue.append(target)

    def extract(self):
        self.log.debug('add {} to process queue'.format(self.target))
        self.process_queue.append(self.target)
        
        while self.process_queue:
            
            process_item = self.process_queue.pop()
            guess = Classify(process_item)
            
            #print(process_item,"   ",guess)
            
            self.log.debug("\t 000000 {}  {}".format(process_item,guess))
            
            if guess not in self.extractor_map.keys():
                continue

            try:
                print(guess)
                #print(process_item,"   ",guess)
                self.enqueue(self.extractor_map[guess](process_item).extract())
            except Exception as e:
                self.log.exception("failed to extract {} ... skip it.".format(process_item))
                self.log.exception(e)

        if not self.extracted.exists():
            self.log.debug("Failed to extract: {}".format(self.extracted))
            return None
        else:
            self.log.debug("Extracted path: {}".format(self.extracted))
            return self.extracted
