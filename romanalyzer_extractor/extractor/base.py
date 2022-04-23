import logging
from pathlib import Path
from utils import execute

class Extractor(object):

    tool = Path()
    log = logging.getLogger('extractor')

    def __init__(self, target):
        self.target = Path(target)

        if self.target.suffix == '.ozip': 
            local_extract = self.target.with_suffix('.zip').name + '.extracted' 
        else: 
            local_extract = self.target.name + '.extracted'
        self.extracted = self.target.parent / local_extract

    def extract(self):
        raise NotImplementedError

    def chmod(self):
        if not self.tool.exists():
            self.log.error("Failed to found {}".format(self.tool))
            return False
        
        chmod_cmd = 'chmod +x "{tool}"'.format(tool=self.tool)
        execute(chmod_cmd)
        return True