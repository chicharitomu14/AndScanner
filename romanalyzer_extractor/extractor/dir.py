from pathlib import Path

class DirExtractor(object):

    def __init__(self, target):
        self.target = Path(target)
    
    def extract(self):
        if not self.target.exists() or \
            not self.target.is_dir():
            return []
        return [file for file in self.target.rglob('*') if not file.is_dir()]
