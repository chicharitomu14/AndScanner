from utils import execute
from extractor.base import Extractor

class ArchiveExtractor(Extractor):

    def extract(self):
        # if not self.chmod(): return None
        self.log.debug("Archive extract target: {}".format(self.target))
        self.log.debug("\tstart extract archive.")

        extract_cmd = '' 
        suffix = self.target.suffix
        abspath = self.target.absolute()

        if self.target.stat().st_size == 0:
            self.log.warn("\tthis is a empty archive {}".format(self.target))
            return None

        if suffix in ('.tar.gz', '.tgz'):
            extract_cmd = 'mkdir "{}"'.format(self.extracted)
            extract_cmd = extract_cmd+' && tar -zxf "{}" -C "{}"'.format(abspath, self.extracted)
        elif suffix == '.gz':
            extract_cmd = 'gunzip -f -d "{}"'.format(abspath)
            self.extracted = self.target.with_suffix('')
        elif suffix in ('.zip'):
            extract_cmd = 'unzip -o "{}" -d "{}"'.format(abspath, self.extracted)
        elif suffix == '.7z':
            extract_cmd = '7za x {} -o{} -y'.format(abspath, self.extracted)
        elif suffix == ".ext4":
            extract_cmd = '7z x {} -o{} -y'.format(abspath, self.extracted)
        elif suffix == '.md5':
            extract_cmd = 'mkdir "{}"'.format(self.extracted)
            extract_cmd = extract_cmd+' && tar -xf "{}" -C "{}"'.format(abspath, self.extracted)
        elif suffix == '.APP' and str(abspath).find("UPDATE.APP")!=-1:
            extract_cmd = 'perl romanalyzer_extractor/tools/huawei_erofs/split_updata.pl "{}" "{}"'.format(abspath,self.extracted)
        else:
            return None
        """
        elif suffix == ".tar.md5":
            extract_cmd = 'tar -xvf {}'.format(abspath)
        """
        
        #print(extract_cmd)
        execute(extract_cmd)

        if not self.extracted.exists(): 
            self.log.warn("\tfailed to extract {}".format(self.target))
            return None
        else:
            self.log.debug("\textracted path: {}".format(self.extracted))
            return self.extracted
