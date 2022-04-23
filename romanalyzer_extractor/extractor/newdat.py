from pathlib import Path
from utils import execute
from extractor.base import Extractor
from extractor.extimg import ExtImgExtractor

class NewDatExtractor(Extractor):
    tool = Path('romanalyzer_extractor/tools/sdat2img/sdat2img.py').absolute()

    def extract(self):
        self.log.debug("New.dat extract: {}".format(self.target))
        workdir = self.target.parents[0]

        transfer_list = workdir / "{}".format(self.target.name.replace('.new.dat', '.transfer.list'))

        if not transfer_list.exists():
            self.log.warn("cannot unpack {} because lack of {}".format(self.target, transfer_list))
            return None

        output_system_img = workdir / "{}".format(self.target.name.replace('.new.dat', '.img'))
        
        convert_cmd = 'python3 {sdat2img} "{transfer_list}" "{system_new_file}" "{system_img}"'.format(
        #convert_cmd = 'cd {workdir} && python3 {sdat2img} {transfer_list} {system_new_file} {system_img}'.format(
            workdir=workdir, sdat2img=self.tool,
            transfer_list=transfer_list, system_new_file=self.target, system_img=output_system_img
        )
        execute(convert_cmd)

        extractor = ExtImgExtractor(output_system_img)
        self.extracted = extractor.extract()
        if self.extracted and self.extracted.exists(): 
            self.log.debug("\textracted path: {}".format(self.extracted))
            return self.extracted
        else:
            self.log.warn("\tfailed to extract {}".format(self.target))
            return None
