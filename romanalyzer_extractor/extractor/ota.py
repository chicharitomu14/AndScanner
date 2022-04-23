from pathlib import Path
from utils import execute
from extractor.base import Extractor

class AndrOtaPayloadExtractor(Extractor):

    tool = Path('romanalyzer_extractor/tools/extract_android_ota_payload/extract_android_ota_payload.py').absolute()

    def extract(self):
        self.log.debug("Android OTA Payload extract target: {}".format(self.target))
        self.log.debug("\tstart extract payload.bin.")

        convert_cmd = 'python3 {extract_script} "{payload}" "{extracted_dir}"'.format(
                        extract_script=self.tool, 
                        payload=self.target.absolute(), 
                        extracted_dir=self.extracted
                    )
        execute(convert_cmd)

        self.log.debug('\textracted ota payload.bin to: {}'.format(self.extracted))

        if not self.extracted.exists(): 
            self.log.warn("\tfailed to extract {} using unzip".format(self.converted_zip))
            return None
        else:
            self.log.debug("\textracted ota payload.bin to: {}".format(self.extracted))
            return self.extracted
