import logging
from time import sleep
from threading import Thread

from extractor.rom import ROMExtractor
from settings import EXTRACT_SLEEP_TIMEOUT

log = logging.getLogger('extract_thread')

class ExtractThread(Thread):

    def __init__(self, task_queue, out_queue, name='ExtractThread'):
        super().__init__()
        self._name = name
        self._task_queue = task_queue
        self._out_queue = out_queue

    def run(self):
        while True:
            log.debug("{}: wait for task".format(self._name))

            meta = self._task_queue.get()
            
            log.debug("{}: task queue size: {} output queue size: {}".format(
                self._name, self._task_queue.qsize(), self._out_queue.qsize()
            ))
            
            try:
                extracted = ROMExtractor(meta['romPath']).extract()
                
                if not extracted:
                    log.warn(u"{}: Failed to extract {}".format(
                        self._name, meta['romName']
                    ))
                    continue
                else:
                    log.debug(u"{}: extract {} to {}".format(
                        self._name, meta['romName'], extracted
                    ))

                meta['extracted'] = extracted
                self._out_queue.put(meta)
            except Exception as e:
                log.exception(e)
                log.exception("{}: Exception happened".format(self._name))
            finally:
                self._task_queue.task_done()
                sleep(EXTRACT_SLEEP_TIMEOUT)