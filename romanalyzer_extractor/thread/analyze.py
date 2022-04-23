import logging
from time import sleep
from pathlib import Path
from threading import Thread

from analysis.static import analyze_extracted
from manager.mongo import MongoManager
from utils import rmf, rmdir
from settings import ANALYZE_SLEEP_TIMEOUT

log = logging.getLogger('analyze_thread')
mongo_manager = MongoManager()

class AnalyzeThread(Thread):

    def __init__(self, task_queue, name='AnalyzeThread'):
        super().__init__()
        self._name = name
        self._task_queue = task_queue

    def run(self):
        while True:
            log.debug("{}: wait for task".format(self._name))

            meta = self._task_queue.get()

            log.debug("{}: task queue size: {}".format(
                self._name, self._task_queue.qsize()
            ))

            try:
                self.job(meta)
            except Exception as e:
                log.exception(e)
            finally:
                self.clean(meta)
                self._task_queue.task_done()
                sleep(ANALYZE_SLEEP_TIMEOUT)

    def job(self, meta):
        log.debug(u"{}: Start analyzing {}".format(
            self.name, meta['romName']
        ))
        
        analyze_extracted(meta)
        
        log.debug(u"{}: Success analyzed {}".format(
            self.name, meta['romName']
        ))

        mongo_manager.update_many({"filemd5": meta['romMd5']},{"analyzed": True})
    
    @staticmethod
    def clean(meta):
        rmdir(meta['extracted'])
        rmdir(meta['romPath']+'.extracted')
        rmf(meta['romPath'])
        rmf(Path(meta['romPath']).with_suffix('.zip'))