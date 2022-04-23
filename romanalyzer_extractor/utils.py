import os
import shutil
import logging
import logging.config
import subprocess
from pathlib import Path
from configparser import ConfigParser

LOGCFG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'default': {
            'format': ('%(asctime)4s %(process)s:%(module)8s [%(levelname)s] - %(message)s'),
            'datefmt': '%m-%d %H:%M'
        }
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'default',
            'stream': 'ext://sys.stdout'
        },
        'debuglog': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.FileHandler',
            'filename': 'romanalyzer_extractor/log/debug.log',
            'mode': 'w',
        },
        'analyzelog': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.FileHandler',
            'filename': 'romanalyzer_extractor/log/analyze.log',
            'mode': 'w',
        }, 
        'staticlog': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.FileHandler',
            'filename': 'romanalyzer_extractor/log/static.log',
            'mode': 'w',
        }, 
        'downloadlog': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.FileHandler',
            'filename': 'romanalyzer_extractor/log/download.log',
            'mode': 'w',
        },
        'extractlog': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.FileHandler',
            'filename': 'romanalyzer_extractor/log/extract.log',
            'mode': 'w',
        },
        'awsdownloadlog': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.FileHandler',
            'filename': 'romanalyzer_extractor/log/aws_down.log',
            'mode': 'w',
        },
        'awsuploadlog': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.FileHandler',
            'filename': 'romanalyzer_extractor/log/aws_up.log',
            'mode': 'w',
        },
        'mongolog': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.FileHandler',
            'filename': 'romanalyzer_extractor/log/mongo.log',
            'mode': 'w',
        },
        'neo4jlog': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.FileHandler',
            'filename': 'romanalyzer_extractor/log/neo4j.log',
            'mode': 'w',
        },
        'extractorlog': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.FileHandler',
            'filename': 'romanalyzer_extractor/log/extractor.log',
            'mode': 'w',
        }
    },
    'loggers': {
        'debug': {
            'level': 'DEBUG',
            'handlers': ['console', 'debuglog']
        },
        'download_thread': {
            'level': 'DEBUG',
            'handlers': ['downloadlog']
        },
        'extract_thread': {
            'level': 'DEBUG',
            'handlers': ['extractlog']
        },
        'analyze_thread': {
            'level': 'DEBUG',
            'handlers': ['analyzelog']
        },
        'analysis_static': {
            'level': 'DEBUG',
            'handlers': ['staticlog']
        },
        'aws_download': {
            'level': 'INFO',
            'handlers': ['awsdownloadlog']
        },
        'aws_upload': {
            'level': 'INFO',
            'handlers': ['awsuploadlog']
        },
        'mongo': {
            'level': 'INFO',
            'handlers': ['mongolog']
        },
        'neo4j': {
            'level': 'DEBUG',
            'handlers': ['neo4jlog']
        },
        'extractor': {
            'level': 'DEBUG',
            'handlers': ['extractorlog']
        }
    }
}

logging.config.dictConfig(LOGCFG)
log = logging.getLogger('debug')

def readcfg(filepath, section='', field=''):
    conf = ConfigParser()
    conf.read(filepath)
    if not section: 
        return conf
    elif section and not field: 
        return conf[section]
    else: 
        return conf[section][field]

def rmf(f):
    f = Path(f)
    if not f.exists():
        log.warn(u"Failed to remove: {} not exists".format(f.name))
        return

    try:
        os.remove(f.absolute())
        log.debug(u"Success removed: {}".format(f.name))
    except Exception as e:
        log.exception(u"Failed to remove: exception happened. {}".format(f.name))
    
def rmdir(d):
    d = Path(d)
    if not d.exists():
        log.warn(u"Failed to remove: {} not exists".format(d.name))
        return
        
    try:
        shutil.rmtree(d, ignore_errors=True)
        log.debug(u"Success removed: {}".format(d.name))
    except Exception as e:
        log.exception(e)

def execute(cmd, showlog=True):
    output = ''
    try:
        output = subprocess.check_output(cmd, shell=True, encoding='utf-8')
        if showlog: log.debug(u"Success execute: {}".format(cmd))
    except Exception as e:
        log.exception(e)
        
    return output
