import logging
from pathlib import Path
from py2neo import Node

from manager.aws import AWSManager
from manager.mongo import MongoManager
from manager.neo4j import NeoGraphManager
from analysis_extractor.rom import AndroRomFile
from analysis_extractor.esrom import SaveRomFileToES

aws_manager = AWSManager()

rom_mongo_manager = MongoManager(database='newrom')

neo_graph = NeoGraphManager()

log = logging.getLogger('analysis_static')

def analyze_extracted(meta):
    log.info("Analyze extracted: {}".format(meta))

    for extracted_file in Path(meta['extracted']).rglob('*'):
        if extracted_file.is_dir(): 
            log.debug("Skip {}".format(extracted_file))
            continue
        if not extracted_file.exists(): 
            log.warn("Not exists: {}".format(extracted_file))
            continue

        log.info(u"Start analysis: {}".format(extracted_file.name))

        try:
            android_rom_file = AndroRomFile(extracted_file, meta)
            analyze_extracted_file(android_rom_file)            
        except:
            log.exception(u"Exception happened: {}".format(extracted_file))

    log.info("Success analysis: {}".format(meta['romName']))

def analyze_extracted_file(androRomFile):

    '''
    SaveRomFileToES(androRomFile)
    log.info("\t=> uploaded {} to es".format(androRomFile.name))
    '''

    rom_mongo_manager.insert(androRomFile.fmt())
    log.info(u"Upload MongoDB: {}".format(androRomFile.name))
    
    aws_manager.upload(androRomFile.abspath, androRomFile.md5)
    log.info(u"Upload AWS: {}".format(androRomFile.name))

    '''
    if androRomFile.type not in ('elf', 'so'): return

    depends_analysis(androRomFile)
    log.info("\t=> uploaded {} to neo4j".format(androRomFile.name)) 
    '''

def depends_analysis(androfile):
    andronode = neo_graph.to_node(androfile)

    for depends_library in androfile.get_librarys():
        depends_library_anchor = neo_graph.match_node('anchor', name=depends_library)
        if not depends_library_anchor: 
            depends_library_anchor = Node('anchor', name=depends_library)
            neo_graph.create(depends_library_anchor)
        
        neo_graph.add_relaship(andronode, 'depend', depends_library_anchor)
    
    log.debug("\t=> added depends node to neo4j")
