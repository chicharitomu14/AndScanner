from datetime import datetime
from elasticsearch_dsl.connections import connections
from elasticsearch_dsl import Document, Date, Integer, Text, Keyword

from utils import readcfg
from settings import ES_ANDROID_ROM_INDEX

ip_addr = readcfg('configs/elastic.cfg', 'ElasticSearch', 'IP')
connections.create_connection(hosts=[ip_addr])

class ESRomFile(Document):
    
    # basic
    name = Text()
    type = Keyword()
    path = Text()

    # hash
    md5 = Keyword()
    sha1 = Keyword()
    sha256 = Keyword()

    depends = Text()
    imports = Text()
    exports = Text()

    # strings = Text()
    pubdate = Date()

    class Index:
        name = ES_ANDROID_ROM_INDEX

def SaveRomFileToES(androfile):
    es_rom = ESRomFile(
            meta = {'id': androfile.md5},
            name = androfile.name,
            type = androfile.type,
            path = androfile.rom_path,
            belongs = androfile.belongs,
            belongsMd5 = androfile.belongsMd5,
            md5 = androfile.md5,
            sha1 = androfile.sha1,
            sha256 = androfile.sha256,
            librarys = str(androfile.get_librarys()),
            imports = str(androfile.get_imports()),
            exports = str(androfile.get_exports())
            # strings = androfile.get_strings()
        )

    es_rom.pubdate = datetime.now()
    es_rom.save()

def ESInitMap():
    ESRomFile.init()