from zlib import crc32
from pathlib import Path

from collections import defaultdict
from hashlib import md5, sha1, sha256

from utils import log, execute
#from analysis.esrom import ESRomFile
from analysis_extractor.classifier import Classify

class AndroRomFile(object):

    def __init__(self, file, meta):
        self._file = Path(file)
        self._arch = ''
        self._bits = 0
        self._endian = ''
        self._machine = ''
        self._crypto = defaultdict(list)
        self.type = Classify(self.path)

        self.belongs = meta['romName']
        self.belongsMd5 = meta['romMd5']

        self.rom_path = "/".join([p.replace('.extracted', '') for p in self._file.relative_to(Path(meta['extracted'])).parts])

    def get_binary_info(self):
        if self.type not in ['elf', 'so']: return None

        output = execute('rabin2 -I "{}"'.format(self.path))
        for info in output.split('\n'):
            if not info.strip(): continue
            attr, value = info.strip().split()
            attr = attr.strip()
            value = value.strip()
            if attr == 'endian':
                self._endian = value
            elif attr == 'arch':
                self._arch = value
            elif attr == 'bits':
                self._bits = int(value)
            elif attr == 'machine':
                self._machine = value

    @property
    def endian(self):
        return self._endian

    @property
    def arch(self):
        return self._arch
    
    @property
    def machine(self):
        return self._machine

    @property
    def bits(self):
        return self._bits

    @property
    def md5(self):
        if self._crypto['md5']: return self._crypto['md5']
        self._crypto['md5'] = md5(self._file.read_bytes()).hexdigest()
        return self._crypto['md5']

    @property
    def sha256(self):
        if self._crypto['sha256']: return self._crypto['sha256']
        self._crypto['sha256'] = sha256(self._file.read_bytes()).hexdigest()
        return self._crypto['sha256']

    @property
    def sha1(self):
        if self._crypto['sha1']: return self._crypto['sha1']
        self._crypto['sha1'] = sha1(self._file.read_bytes()).hexdigest()
        return self._crypto['sha1']

    @property
    def crc32(self):
        if self._crypto['crc32']: return self._crypto['crc32']
        self._crypto['crc32'] = str(crc32(self._file.read_bytes()))
        return self._crypto['crc32']

    def get_strings(self):
        if self.type == 'text': return self._file.read_bytes().decode('utf-8')
        else: return execute('strings "{}"'.format(self.path))

    def get_files(self):
        output = execute('file "{}"'.format(self.path))
        return output.split(':', 1)[1].strip()

    def get_imports(self):
        if self.type not in ['elf', 'so']: return None

        imports = execute('rabin2 -i "{}"'.format(self.abspath))
        result = set()
        for line in imports.split('\n')[3:]:
            if not line: continue
            result.add(' '.join(line.split()[4:]))
        return result
    
    def get_exports(self):
        if self.type not in ['elf', 'so']: return None

        exports = execute('rabin2 -E "{}"'.format(self.abspath))
        result = set()
        for line in exports.split('\n')[4:]:
            if not line: continue
            result.add(' '.join(line.split()[6:]))
        return result
    
    def get_librarys(self):
        if self.type not in ['elf', 'so']: return None
        
        librarys = execute('rabin2 -l "{}"'.format(self.abspath))
        result = set()
        for line in librarys.split('\n')[1:-2]:
            if not line: continue
            result.add(line.strip())
        return result

    def fmt(self):
        return {
            'name': self.name,
            'arch': self.arch,
            'bits': self.bits,
            'size': self.size,
            'endian': self.endian,
            'machine': self.machine,
            'belongs': self.belongs,
            'belongsMd5': self.belongsMd5,
            'rompath': self.rom_path,
            'md5': self.md5,
            'sha1': self.sha1,
            'sha256': self.sha256,
            'crc32': self.crc32,
            'filecmd': self.get_files(),
            'imports': str(self.get_imports()),
            'exports': str(self.get_exports()),
            'librarys': str(self.get_librarys())
        }

    @property
    def stem(self): return self._file.stem
    
    @property
    def name(self): return self._file.name
    
    @property
    def suffix(self): return self._file.suffix

    @property
    def path(self): return self._file.as_posix()

    @property
    def abspath(self): return self._file.absolute().as_posix()

    @property
    def dir(self): return self._file.parents[0]

    @property
    def size(self): 
        try:
            return self._file.stat().st_size
        except:
            if self.is_symlink:
                log.warn("{} is symlink. maybe it point to a non-exist file.")
            return 0

    @property
    def is_symlink(self): return self._file.is_symlink()

    @property
    def exist(self): return self._file.exists()
