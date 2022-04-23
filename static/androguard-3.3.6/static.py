#!/usr/bin/env python
#encoding: utf-8
import os
import sys
import time
import logging
import traceback
import shutil
import zipfile
import hashlib

from pathlib import Path

from androguard.core import bytecode
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis

from utils import export_to_csv, export_to_txt

abs_path = os.path.abspath(os.path.dirname(__file__))
resource_path=os.path.join(abs_path,"resource")
print(resource_path)
logger = logging.getLogger('main')

TYPE_DESCRIPTOR = {
    'V': 'void',
    'Z': 'boolean',
    'B': 'byte',
    'S': 'short',
    'C': 'char',
    'I': 'int',
    'J': 'long',
    'F': 'float',
    'D': 'double',
}

def get_type(atype, size=None):
    """
    Retrieve the type of a descriptor (e.g : I)
    """
    if atype.startswith('java.lang'):
        atype = atype.replace('java.lang.', '')
    res = TYPE_DESCRIPTOR.get(atype.lstrip('java.lang'))
    if res is None:
        if atype[0] == 'L':
            res = atype[1:-1].replace('/', '.')
        elif atype[0] == '[':
            if size is None:
                res = '%s[]' % get_type(atype[1:])
            else:
                res = '%s[%s]' % (get_type(atype[1:]), size)
        else:
            res = atype
    return res

class StaticAnalyzer(object):

    def __init__(self, report_folder=Path('report')):
        self.report_folder = report_folder
    
    def load_apk(self, apk_path):
        # In the older version: zipmodule: specify the type of 
        # zip module to use (0:chilkat, 1:zipfile, 2:patch zipfile)
        # FIXME: In the latest version of androguard
        #        there are already no zipmodule options.
        #        Would it cause some unexpectable fault? 
        # a = apk.APK(child.as_posix(), zipmodule=2)
        a = apk.APK(apk_path.as_posix())
        
        if not a.is_valid_APK():
            # It means the APK has a valid signature 
            # or the APK cannot be installed on an Android system.
            logger.error("APK %s is invalid!" % apk_path)
            return None

        self.target = a
        self.target_path = apk_path
        # parse classes.dex of the target apk
#        self.dex = self.target.get_dex()
        self.dex = self.target.get_all_dex()
        self.vm = []
        if self.dex == '':
            print ('no dex')
        else:
            for tmp_dex in self.dex:
                tmp_vm = dvm.DalvikVMFormat(tmp_dex)
                self.vm.append(tmp_vm)

        self.max_sdk_version = self.target.get_max_sdk_version()
        self.min_sdk_version = self.target.get_min_sdk_version()
        self.target_sdk_version = self.target.get_target_sdk_version()
        self.effective_target_sdk_version = self.target.get_effective_target_sdk_version()

        self.apk_report = self.report_folder

#        os.system('apktool d ' + self.target_path.as_posix() + ' -o ' + self.apk_report.as_posix() + '/apktool_tmp')
#        print self.target_path.stem
        if not self.apk_report.exists():
            self.apk_report.mkdir(parents=True)
        return a

    def start(self):
        logger.info("Analysis target: %s" % self.target_path)
        if self.dex == '':
            self.export_sign()
            self.export_sdk_version()
            self.export_basic_info()
            self.export_hash()
            self.export_exported_components()
            self.export_app_configs()
        else:
            self.export_report()

    def export_sign(self):
        from androguard.util import get_certificate_name_string
        
#        import hashlib
        import binascii
        import traceback
#        from asn1crypto import x509, keys
        from asn1crypto import x509
        from oscrypto import asymmetric

        txt_write_line = []
        # keep the list of hash functions in sync with cli/entry_points.py:sign
        hashfunctions = dict(md5=hashlib.md5,
                            sha1=hashlib.sha1,
                            sha256=hashlib.sha256,
                            sha512=hashlib.sha512,
                            )
        try:
            a = self.target
#            txt_write_line.append("{}, package: '{}'".format(self.target_path, a.get_package()))
#            txt_write_line.append("is signed v1: {}".format(a.is_signed_v1()))
#            txt_write_line.append("is signed v2: {}".format(a.is_signed_v2()))
#            txt_write_line.append("is signed v3: {}".format(a.is_signed_v3()))
#            tmp_sv = "is signed v1: {}".format(a.is_signed_v1()) + '\n' + "is signed v2: {}".format(a.is_signed_v2()) + '\n' + "is signed v3: {}".format(a.is_signed_v3())
#            txt_write_line.append(tmp_sv)
            
            certs = set(a.get_certificates_der_v3() + a.get_certificates_der_v2() + [a.get_certificate_der(x) for x in a.get_signature_names()])
            pkeys = set(a.get_public_keys_der_v3() + a.get_public_keys_der_v2())
            if len(certs) > 0:
                txt_write_line.append("found {} unique public keys associated with the certs".format(len(pkeys)))

            tmp_sv = "is signed v1: {}".format(a.is_signed_v1()) + '\n' + "is signed v2: {}".format(a.is_signed_v2()) + '\n' + "is signed v3: {}".format(a.is_signed_v3())
            txt_write_line.append(tmp_sv)
           
            for cert in certs:
                x509_cert = x509.Certificate.load(cert)
#                txt_write_line.append("## issuer:")
                tmp_issuer = "issuer: "
                issuer = get_certificate_name_string(x509_cert.issuer).split(',')
                for item in issuer:
#                    txt_write_line.append(item.strip())
                    tmp_issuer += item.strip() + ';'
                txt_write_line.append(tmp_issuer)

#                txt_write_line.append("## subject:")
                tmp_subject = "subject: "
                subject = get_certificate_name_string(x509_cert.subject).split(',')
                for item in subject:
#                    txt_write_line.append(item.strip())
                    tmp_subject += item.strip() + ';'
                txt_write_line.append(tmp_subject)
                    
                txt_write_line.append("serial number: %s" % hex(x509_cert.serial_number).replace('0x', '').replace('l', ''))
                txt_write_line.append("hash algorithm: %s" % x509_cert.hash_algo.upper())
                txt_write_line.append("signature algorithm: %s" % x509_cert.signature_algo)
                txt_write_line.append("valid from: %s" % x509_cert['tbs_certificate']['validity']['not_before'].native)
                txt_write_line.append("valid to: %s" % x509_cert['tbs_certificate']['validity']['not_after'].native)

                for k, v in hashfunctions.items():
                    txt_write_line.append("{}: {}".format(k.upper(), v(cert).hexdigest()))

            for public_key in pkeys:
#                x509_public_key = keys.publickeyinfo.load(public_key)
                x509_public_key = asymmetric.load_public_key(public_key)
                txt_write_line.append("publickey algorithm: %s" % x509_public_key.algorithm)
                txt_write_line.append("bit size: %s" % x509_public_key.bit_size)
                txt_write_line.append("fingerprint: %s" % binascii.hexlify(x509_public_key.fingerprint))
#                try:
#                    txt_write_line.append("hash algorithm: %s" % x509_public_key.hash_algo)
#                except valueerror as ve:
#                    # rsa pkey does not have an hash algorithm
#                    pass
            
#            export_to_sign(txt_write_line, self.target_path.stem + '_sign.txt', self.apk_report)
            export_to_txt(txt_write_line, 'sign.txt', self.apk_report)
        except:
            traceback.print_exc(file=sys.stderr)

    def export_sdk_version(self):
        txt_write_line = []
        tmp_min_sdk = str(self.min_sdk_version)
        tmp_max_sdk = str(self.max_sdk_version)
        tmp_target_sdk = str(self.target_sdk_version)
        tmp_effective_sdk = str(self.effective_target_sdk_version)

        tmp_sdk_path = resource_path+'/android_sdk_level.txt'
        tmp_sdk_list = []
        with open(tmp_sdk_path) as tsp:
            for line in tsp:
                tmp_sdk_list.append(line.replace('\n', ''))
        for tmp_sdk_str in tmp_sdk_list:
            if tmp_min_sdk == tmp_sdk_str.split('(')[0]:
                tmp_min_sdk = tmp_sdk_str
            if tmp_max_sdk == tmp_sdk_str.split('(')[0]:
                tmp_max_sdk = tmp_sdk_str
            if tmp_target_sdk == tmp_sdk_str.split('(')[0]:
                tmp_target_sdk = tmp_sdk_str
            if tmp_effective_sdk == tmp_sdk_str.split('(')[0]:
                tmp_effective_sdk = tmp_sdk_str

        txt_write_line.append('min_sdk_version: ' + tmp_min_sdk)
        txt_write_line.append('max_sdk_version: ' + tmp_max_sdk)
        txt_write_line.append('target_sdk_version: ' + tmp_target_sdk)
        txt_write_line.append('effective_target_sdk_version: ' + tmp_effective_sdk)

#        txt_write_line.append('min_sdk_version: ' + str(self.min_sdk_version))
#        txt_write_line.append('max_sdk_version: ' + str(self.max_sdk_version))
#        txt_write_line.append('target_sdk_version: ' + str(self.target_sdk_version))
#        txt_write_line.append('effective_target_sdk_version: ' + str(self.effective_target_sdk_version))
#        export_to_sdk(txt_write_line, self.target_path.stem + '_sdk_version.txt', self.apk_report)
        export_to_txt(txt_write_line, 'sdk_version.txt', self.apk_report)

    def get_exported_components(self, mode='all'):
        _ = self.target
    
        if mode != 'all' and mode != 'activity':
            # invalid mode
            return 

        ns = '{http://schemas.android.com/apk/res/android}'
        axml = _.get_android_manifest_axml().get_xml_obj()
        components = axml.xpath('//activity') + axml.xpath('activity-alias') + axml.xpath('//service') \
                + axml.xpath('//receiver') + axml.xpath('//provider') if mode =='all' \
                else axml.xpath('//activity') + axml.xpath('activity-alias')
        

        components_in_mode = []
        activities = _.get_activities()
        services = _.get_services() if mode == 'all' else []
        receivers = _.get_receivers() if mode == 'all' else []
        providers = _.get_providers() if mode == 'all' else []

        exported_components = {} if mode == 'all' else []
        comp_type = '' if mode == 'all' else 'activity'
        for comp in components:
            comp_is_exported = comp.get(ns+'exported')
            comp_permission = comp.get(ns+'permission')
            if not comp_is_exported or comp_is_exported.lower()  != 'true':
                continue
            comp_name = comp.get(ns+'name')
           
            tmp_package_name = _.get_package()
            if comp_name in activities or comp_name in services or comp_name in receivers or comp_name in providers:
                full_comp_name = comp_name
            else:
                full_comp_name = tmp_package_name + '.' + comp_name

            if mode == 'all':
                if full_comp_name in activities:
                    comp_type = 'activity'
                elif full_comp_name in services:
                    comp_type = 'service'
                elif full_comp_name in receivers:
                    comp_type = 'receiver'
                elif full_comp_name in providers:
                    comp_type = 'provider'
                else:
                    comp_type = 'unknown'

                if '..' in full_comp_name:
                    full_comp_name = full_comp_name.replace('..', '.')

                if comp_permission != None:
                    full_comp_name = full_comp_name + ': ' + comp_permission

                if comp_type not in exported_components:
                    exported_components[comp_type] = []
                if full_comp_name not in exported_components[comp_type]:
                    exported_components[comp_type].append(full_comp_name)
            elif mode == 'activity':
                if '..' in full_comp_name:
                    full_comp_name = full_comp_name.replace('..', '.')

                if comp_permission != None:
                    full_comp_name = full_comp_name + ': ' + comp_permission
                if full_comp_name not in exported_components:
                    exported_components.append(full_comp_name)
        
        return exported_components

    def export_exported_components(self):
        comps = self.get_exported_components('all')
        import json
        output = self.apk_report / 'exported_components.json'
        with output.open('w', encoding='utf-8') as fp:
            fp.write(json.dumps(comps, indent=2, ensure_ascii=False))
    
    def export_basic_info(self):
        txt_write_line = []
        err_write_line = []
        try:
            txt_write_line.append("package name: {}".format(self.target.get_package()))
            if self.target.get_package() == None:
                err_write_line.append('this app has no package name')
        except Exception as e:
            print ('package name error')
            print (e)
        try:
            txt_write_line.append("internal version: {}".format(self.target.get_androidversion_code()))
        except Exception as e:
            print ('internal version error')
            print (e)

        try:
            txt_write_line.append("displayed version: {}".format(self.target.get_androidversion_name()))
        except Exception as e:
            print ('displayed version error')
            print (e)

        try:
            txt_write_line.append("apk file: {}".format(self.target.get_filename().split('/')[-1]))
        except Exception as e:
            print ('apk file error')
            print (e)

        try:
            txt_write_line.append("app name: {}".format(self.target.get_app_name()))
            if self.target.get_app_name() == None:
                err_write_line.append('this app has no app name')
        except Exception as e:
            print ('app name error')
            print (e)

#        txt_write_line.append("app icon: {}".format(self.target.get_app_icon()))       
        tmp_icon_str = self.target.get_app_icon()
        txt_write_line.append("app icon: {}".format(tmp_icon_str))

        export_to_txt(txt_write_line, 'basic_info.txt', self.apk_report)
        export_to_txt(err_write_line, 'abnormal_info.txt', self.apk_report)

    def export_hash(self):
        import zlib 
#        import hashlib
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = hashlib.sha256()
        txt_write_line = []
        
        with self.target_path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
                hash_sha1.update(chunk)
                hash_sha256.update(chunk)

        prev = 0
        crc32_res = ""
        with self.target_path.open("rb") as f: 
            for item in f:
                prev = zlib.crc32(item, prev)
            crc32_res = "crc32: %x" % (prev & 0xffffffff)
        
        txt_write_line.append("md5: " + hash_md5.hexdigest())
        txt_write_line.append("sha-1: " + hash_sha1.hexdigest())
        txt_write_line.append("sha-256: " + hash_sha256.hexdigest())
        txt_write_line.append(crc32_res)

#        import os
        size_in_bytes = os.path.getsize(self.target_path.as_posix())
        txt_write_line.append('apk size: ' + str(round(size_in_bytes/(1024*1024.0), 2)) + 'mb (%d bytes)' % size_in_bytes)
        
#        export_to_apkhash(txt_write_line, self.target_path.stem + '_apk_hash.txt', self.apk_report)
        export_to_txt(txt_write_line, 'apk_hash.txt', self.apk_report)

    def export_app_configs(self):
        configs_list = []
        ns = '{http://schemas.android.com/apk/res/android}'
        axml = self.target.get_android_manifest_axml().get_xml_obj()
        mani_configs = axml.xpath('//manifest')
        app_configs = axml.xpath('//application')
        
        app_uid = ''

        for mani_config in mani_configs:
            app_uid = mani_config.get(ns+'shareduserid')
            if app_uid != None:
                app_uid = 'shareduserid: ' + app_uid
#                configs_list.append(app_uid)
       
        for app_config in app_configs:
            app_backup = app_config.get(ns+'allowbackup')
            app_nw_sec = app_config.get(ns+'networksecurityconfig')
            app_debug = app_config.get(ns+'debuggable')
            app_store = app_config.get(ns+'requestlegacyexternalstorage')
           
            if app_backup != None:
                app_backup = 'allowbackup: ' + app_backup
                configs_list.append(app_backup)
            if app_backup == None:
                app_backup = 'allowbackup: true'
                configs_list.append(app_backup)
               
            if app_nw_sec != None: 
                app_nw_sec = 'networksecurityconfig: ' + app_nw_sec
                configs_list.append(app_nw_sec)
            if app_nw_sec == None: 
                app_nw_sec = 'networksecurityconfig: none'
                configs_list.append(app_nw_sec)

            if app_debug != None:
                app_debug = 'debuggable: ' + app_debug
                configs_list.append(app_debug)
            if app_debug == None:
                app_debug = 'debuggable: false'
                configs_list.append(app_debug)

            if app_store != None:
                app_store = 'requestlegacyexternalstorage: ' + app_store
                configs_list.append(app_store)
            if app_store == None:
                app_store = 'requestlegacyexternalstorage: none'
                configs_list.append(app_store)

            if app_uid == None or app_uid == '':
#                print 'in app_config'
                app_uid = app_config.get(ns+'shareduserid')
                if app_uid != None:
                    app_uid = 'shareduserid: ' + app_uid
#                    configs_list.append(app_uid)
                if app_uid == None:
                    app_uid = 'shareduserid: none'
            configs_list.append(app_uid)

        export_to_txt(configs_list, 'apk_configs.txt', self.apk_report)


    def export_report(self):
        self.export_sign()
        self.export_sdk_version()
        self.export_basic_info()
        self.export_hash()
        self.export_exported_components()
        self.export_app_configs()
        

