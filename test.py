
import sys
import os
sys.path.append("romanalyzer_extractor")
from extractor.rom import ROMExtractor

sys.path.append("romanalyzer_patch")
from analysis.TestEngine import TestEngine

#===============ROM Extractor===============

def rom_extractor(file_path,rom_brand=None):
    """
    :file_path:firmware path
    :rom_brand:firmware brands, special approaches to Huawei and ZTE
    :return:extracted files path
    """

    if rom_brand=='zte':
        import time
        path_zip=os.path.abspath(file_path)
        path1=path_zip[:path_zip.rfind('/')+1]
        path_extract=path1+'ZTE_Rom_'+str(time.time())+'.extracted'
        os.system('unzip -o '+path_zip+' -d '+path_extract)
    
        for root, dirs, files in os.walk(path_extract):
            for d in dirs:
                os.rename(os.path.join(root, d),os.path.join(root, 'ZTE_Rom_'+str(time.time())))
        
        extracted = ROMExtractor(path_extract).extract()

        if os.popen(f'find {path_extract} -name "system.img.extracted"').read()=='':
            path_img=os.popen(f'find {path_extract} -name "system.img"').read()

            path2=str(os.path.abspath(sys.argv[0]))
            work_path=path1[:path2.rfind('/')]
            os.system(work_path+'/romanalyzer_extractor/tools/extfstools/ext2rd '+str(path_img)[:-1]+' ./:'+str(path_img)[:-1]+'.extracted')

        print(path_extract)
        return(path_extract)

    elif rom_brand=='huawei':
        extracted = ROMExtractor(os.path.abspath(file_path)).extract()
        os.system('mkdir '+str(extracted)+'/tmp')

        path1=str(os.path.abspath(sys.argv[0]))
        work_path=path1[:path1.rfind('/')]
        
        os.system(work_path+'/romanalyzer_extractor/tools/huawei_erofs/lpunpack '+str(extracted)+'/UPDATE.APP.extracted/SUPER.img.ext4 '+str(extracted)+'/tmp')
        os.system(work_path+'/romanalyzer_extractor/tools/huawei_erofs/erofsUnpackKt_x64 '+str(extracted)+'/tmp/system.img '+str(extracted)+'/sys')
        
        print(str(extracted)+'/sys/')
        return (str(extracted)+'/sys/')
    else:        
        extracted = ROMExtractor(os.path.abspath(file_path)).extract()
        print(str(extracted)+'/')
        return (str(extracted)+'/')


#================Patch Analyzer================


def path_change(targetFirmware):
    path_input = os.popen(f'find {targetFirmware} -name "build.prop" -size +1k').read()
   
    if path_input=='':
        return None

    path_input = os.path.abspath(path_input)
    index0=path_input.find('\n')
    path_input=path_input[:index0]

    index1=path_input.rfind('/')
    str1=path_input[:index1]
    index2=str1.rfind('/')
    str2=str1[:index2]
    dir1=path_input[index2:index1][1:]

    if dir1 == 'system':
        return (str2+'/')
    else:
        os.rename(str1,str2+'/system')
        return (str2+'/')


def runVulnLogic(targetFirmware):
    firmware=path_change(targetFirmware)
    
    if firmware==None:
        print("detect error: can not find build.prop")
    else:
        print(firmware)
        engine = TestEngine(firmware)
        reports = engine.runAllVulnLogicTest()
        print(reports)

#================App Analyzer================

def runAppAnalyzer(targetDir, reportDir):
    for root, dirs, files in os.walk(targetDir):
        for file_str in files:
            if file_str.endswith('.apk'):
                path_str = os.path.join(root, file_str)
                report_path = reportDir + '/' + path_str.replace('/', '_')
                command_str = 'python ./static/androguard-3.3.6/main.py -i ' + path_str + ' -r ' + report_path
                os.system(command_str)

if __name__ == "__main__":
    
    rom_file='./rom/sailfish-nhg47l-factory-509076ee.zip'  ##replace with your firmware path
    rom_brand='brand'    ##replace with your rom's brand


    rom_path=os.path.abspath(rom_file)
    apk_report=str(rom_path)+'.apk_report/'
    
    extracted_path=rom_extractor(rom_path,rom_brand)
    runVulnLogic(extracted_path)
    runAppAnalyzer(extracted_path, apk_report)


