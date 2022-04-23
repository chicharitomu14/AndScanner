#!/usr/bin/env python
#encoding: utf-8
import os
import sys
import logging
import datetime
from pathlib import Path
from optparse import OptionParser

from androguard.core import androconf
from androguard.core.bytecodes import apk

#from utils import print_exception
from static import StaticAnalyzer

__version__ = '0.1'

# Initialize logger
logging.basicConfig(level=logging.DEBUG,
    format='%(asctime)s %(filename)s [line:%(lineno)d]  \t%(levelname)s %(message)s',
    datefmt='%a, %d %b %Y %H:%M:%S',
    filename=os.path.split(os.path.realpath(__file__))[0]+'/analysis.log',
    filemode='w')
logger = logging.getLogger('main')
logger.addHandler(logging.StreamHandler(sys.stdout))

def get_analysis_queue(options):
    analysis_queue = []
    if options.input:
        analysis_queue.append(options.input)

    if options.folder:
        for child in options.folder.iterdir():
            if child.is_dir():  
                # androconf can not accept directory as argument
                continue
            # HACK: is there need to filter apk by its extension?
            elif androconf.is_android(child.as_posix()) != 'APK':
                # child is not a valid apk file
                continue
            print ("Android Type: APK")
            analysis_queue.append(child)
    return analysis_queue

def main(options, args):
    static_analyzer = StaticAnalyzer(options.report)
    queue = get_analysis_queue(options)
    for child in queue:
        try:
            a = static_analyzer.load_apk(child)
            if not a:
                continue

            static_analyzer.start()
        except Exception as e:
            logger.exception(str(e))
            #print_exception()

def func(input,report):
    
    log_input = Path(input)
    logger.debug("The provided APK file is: %s" % log_input.absolute())

    report = Path(report)
    if not report.exists():
        try:
            report.mkdir(parents=True)
        except Exception as e:
            print (str(e))
    logger.debug("The specified report output folder is: %s" % report.absolute())

    static_analyzer = StaticAnalyzer(report)
    queue = [input]
    for child in queue:
        try:
            a = static_analyzer.load_apk(child)
            if not a:
                continue

            static_analyzer.start()
        except Exception as e:
            logger.exception(str(e))
            #print_exception()


if __name__ == "__main__":
    usage = "Usage: %prog (-i example.apk | -f /folder/) [-t time] [-r report_folder] \n\t[-a avd_name] [-s screenshot_folder] [-v]"
    parser = OptionParser(usage)
    parser.add_option("-f", '--folder', dest='folder', help='the folder containing dozens of APK files to be analyzed', action='store', type='string')
    parser.add_option("-i", '--input', dest='input', help='path of the APK file to be analyzed', action='store', type='string')
    parser.add_option("-t", '--timeout', dest='timeout', help='maximum analysis time limit in minutes', action='store', type='int')
    parser.add_option("-r", '--report', dest='report', help='folder where store the outputed report', action='store', type='string')
    parser.add_option("-a", '--avd', dest='avd', help='the chosen android virtual device(AVD) name', action='store', type='string')
    parser.add_option("-s", '--screenshot', dest='screenshot', help='path where store the outputed screenshot', action='store', type='string')
    parser.add_option("-v", '--version', dest='version', help='', action='store_true', default=False)
    
    (options, _) = parser.parse_args()

    if options.version:
        # only show version
        logger.info("Static Analyzer: " + __version__)
        logger.info("Android Guard: " + androconf.ANDROGUARD_VERSION)
        sys.exit(0)

    if options.input:
        # single apk analysis first
        options.input = Path(options.input)
        logger.debug("The provided APK file is: %s" % options.input.absolute())
    elif options.folder:  
        # multiple apks analysis second
        options.folder = Path(options.folder)
        if not options.folder.is_dir():
            logger.error("Please specify the folder option as a folder path")
            sys.exit(-1)
        logger.debug("The provided APK folder is: %s" % options.folder.absolute())
    else:
        # User must provide option "-i" or "-f"
        parser.print_help()
        sys.exit(-1)

    if options.report:  
        options.report = Path(options.report)
#        print options.report
        if not options.report.exists():
            try:
                options.report.mkdir(parents=True)
            except Exception as e:
                print (str(e))
        logger.debug("The specified report output folder is: %s" % options.report.absolute())
    else:
        options.report = Path('report/')
        if not options.report.exists():
            options.report.mkdir(parents=True)

    if options.screenshot:  
        options.screenshot = Path(options.screenshot)
        if not options.screenshot.exists():
            options.screenshot.mkdir(parents=True)
        logger.debug("The specified screenshot output path is: %s" % options.screenshot.absolute())

    # TODO: There still need to deal with the CLI args
    main(options, _)
