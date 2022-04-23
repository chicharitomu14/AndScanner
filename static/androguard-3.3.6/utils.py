#!/usr/bin/env python
#encoding: utf-8

import re
import sys
import csv
import logging
import linecache
import time

logger = logging.getLogger('main')

def print_exception():
    # Custom defined print exception function
    # It can display the filename, line number, line contents et al
    # when exception was captured.
    exe_type, exe_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    logger.exception('Exception in ({}, line {}, "{}"): {}'.format(filename, lineno, line.strip(), exe_obj))

def export_to_csv(str_list, save_name, csv_header, output_dir):
    # FIXME: What happended if the output_dir is empty?
    if not output_dir.exists():
        output_dir.mkdir(parents=True)
    save_path = output_dir / save_name
    try:
        # write string to a new file
        with save_path.open(mode='w') as f_csv:
            csv_writer = csv.writer(f_csv)
            csv_writer.writerow(csv_header)
            csv_writer.writerows(str_list)
    except:
        print_exception()
    logger.debug("Exported string into {}.".format(output_dir / save_name))

def export_to_txt(str_list, save_name, output_dir):
    # FIXME: What happended if the output_dir is empty?
    if not output_dir.exists():
        output_dir.mkdir(parents=True)
    save_path = output_dir / save_name
    try:
        with save_path.open(mode='w') as f_txt:
            for line in str_list:
                if not line:
                    continue
                line = str(line).strip()
                f_txt.write(line + '\n')
    except:
        print_exception()
    logger.debug("Exported string into {}.".format(output_dir / save_name))


