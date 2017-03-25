import argparse
import codecs
import datetime
import hashlib
import logging
import os
import re
import sys
import tempfile

class BatchSigCheck:

    _SIGCHECK_EXE   = 'C:\\tools\\SysinternalsSuite\\sigcheck.exe'
    _SIGCHECK_ARGS  = '-nobanner -a -h -ct {0}'

    _MAX_SIZE = 50 * 1048576 # 50MiB

    _INSIST = [
        ur'\.dll$',
        ur'\.exe$',
        ur'\.sys$'
    ]

    _SKIP = [
        ur'^C:\\Windows\\System32\\',
        ur'^C:\\Windows\\Syswow64\\'
    ]

    def __init__(self, layout_ini, out_dir, root, now):

        self.layout_ini = layout_ini
        self.out_dir = os.path.abspath(out_dir)
        self.root = root
        self.now = now

        logging.info('Processing: %s' % self.layout_ini)
        logging.info('Output Dir: %s' % self.out_dir)
        logging.info('Max File Size: %i' % self._MAX_SIZE)

    def parse_layout(self):

        if self.root:
            _trunk = self.root
            logging.info('User provided root as: %s' % _trunk)
        else:
            _trunk  = os.path.abspath(os.path.join(self.layout_ini, os.pardir, os.pardir, os.pardir))
            logging.info('Calculated root as: %s' % _trunk)

        self.files = {}
        dupes = 0
        ignored = 0
        skipped = 0
        too_big = 0
        total = 0

        try:
            with codecs.open(self.layout_ini, 'r', encoding='utf-16-le') as f:
                for line in f:
                    total += 1
                    line = line.strip()
                    if not any(re.search(rx, line, flags=re.UNICODE|re.IGNORECASE) for rx in self._INSIST):
                        ignored += 1
                    else:
                        if any(re.search(rx, line, flags=re.UNICODE|re.IGNORECASE) for rx in self._SKIP):
                            skipped += 1
                        else:
                            local_path = translate_path(os.path.join(_trunk, os.sep.join(line.split('\\')[1:])))
                            if os.path.getsize(local_path) > self._MAX_SIZE:
                                logging.info('file too big: %s' % line)
                                too_big += 1
                                continue
                            try:
                                md5 = hashlib.md5(open(local_path, 'rb').read()).hexdigest().upper()
                                if md5 in self.files:
                                    self.files[md5]['paths'].append(line)
                                    dupes += 1
                                else:
                                    self.files[md5] = {}
                                    self.files[md5]['paths'] = [line]
                                    self.files[md5]['local_path'] = local_path
                            except IOError as e:
                                logger.error(e)

            logging.info('Total Lines: %i' % total)
            logging.info('Duplicates: %i' % dupes)
            logging.info('Ignored: %i' % ignored)
            logging.info('Skipped: %i' % skipped)
            logging.info('Too Big: %i' % too_big)
            logging.info('To Process: %i' % len(self.files))

            return len(self.files)

        except IOError as e:
            logger.error(e)
            sys.exit(1)

    def create_lnks(self):

        for file in self.files:
            logging.debug(file)

    def run(self):

        sigcheck_out = os.path.join(self.out_dir, '{}_BatchSigCheck.csv'.format(self.now))
        rta_out = os.path.join(self.out_dir, '{}_BatchSigCheck.txt'.format(self.now))
        logging.info('SigCheck Output to \'%s\'' % sigcheck_out)
        logging.info('Runtime Analysis to \'%s\'' % rta_out)

def translate_path(dir):

    if os.name == 'nt':
        return dir

    so_far = '/'
    parts = dir.split(os.sep)[1:]
    for part in parts:
        match = [s for s in os.listdir(so_far) if s.upper() == part.upper()][0]
        so_far = os.path.join(so_far, match)
    return so_far


if __name__ == '__main__':

    argp = argparse.ArgumentParser()
    argp.add_argument('layout_ini', help='Path of Layout.ini file to process.')
    argp.add_argument('out_dir', help='Directory into which to save the output.')
    argp.add_argument('--root', help='Insist root of volume is this folder, e.g. G:\\')
    args = argp.parse_args()

    now = datetime.datetime.now().strftime('%Y%m%d%H%M%S')

    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s', datefmt='[%Y-%m-%d %H:%M:%S]')
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(os.path.join(args.out_dir, '{}_BatchSigCheck.log'.format(now)))
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    batchsigcheck = BatchSigCheck(args.layout_ini, args.out_dir, args.root, now)
    if batchsigcheck.parse_layout() > 0:
        batchsigcheck.create_lnks()
        batchsigcheck.run()
