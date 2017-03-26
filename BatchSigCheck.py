import argparse
import codecs
import csv
import datetime
import hashlib
import logging
import os
import re
import shutil
import StringIO
import subprocess
import sys
import tempfile
import win32file

class BatchSigCheck:

	_SIGCHECK_EXE	= 'C:\\tools\\SysinternalsSuite\\sigcheck.exe'
	_SIGCHECK_ARGS	= '-nobanner -a -ct -e -h {0}'
	_SIGCHECK_CMD	= '{} {}'

	_MAX_SIZE = 50 * 1048576 # 50MiB
	_LOW_LOADS = 1 # Highlight folders with only this many or fewer files loaded

	_INSIST = [
		ur'\.dll$',
		ur'\.exe$',
		ur'\.sys$'
	]

	_SKIP = [
		ur'^C:\\Windows\\System32\\',
		ur'^C:\\Windows\\Syswow64\\'
	]

	_SUSPICIOUS = [
		'\\ProgramData\\',
		'\\Recycler\\',
		'\\Temp',
		'\\Users\\'
	]

	def __init__(self, layout_ini, out_dir, root, now):

		self.layout_ini = os.path.abspath(layout_ini)
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
		error = 0
		total = 0

		try:
			logger.info('Building hash table...')
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
							try:
								if os.path.getsize(local_path) > self._MAX_SIZE:
									logging.info('file too big: %s' % line)
									too_big += 1
									continue
								md5 = hashlib.md5(open(local_path, 'rb').read()).hexdigest().upper()
							except Exception as e:
								error += 1
								logger.error(e)
								continue
							if md5 in self.files:
								self.files[md5]['paths'].append(line)
								dupes += 1
							else:
								self.files[md5] = {}
								self.files[md5]['paths'] = [line]
								self.files[md5]['local_path'] = local_path
			logger.info('Done.')

			logging.info('Total Lines: %i' % total)
			logging.info('Duplicates: %i' % dupes)
			logging.info('Ignored: %i' % ignored)
			logging.info('Skipped: %i' % skipped)
			logging.info('Too Big: %i' % too_big)
			logging.info('Errored: %i' % error)
			logging.info('To Process: %i' % len(self.files))

		except IOError as e:
			logger.error(e)
			sys.exit(1)

	def create_lnks(self):

		if len(self.files) < 1:
			return

		self.lnk_dir = tempfile.mkdtemp()
		logger.info('Created temporary folder: %s' % self.lnk_dir)

		logger.info('Creating LNKs...')
		for file in self.files:
			lnk = win32file.CreateSymbolicLink(
				os.path.join(self.lnk_dir, '{}.lnk'.format(file)),
				self.files[file]['local_path']
			)
		logger.info('Done; created %i LNKs.' % len(os.listdir(self.lnk_dir)))

	def run(self):

		if not hasattr(self, 'lnk_dir'):
			return

		if len(os.listdir(self.lnk_dir)) > 0:
			sigcheck_out = os.path.join(self.out_dir, '{}_BatchSigCheck.csv'.format(self.now))
			rta_out = os.path.join(self.out_dir, '{}_BatchSigCheck.txt'.format(self.now))
			logging.info('SigCheck Output to \'%s\'' % sigcheck_out)
			logging.info('Runtime Analysis to \'%s\'' % rta_out)

			cmd = self._SIGCHECK_CMD.format(
				self._SIGCHECK_EXE,
				self._SIGCHECK_ARGS.format(self.lnk_dir)
			)
			logger.info('Running command: %s' % cmd)
			# I know there's a security risk with shell=True, but
			# even with shlex I couldn't get it to work.
			# Also,
			# sigcheck seems to return non-zero (1) even on success???
			try:
				subprocess.check_output(cmd, shell=True)
			except subprocess.CalledProcessError, e:
				self.result = e.output

			logging.info('Removing temporary folder.')
			shutil.rmtree(self.lnk_dir)

			result = []
			csv_reader = csv.reader(StringIO.StringIO(self.result), delimiter='\t')
			for row in csv_reader:
				if row[0].endswith('.lnk'):
					row[0] = self.files[row[16]]['paths'][0] # 16 = md5
					result.append(row)
				else:
					result.append(row)

			logger.info('Writing SigCheck output... ')
			with open(sigcheck_out, 'wb') as csv_out:
				csv_writer = csv.writer(csv_out, delimiter='\t')
				csv_writer.writerows(result)
			logger.info('Done, wrote header + {:,} lines.'.format(len(result) - 1))

			# Check for non-binaries that were ignored
			# Gather folder heuristics
			# Check against suspicious strings
			logger.info('Analysing output...')

			processed_md5s = [row[16] for row in result]
			non_binaries_md5 = set(self.files) - set(processed_md5s)
			non_binaries = [self.files[md5]['paths'][0] for md5 in non_binaries_md5]
			processed_md5s = non_binaries_md5 = None
			logger.info('%i files were skipped by SigCheck.' % len(non_binaries))

			folders = {}
			suspicious = []
			for i, row in enumerate(result):
				if i==0: continue # Skip header
				if os.path.dirname(row[0]) in folders:
					folders[os.path.dirname(row[0])] += 1
				else:
					folders[os.path.dirname(row[0])] = 1
				if any(s.upper() in row[0].upper() for s in self._SUSPICIOUS):
					suspicious.append(row[0])

			logger.info('Writing RTA output...')
			with open(rta_out, 'wb') as rta:

				rta.write('Non-Binaries:\n')
				rta.write('=============\n')
				if len(non_binaries) < 1:
					rta.write('None\n')
				else:
					[rta.write('{}\n'.format(non_binary)) for non_binary in non_binaries]
				rta.write('\n')

				rta.write('Folder Heuristics:\n')
				rta.write('==================\n')
				got_heuristics = False
				for folder in folders:
					if folders[folder] <= self._LOW_LOADS:
						got_heuristics = True
						rta.write('{:,}\t{}\n'.format(folders[folder], folder))
				if not got_heuristics:
					rta.write('None\n')
				rta.write('\n')

				rta.write('Suspicious:\n')
				rta.write('===========\n')
				if len(suspicious) < 1:
					rta.write('None\n')
				else:
					for suspect in suspicious:
						rta.write('{}\n'.format(suspect))

			logging.info('Done.')

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

	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s', datefmt='[%Y-%m-%d %H:%M:%S]')
	logger = logging.getLogger()
	logger.setLevel(logging.INFO)
	stream_handler = logging.StreamHandler()
	stream_handler.setFormatter(formatter)
	file_handler = logging.FileHandler(os.path.join(args.out_dir, '{}_BatchSigCheck.log'.format(now)))
	file_handler.setFormatter(formatter)
	logger.addHandler(file_handler)
	logger.addHandler(stream_handler)

	batchsigcheck = BatchSigCheck(args.layout_ini, args.out_dir, args.root, now)
	batchsigcheck.parse_layout()
	batchsigcheck.create_lnks()
	batchsigcheck.run()
