#!/usr/bin/env python

'''
Version 0.3 2012.02.01
Copyright (c) 2009, Taoufik El Aoumari (v0.2)
Copyright (c) 2012, OmegaPhil (v0.3-)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

# TODO: GPL3+?

import codecs
import io
import os
import re
import shutil
import sys
import zlib
from optparse import OptionParser

# Defining terminal escape codes
c_null = "\x1b[00;00m"
c_red = "\x1b[31;01m"
c_green = "\x1b[32;01m"
p_reset = "\x08" * 8

# Variable declaration
addHashModeFiles = []


def CRC32Checksum(filename):

    # Variable allocation
    crc = 0
    done = 0

    # Opening file to hash, buffer is large presumably to ensure its read in
    # fast
    fileToHash = open(filename, "rb")
    buff_size = 65536
    size = os.path.getsize(filename)

    try:
        while True:

            # Reading in a chunk of the data and updating the terminal
            data = fileToHash.read(buff_size)
            done += buff_size

            # Print digit in 7 character field with right justification
            sys.stdout.write("%7d" % (done * 100 / size) + "%" + p_reset)

            # Iteratively hashing the data
            if not data:
                break
            crc = zlib.crc32(data, crc)

    # Catching Cntrl+C and exiting
    except KeyboardInterrupt:
        sys.stdout.write(p_reset)
        fileToHash.close()
        sys.exit(1)

    # Clearing up terminal and file
    sys.stdout.write(p_reset)
    fileToHash.close()

    # If the crc hex value is negative, bitwise and it with the maximum 32bit
    # value. Apparently this is a 'bit mask' resulting in a 32bit long value
    # (rather than an infinitely long value, see
    # http://stackoverflow.com/a/7825412). It is also guaranteed to return a
    # positive number
    if crc < 0:
        crc &= 2 ** 32 - 1

    # Return 8-digit precision decimal hex integer in uppercase
    return "%.8X" % (crc)


def DisplayResults(fileToHash, crc, checksumFileCRC=None):

    # Splitting based on whether a checksum file is being processed or not
    if checksumFileCRC == None:
        try:

            # Obtaining the hash from the filename (penultimate fragment) -
            # remember that re does not support POSIX character classes
            dest_sum = re.split('([a-f0-9]{8})', fileToHash, \
                                flags=re.IGNORECASE)[-2]

            # Setting colours depending on good/bad hash
            if crc == dest_sum.upper():
                c_in = c_green
            else:
                c_in = c_red

            # Obtaining a list of the filename before and after the hash
            sfile = fileToHash.split(dest_sum)

            # Printing results with coloured hash at the beginning and in
            # the file path
            print("%s%s%s   %s%s%s%s%s" % (c_in, crc, c_null, sfile[0], \
                                           c_in, dest_sum, c_null, \
                                           sfile[1]))

        except(IndexError, ValueError):

            # No CRC32 has been found - outputting calculated value and file
            # path
            print("%s   %s" % (crc, fileToHash))

            # If hashes are to be added to filenames, adding to the list
            if options.addHashMode != 'none':
                hashedFile = [fileToHash, crc]
                addHashModeFiles.append(hashedFile)
    else:

        # crc is from checksum file - setting colours depending on good/bad
        # hash
        if crc == checksumFileCRC.upper():
            c_in = c_green
        else:
            c_in = c_red

        # Printing results with coloured hash at the beginning and in the
        # file path
        print("%s%s%s   %s" % (c_in, crc, c_null, fileToHash))


def OpenFile(fileToOpen):

    # Custom function has been created as Python, even though it is 'unicode
    # capable', cannot cope with Just Reading a UTF-16 file (so far)

    # Reading whole file in at once - done like this to work around
    # encoding issues (binary to prevent any attempt at interpretation
    # which would just lead to corruption)
    fileData = open(fileToOpen, 'rb').read()

    # Detecting utf16 encoding and decoding to sane data. Appears
    # to also thankfully kill off the BOM. The following StringIO wants
    # unicode so everything else is encoded accordingly
    if fileData.startswith(codecs.BOM_UTF16):
        fileData = fileData.decode('utf16')
    else:
        fileData = unicode(fileData)

    # You apparently cant just split the resulting string into newlines and
    # then iterate over them, so returning a file-like object
    # io's StringIO translates newlines, raw StringIO doesnt - however even
    # though io's 'universal newlines' translation is supposed to be default
    # on (None), it isnt unless you explicitly pass None!!
    return io.StringIO(fileData, None)


def CRC32HashMode(files):

    # Looping for all passed files - these are left over in args after the
    # options have been processed
    for fileToHash in files:
        try:

            # Hashing file
            crc = CRC32Checksum(fileToHash)

            # Displaying results
            DisplayResults(fileToHash, crc)

        except(IOError) as e:
            sys.stderr.write('\n' + str(e) + '\n')
            continue

    # If files without hashes exist and the add hash mode is 'ask', proceeding
    # only if the user wants to
    if len(addHashModeFiles) > 0 and options.addHashMode == 'ask' and \
    raw_input('\nDo you want to add CRC32 hashes to the filenames of files \
without them (y/n)?').lower() != 'y':
        print('Hashes will not be added to files without them')
        sys.exit()

    # Looping for all files that need a hash adding to
    for hashedFile in addHashModeFiles:

        try:

            # Obtaining file name and file extension
            (filePath, fileName) = os.path.split(hashedFile[0])
            (fileName, fileExtension) = os.path.splitext(fileName)

            # Renaming file with the hash (note that the hash does not end up
            # before the first fullstop in a filename - however my usage will
            # not include files with more than one fullstop
            filePath = \
            os.path.join(filePath, fileName + ' [' + hashedFile[1] + ']' + \
                         fileExtension)
            shutil.move(hashedFile[0], filePath)

        except(Exception) as e:
            sys.stderr.write('Addition of CRC32 hash \'%s\' to the filename of\
 \'%s\' failed: %s' % (crc, file, e))
            continue


def CheckSFVFile(checksumFile):
    try:

        # Opening file, resulting in usable text regardless of original
        # encoding
        fileData = OpenFile(checksumFile)

        # Looping through all lines
        for line in fileData:

            # Ignoring comments
            if line[0] != ';':

                # Extracting hash (last 'word' on line) and the file to hash.
                # Regex is used as basic splitting on space screws up when
                # there are contiguous spaces. As a capturing group is at the
                # start, '' is returned in 0
                match = re.split("^(.*)[ ]+([a-f0-9]{8})$", line, \
                                flags=re.IGNORECASE)
                path, checksumFileCRC = match[1], match[2]

                # Coping with nested directories in the path depending on
                # platform
                if os.name == 'posix':
                    path = path.replace('\\', '/')
                elif os.name == 'nt':
                    path = path.replace('/', '\\')

                # Constructing full path to hash
                fileToHash = os.path.join(os.path.dirname(checksumFile),
                                          path)

                try:

                    # Hashing file
                    crc = CRC32Checksum(fileToHash)

                    # Displaying results
                    DisplayResults(fileToHash, crc, checksumFileCRC)

                except(Exception) as e:
                    sys.stderr.write('Failed to hash \'%s\':\n%s\n' % \
                                     (fileToHash, e))
                    continue

    except(Exception) as e:
        sys.stderr.write('Failed to process the checksum file \'%s\':\n%s\n'\
                         % (checksumFile, e))


def CheckMD5File(checksumFile):
    raise Exception("Not implemented")
    # TODO:


def ChecksumReadMode(files):

    # Looping for all files passed to detect checksum files and then calling
    # the relevant procedure
    for passedFile in files:
        (ignored, extension) = os.path.splitext(passedFile)

        if extension == '.md5':
            print('\nProcessing \'' + passedFile + '\'...\n')
            CheckMD5File(passedFile)
            fileProcessed = True

        if extension == '.sfv':
            print('\nProcessing \'' + passedFile + '\'...\n')
            CheckSFVFile(passedFile)
            fileProcessed = True

    # Warning user if no valid files have been detected
    if fileProcessed == False:
        print('No valid checksum files have been detected!')

def MD5CreateMode(files):
    raise Exception("Not implemented")
    # TODO:


def SFVCreateMode(files):
    raise Exception("Not implemented")
    # TODO:

# Configuring and parsing passed options
parser = OptionParser()
parser.add_option('-a', '--add-hash-mode', dest='addHashMode', help='mode to \
define when a CRC32 hash is added to a filename where none has been found. \
Defaults to \'none\', \'ask\' prompts the user after hashing and \'always\' \
causes the hash to automatically be added when missing', \
metavar='addHashMode', choices=('none', 'ask', 'always'), default='none')
parser.add_option('-c', '--checksum-read-mode', dest='checksumReadMode', \
help='mode to look for checksum files and then hash the files as \
described', metavar='checksumMode', action='store_true', default=False)
parser.add_option('-s', '--sfv-create-mode', dest='sfvCreateMode', help=' mode\
 to create an sfv file based on hashing the files passed', \
metavar='sfvCreateMode', action='store_true', default=False)
parser.add_option('-m', '--md5-create-mode', dest='md5CreateMode', \
help='mode to create an md5 file based on hashing the files passed', \
metavar='md5CreateMode', action='store_true', default=False)
(options, args) = parser.parse_args()

# Validating options
# Ensuring no other modes are enabled when add-hash-mode is
if options.addHashMode != 'none' and (options.checksumReadMode or \
options.md5CreateMode or options.sfvCreateMode):
    sys.stderr.write(parser.get_usage() + '\nadd-hash-mode can only be used \
when no other modes are enabled\n')
    sys.exit(1)

# Ensuring one mode is enabled at one time
if (options.checksumReadMode + options.sfvCreateMode + options.md5CreateMode) > 1:
    sys.stderr.write(parser.get_usage() + '\nOnly one mode can be enabled at once\n')
    sys.exit(1)

# cfv cannot cope even with opening rapidcrc mod files, let alone intelligently
# dealing with Windows-based nested directory structures inside - dropping
# Ensuring cfv is available if a relevant mode has been requested
#if (options.checksumReadMode + options.sfvCreateMode + options.md5CreateMode) > 0:
#    try:
#        # Quashing stdout and stderr (Python 3.3 allows you to do this
#        # properly...)
#        subprocess.call('cfv --version', stdout=open(os.devnull, 'w'), \
#                        stderr=subprocess.STDOUT)
#
#    except (Exception) as e:
#        sys.stderr.write('%s\nA cfv mode was requested, however the following \
#error occurred when testing to see if cfv is installed:\n\n%s\n\n' % \
#        (parser.get_usage(), e))
#        sys.exit(1)

# Dealing with various modes to run
if options.checksumReadMode:
    ChecksumReadMode(args)

elif options.md5CreateMode:
    MD5CreateMode(args)

elif options.sfvCreateMode:
    SFVCreateMode(args)

else:

    # Normal CRC32 hashing needed
    CRC32HashMode(args)


# TODO: Add ed2k hashing if possible?
