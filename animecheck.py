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

# TODO: GPL3+? Original author hasn't responded to emails

import codecs
import hashlib
import io
import os
import re
import shutil
import sys
import zlib
from datetime import datetime
from optparse import OptionParser

# Defining terminal escape codes
h_null = "\x1b[00;00m"
h_red = "\x1b[31;01m"
h_green = "\x1b[32;01m"
p_reset = "\x08" * 8

# Variable declaration
addHashModeFiles = []
version = '0.3'


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
            if size > 0:
                sys.stdout.write("%7d" % (done * 100 / size) + "%" + p_reset)
                pass
            else:
                sys.stdout.write("%7d" % (100) + "%" + p_reset)
                pass

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


def MD5Checksum(filename):

    # Variable allocation
    done = 0

    # Opening file to hash, buffer is large presumably to ensure its read in
    # fast
    fileToHash = open(filename, "rb")
    buff_size = 65536
    size = os.path.getsize(filename)

    # Preparing md5 hash object
    md5Hash = hashlib.md5()
    try:
        while True:

            # Reading in a chunk of the data and updating the terminal
            data = fileToHash.read(buff_size)
            done += buff_size

            # Print digit in 7 character field with right justification
            if size > 0:
                sys.stdout.write("%7d" % (done * 100 / size) + "%" + p_reset)
            else:
                sys.stdout.write("%7d" % (100) + "%" + p_reset)

            # Iteratively hashing the data
            if not data:
                break
            md5Hash.update(data)

    # Catching Cntrl+C and exiting
    except KeyboardInterrupt:
        sys.stdout.write(p_reset)
        fileToHash.close()
        sys.exit(1)

    # Clearing up terminal and file
    sys.stdout.write(p_reset)
    fileToHash.close()

    # Returning actual hash
    return md5Hash.hexdigest()


def ED2kLink(filename):
    """ Returns the ed2k hash of a given file. """

    # Based on radicand's code:
    # http://www.radicand.org/edonkey2000-hash-in-python/
    # ed2k links article: http://en.wikipedia.org/wiki/Ed2k_URI_scheme

    # Variable allocation
    # done is global as the md4_hash function needs to be able to update it
    global done
    done = 0

    # Obtaining file size
    fileSize = os.path.getsize(filename)

    try:

        # Preparing md4 hash object. Obtaining a copy perhaps due to speed?
        # hashlib does not include this algorithm, but the new method
        # delegates to OpenSSL when the algorithm is not found
        md4 = hashlib.new('md4').copy

    except Exception as e:

        # OpenSSL is probably not available?
        sys.stderr.write('ed2k hash mode was requested, but an attempt to get '
                         'at md4 hashing failed - is OpenSSL installed?'
                         '\n\n%s\n' % (e))
        sys.exit(1)

    def gen(f):

        # Generator to return data in 9500KB blocks - these are the individual
        # blocks that are hashed to start with

        # Ensuring a local variable is not created
        global done

        # Defining a smaller read size that is a factor of 9500KB (9728000B),
        # so that we get much finger grained feedback on the read progress
        smallBufSize = 972800

        # Preparing currentBlockData
        currentBlockData = ''

        while True:
            try:

                # Looping until a clean 9500KB block has been read
                for readCounter in range(10):

                    # Reading data and breaking if nothing more has been read
                    data = f.read(smallBufSize)
                    if not data: break
                    else: currentBlockData += data
                    
                    # Updating terminal
                    done += len(data)

                    # Print digit in 7 character field with right justification
                    if fileSize > 0:
                        sys.stdout.write("%7d" % (done * 100 / fileSize) + "%"
                                         + p_reset)
                    else:
                        sys.stdout.write("%7d" % (100) + "%" + p_reset)

                # Yielding or exiting based on whether the current block of data
                # is empty. As this is a generator function and currentBlockData
                # accrues data, unless it is cleared before yielding, its contents
                # will persist  
                if currentBlockData:
                    dataToReturn = currentBlockData
                    currentBlockData = '' 
                    yield dataToReturn
                else: return
               
            # Catching Cntrl+C and exiting
            except KeyboardInterrupt:
                sys.stdout.write(p_reset)
                f.close()
                sys.exit(1)
 
    def md4_hash(data):
        try:
            
            # Hashing passed block
            m = md4()
            m.update(data)
    
            # Returning hash
            return m
        
        # Catching Cntrl+C and exiting
        except KeyboardInterrupt:
            sys.stdout.write(p_reset)
            f.close()
            sys.exit(1)

    with open(filename, 'rb') as f:
        
        # Obtaining generator function
        a = gen(f)
        
        # Building up a list of md4 hashes associated with 9500KB blocks
        hashes = [md4_hash(data).digest() for data in a]
        
        # If only one chunk is present, the hash is already done, otherwise concatenate
        # the hashes of all current blocks and hash this
        if len(hashes) == 1: ed2kHash = hashes[0].encode("hex")
        else: ed2kHash = md4_hash(reduce(lambda a,d: a + d, hashes, "")).hexdigest()

        # Returning ed2k link
        # E.g.: 'ed2k://|file|The_Two_Towers-The_Purist_Edit-Trailer.avi|14997504|965c013e991ee246d63d45ea71954c4d|/'
        return ('ed2k://|file|%s|%d|%s|/' % 
                (os.path.basename(filename).replace(' ', '_'), fileSize, ed2kHash))
        

def DisplayResults(fileToHash, obtainedHash, checksumFileHash=None):

    # Splitting based on whether a checksum file is being processed or not
    if checksumFileHash == None:
        try:

            # Obtaining the hash from the filename (penultimate fragment) -
            # remember that re does not support POSIX character classes
            dest_sum = re.split('([a-f0-9]{8})', fileToHash,
                                flags=re.IGNORECASE)[-2]

            # Setting colours depending on good/bad hash
            if obtainedHash == dest_sum.upper():
                h_in = h_green
            else:
                h_in = h_red

            # Obtaining a list of the filename before and after the hash
            sfile = fileToHash.split(dest_sum)

            # Printing results with coloured hash at the beginning and in
            # the file path
            print("%s%s%s   %s%s%s%s%s" % (h_in, obtainedHash, h_null,
                                           sfile[0], h_in, dest_sum, h_null,
                                           sfile[1]))

        except(IndexError, ValueError):

            # No CRC32 has been found - outputting calculated value and file
            # path
            print("%s   %s" % (obtainedHash, fileToHash))

            # If hashes are to be added to filenames, adding to the list
            if options.addHashMode != 'none':
                hashedFile = [fileToHash, obtainedHash]
                addHashModeFiles.append(hashedFile)
    else:

        # hash is from checksum file - setting colours depending on good/bad
        # hash. obtainedHash is uppercased here as md5 hashes are outputted
        # lowercase
        if obtainedHash.upper() == checksumFileHash.upper():
            h_in = h_green
        else:
            h_in = h_red

        # Printing results with coloured hash at the beginning and in the
        # file path
        print("%s%s%s   %s" % (h_in, obtainedHash, h_null, fileToHash))


def NormaliseAndValidateFiles(files, checksumType):

    # Normalising the file paths to ensure all inputs are absolute paths
    normalisedFiles = []
    for fileToHash in files:
        normalisedFiles.append(os.path.abspath(fileToHash))

    # Debug code
    #print(normalisedFiles)

    # Obtaining common directory root
    commonPrefix = os.path.commonprefix(normalisedFiles)

    # Ensuring files share a common directory root
    if commonPrefix == '':

        # If the commonPrefix is blank there is a chance all files are in the
        # current directory - making sure this is the case
        for fileToHash in normalisedFiles:
            if not os.path.isfile(fileToHash):
                sys.stderr.write('%s\n%s create mode was requested, but the \
passed files to hash do not share a common root directory:\n\n%s\n' %
                (parser.get_usage(), checksumType, normalisedFiles))
                sys.exit(1)

        # It is - setting commonPrefix appropriately (curdir is just '.' -
        # forcing it into a usable path)
        commonPrefix = os.path.abspath(os.curdir)

    # If the prefix is actually a file, fixing. The common prefix could also be
    # a directory structure then a common part of the filename - attempting
    # to resolve to the underlying directory
    if not os.path.isdir(commonPrefix):
        commonPrefix = os.path.dirname(commonPrefix)

    # Ensuring common directory root is valid
    if not os.path.isdir(commonPrefix):
        sys.stderr.write('%s\n%s create mode was requested, but the \
calculated common root directory (\'%s\') of the passed files to hash is not \
valid:\n\n%s\n' % (parser.get_usage(), checksumType, commonPrefix,
                   normalisedFiles))
        sys.exit(1)

    # Making sure that commonPrefix doesnt have a trailing slash
    if commonPrefix[-1:] == os.sep: commonPrefix = commonPrefix[:-1]

    # Returning results
    return normalisedFiles, commonPrefix


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

        except IOError as e:
            sys.stderr.write('\nFailed to hash the file \'%s\':\n\n%s\n' %
                             (fileToHash, e))
            continue

    # If files without hashes exist and the add hash mode is 'ask', proceeding
    # only if the user wants to
    if (len(addHashModeFiles) > 0
        and options.addHashMode == 'ask'
        and raw_input('\nDo you want to add CRC32 hashes to the filenames of'
        ' files without them (y/n)?').lower() != 'y'):
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
            os.path.join(filePath, fileName + ' [' + hashedFile[1] + ']' +
                         fileExtension)
            shutil.move(hashedFile[0], filePath)

        except Exception as e:
            sys.stderr.write('Addition of CRC32 hash \'%s\' to the filename of'
                             ' \'%s\' failed: %s' % (crc, file, e))
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
                match = re.split("^(.*)[ ]+([a-f0-9]{8})$", line,
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

                except Exception as e:
                    sys.stderr.write('Failed to hash \'%s\':\n%s\n' %
                                     (fileToHash, e))
                    continue

    except Exception  as e:
        sys.stderr.write('Failed to process the checksum file \'%s\':\n%s\n'
                         % (checksumFile, e))


def CheckMD5File(checksumFile):
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
                match = re.split("^([a-f0-9]{32})[ ]+\*(.*)$", line,
                                flags=re.IGNORECASE)
                path, checksumFileMD5 = match[2], match[1]

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
                    md5 = MD5Checksum(fileToHash)

                    # Displaying results
                    DisplayResults(fileToHash, md5, checksumFileMD5)

                except Exception as e:
                    sys.stderr.write('Failed to hash \'%s\':\n%s\n' %
                                     (fileToHash, e))
                    continue

    except Exception as e:
        sys.stderr.write('Failed to process the checksum file \'%s\':\n%s\n'
                         % (checksumFile, e))


def ChecksumReadMode(files):

    # Variable allocation
    fileProcessed = False

    # Looping for all files passed to detect checksum files and then calling
    # the relevant procedure
    for passedFile in files:
        extension = os.path.splitext(passedFile)[1]

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

    try:

        # Preparing checksumFile
        checksumFile = None

        # Normalising and validating passed files
        files, commonPrefix = NormaliseAndValidateFiles(files, 'md5')

        # Debug code
        #print commonPrefix
        #print os.path.basename(commonPrefix[:-1])

        # Setting checksumFileOutput. Basename implementation is broken,
        # removing trailing os.sep to make it work...
        if options.checksumOutput != None:
            checksumFileOutput = options.checksumOutput
        else:
            checksumFileOutput = (commonPrefix + os.sep +
            os.path.basename(commonPrefix) + '.md5')

        # Debug code
        #print checksumFileOutput

        # Writing out header to checksum file
        checksumFile = open(checksumFileOutput, 'w')
        checksumFile.writelines('; Generated by %s v%s on %s' %
            (os.path.split(sys.argv[0])[1], version,
            datetime.now().isoformat() + '\n;\n'))

        # Looping for all files to hash
        for fileToHash in files:

            # Removing common root directory from file path (first item in the
            # list will be empty). Removing directory slash as needed
            relativePath = fileToHash.split(commonPrefix)[1]
            if relativePath[:1] == os.sep: relativePath = relativePath[1:]

            # Obtaining file hash
            fileHash = MD5Checksum(fileToHash)

            # Writing out file record
            checksumFile.write(fileHash + ' *' + relativePath + '\n')

        # Notifying user that checksum file has been written successfully
        print('\nChecksum file \'' + checksumFileOutput + '\' has been written'
              ' successfully')

    except Exception as e:
        sys.stderr.write('Failed to write to the checksum file \'%s\':\n%s\n'
                         % (checksumFileOutput, e))
        sys.exit(1)

    finally:

        # Closing file
        if not checksumFile is None: checksumFile.close()
        
    
def SFVCreateMode(files):

    try:
        
        # Preparing checksumFile
        checksumFile = None
        
        # Normalising and validating passed files
        files, commonPrefix = NormaliseAndValidateFiles(files, 'sfv')

        # Debug code
#        print commonPrefix
#        print os.path.basename(commonPrefix)
#        print files

        # Setting checksumFileOutput. Basename implementation is broken,
        # removing trailing os.sep to make it work...
        if options.checksumOutput != None:
            checksumFileOutput = options.checksumOutput
        else:
            checksumFileOutput = (commonPrefix + os.sep +
            os.path.basename(commonPrefix) + '.sfv')
    
        # Writing out header to checksum file
        checksumFile = open(checksumFileOutput, 'w')
        checksumFile.writelines('; Generated by %s v%s on %s' %
            (os.path.split(sys.argv[0])[1], version,
            datetime.now().isoformat() + '\n;\n'))
    
        # Looping for all files to hash
        for fileToHash in files:
    
            # Removing common root directory from file path (first item in the
            # list will be empty). Removing directory slash as needed
            relativePath = fileToHash.split(commonPrefix)[1]
            if relativePath[:1] == os.sep: relativePath = relativePath[1:]
    
            # Obtaining file hash
            fileHash = CRC32Checksum(fileToHash)
    
            # Writing out file record
            checksumFile.write(relativePath + ' ' + fileHash + '\n')
    
        # Notifying user that checksum file has been written successfully
        print('\nChecksum file \'' + checksumFileOutput + '\' has been written '
              'successfully')

    except Exception as e:
        sys.stderr.write('Failed to write to the checksum file \'%s\':\n%s\n'
                         % (checksumFileOutput, e))
        sys.exit(1)

    finally:

        # Closing file
        if not checksumFile is None: checksumFile.close()


def ED2kLinkMode(files):
    
    # Generating eD2k links for all passed files
    for fileToHash in files:
        try:
            print(ED2kLink(fileToHash))
            
        except IOError as e:
            sys.stderr.write('\nFailed to generate an eD2k link for the file '
                             '\'%s\':\n\n%s\n' % (fileToHash, e))
            continue


# Configuring and parsing passed options
parser = OptionParser()
parser.add_option('-a', '--add-hash-mode', dest='addHashMode', help='mode to '
'define when a CRC32 hash is added to a filename where none has been found. '
'Defaults to \'none\', \'ask\' prompts the user after hashing and \'always\' '
'causes the hash to automatically be added when missing',
metavar='addHashMode', choices=('none', 'ask', 'always'), default='none')
parser.add_option('-c', '--checksum-read-mode', dest='checksumReadMode',
help='mode to look for checksum files and then hash the files as \
described', metavar='checksumMode', action='store_true', default=False)
parser.add_option('-e', '--ed2k-link-mode', dest='ED2kLinkMode',
help='mode to hash given files and output the ed2k links',
metavar='checksumMode', action='store_true', default=False)
parser.add_option('-s', '--sfv-create-mode', dest='sfvCreateMode', help=' mode'
' to create an sfv file based on hashing the files passed',
metavar='sfvCreateMode', action='store_true', default=False)
parser.add_option('-m', '--md5-create-mode', dest='md5CreateMode',
help='mode to create an md5 file based on hashing the files passed',
metavar='md5CreateMode', action='store_true', default=False)
parser.add_option('-o', '--checksum-output', dest='checksumOutput',
help='path to output checksum file to (only valid in checksum file creation '
'modes). If omitted, the file is output to the hashed files\' common root '
'directory', metavar='checksumOutput')
(options, args) = parser.parse_args()

# Validating options
# Ensuring no other modes are enabled when add-hash-mode is
if (options.addHashMode != 'none'
    and (options.checksumReadMode
    or options.md5CreateMode
    or options.sfvCreateMode)):
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

elif options.ED2kLinkMode:
    ED2kLinkMode(args)

else:

    # Normal CRC32 hashing needed
    CRC32HashMode(args)


# TODO: Proper information display during hashing
# TODO: Summary of successful and failed hashes including files not found when processing checksum files and general CRC32 hashing mode
# TODO: Import future?