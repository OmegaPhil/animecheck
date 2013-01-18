#!/usr/bin/env python

'''
Version 0.9 2012.11.17
Copyright (c) 2009, Taoufik El Aoumari (v0.2)
Copyright (c) 2012, OmegaPhil (v0.3-) - OmegaPhil+animecheck@gmail.com
Copyright (c) 2012, Ricardo Constantino (v0.5) - wiiaboo@gmail.com

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

# Preparing for Python 3
from __future__ import division, print_function, unicode_literals

GPL_NOTICE = '''
Copyright (C) 2012 OmegaPhil
License GPLv3: GNU GPL version 3 <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
'''

import codecs
import hashlib
import io
import os
import re
import shutil
import sys
import time
import traceback
import zlib
from datetime import datetime, timedelta
from optparse import OptionParser

# Initialising variables
addHashModeFiles = []
VERSION = '0.9'  # Remember to update the notice at the top too
addHashFormat = '{name} [{hash}]'
done = 0
currentHashingTask = {}
listingError = False

# Defining terminal escape codes based on OS
if os.name != 'nt':
    H_NULL = '\x1b[00;00m'
    H_RED = '\x1b[31;01m'
    H_GREEN = '\x1b[32;01m'
    #P_RESET = '\x08'  # Backspace...

    # Clear to end of line then carriage return. This is usable now that there
    # are only two terminal updates a second
    P_RESET = '\x1B[K\x0D'

else:
    try:
        from colorama import init, Fore, Style  # pylint: disable=F0401

        init()

        H_NULL = Fore.RESET + Style.NORMAL
        H_RED = Fore.RED + Style.BRIGHT
        H_GREEN = Fore.GREEN + Style.BRIGHT

    except ImportError:
        H_NULL = H_RED = H_GREEN = ''

    P_RESET = '\x0D'

# Fix Python 2.x input
try:
    input = raw_input  # pylint: disable=W0622
except NameError:
    pass

# In Python 2 on Debian, despite the fact that the locale is clearly UTF-8, the
# default encoding is set to ASCII. This is unacceptable - the requirement to
# deal with and print unicode filenames is trivial. In Python 3, the proper
# default of UTF-8 is already set. This was what essentially caused the
# original unicode errors on processing program arguments, and is also
# responsible for the encoding Python decides to use when it has the
# responsibility for writing stdout/err to file
if sys.getdefaultencoding() != 'utf-8':

    # Non-UTF-8 encoding in use (probably ASCII) - fixing (the
    # setdefaultencoding method is removed after it is set in a site
    # customisation script during Python startup I think - hence the reload)
    reload(sys)
    sys.setdefaultencoding('utf-8')


def crc32_checksum(filename):
    '''CRC32 hashes the passed file, displaying the hashing progress'''

    # Initialising variables
    crc = 0
    done = 0  # pylint: disable=W0621

    # Opening file to hash, buffer is large presumably to ensure its read in
    # fast
    with io.open(filename, "rb") as fileToHash:
        buff_size = 65536
        size = os.path.getsize(filename)

        try:
            while True:

                # Reading in a chunk of the data
                data = fileToHash.read(buff_size)
                done += buff_size

                # Updating the hashing task status
                if data:
                    currentHashingTask_update(hashedData=len(data),
                                                   fileSize=size,
                                                   hashedSoFar=done)

                # Iteratively hashing the data
                if not data:
                    break
                crc = zlib.crc32(data, crc)

        # Catching Cntrl+C and exiting
        except KeyboardInterrupt:
            sys.stdout.write(P_RESET)
            sys.exit(1)

    # Clearing up terminal and file
    sys.stdout.write(P_RESET)

    # If the crc hex value is negative, bitwise and it with the maximum 32bit
    # value. Apparently this is a 'bit mask' resulting in a 32bit long value
    # (rather than an infinitely long value, see
    # http://stackoverflow.com/a/7825412). It is also guaranteed to return a
    # positive number
    if crc < 0:
        crc &= 2 ** 32 - 1

    # Return 8-digit precision hex integer in uppercase
    return "%.8X" % (crc)


def md5_checksum(filename):
    '''MD5 hashes the passed file, displaying the hashing progress'''

    # Initialising variables
    done = 0  # pylint: disable=W0621

    # Opening file to hash, buffer is large presumably to ensure its read in
    # fast
    with io.open(filename, "rb") as fileToHash:
        buff_size = 65536
        size = os.path.getsize(filename)

        # Preparing md5 hash object (disabling pylint error as it can't detect
        # the md5 function)
        md5Hash = hashlib.md5()  # pylint: disable=E1101
        try:
            while True:

                # Reading in a chunk of the data
                data = fileToHash.read(buff_size)
                done += buff_size

                # Updating the hashing task status
                if data:
                    currentHashingTask_update(hashedData=len(data),
                                                   fileSize=size,
                                                   hashedSoFar=done)

                # Iteratively hashing the data
                if not data:
                    break
                md5Hash.update(data)

        # Catching Cntrl+C and exiting
        except KeyboardInterrupt:
            sys.stdout.write(P_RESET)
            sys.exit(1)

    # Clearing up terminal
    sys.stdout.write(P_RESET)

    # Returning actual hash
    return md5Hash.hexdigest()


def ed2k_link(filename):
    '''Generates an eD2k link of the passed file, displaying the hashing
    progress'''

    # Based on radicand's code:
    # http://www.radicand.org/edonkey2000-hash-in-python/
    # eD2k links article: http://en.wikipedia.org/wiki/Ed2k_URI_scheme

    # pylint considers this function to have too many branches?
    # pylint: disable=R0912

    # Initialising variables
    # done is global as the md4_hash function needs to be able to update it
    global done  # pylint: disable=W0603
    done = 0

    # Obtaining file size
    fileSize = os.path.getsize(filename)

    try:

        # Preparing md4 hash object. Obtaining a copy perhaps due to speed?
        # hashlib does not include this algorithm, but the new method
        # delegates to OpenSSL when the algorithm is not found
        md4 = hashlib.new('md4').copy

    except ValueError as e:

        # OpenSSL is probably not available?
        sys.stderr.write('eD2k link mode was requested, but an attempt to get '
                         'at md4 hashing failed - is OpenSSL installed?'
                         '\n\n%s\n' % (e))
        sys.exit(1)

    def gen(f):
        '''Generator to return data in 9500KB blocks - these are the individual
        blocks that are hashed to start with'''

        # Initialising variables
        # Ensuring a local variable is not created
        global done  # pylint: disable=W0603
        currentBlockData = b''

        # Defining a smaller read size that is a factor of 9500KB (9728000B),
        # so that we get much finger grained feedback on the read progress
        smallBufSize = 972800

        while True:
            try:

                # Looping until a clean 9500KB block has been read
                for _ in range(10):

                    # Reading data and breaking if nothing more has been read
                    data = f.read(smallBufSize)
                    if not data:
                        break
                    else:
                        currentBlockData += data

                    # Updating done
                    done += len(data)

                    # Updating the hashing task status
                    if data:
                        currentHashingTask_update(hashedData=len(data),
                                                       fileSize=fileSize,
                                                       hashedSoFar=done)

                # Yielding or exiting based on whether the current block of
                # data is empty. As this is a generator function and
                # currentBlockData accrues data, unless the latter is cleared
                # before yielding, its contents will persist
                if currentBlockData:
                    dataToReturn = currentBlockData
                    currentBlockData = b''
                    yield dataToReturn
                else:
                    return

            # Catching Cntrl+C and exiting
            except KeyboardInterrupt:
                sys.stdout.write(P_RESET)
                f.close()
                sys.exit(1)

    def md4_hash(data):
        '''Returns md4 hash of passed data'''

        try:

            # Hashing passed block
            m = md4()
            m.update(data)

            # Returning hash
            return m

        # Catching Cntrl+C and exiting
        except KeyboardInterrupt:
            sys.stdout.write(P_RESET)
            f.close()
            sys.exit(1)

    with io.open(filename, 'rb') as f:

        # Obtaining generator function
        a = gen(f)

        # Building up a list of md4 hashes associated with 9500KB blocks
        hashes = [md4_hash(data).digest() for data in a]

        # If only one chunk is present, the hash is already done, otherwise
        # concatenate the hashes of all current blocks and hash this
        if len(hashes) == 1:
            ed2kHash = hashes[0].encode('hex')
        else:
            ed2kHash = md4_hash(b''.join(hashes)).hexdigest()

        # Returning ed2k link
        # E.g.: 'ed2k://|file|The_Two_Towers-The_Purist_Edit-Trailer.avi|14997504|965c013e991ee246d63d45ea71954c4d|/'
        return ('ed2k://|file|%s|%d|%s|/' %
                (os.path.basename(filename).replace(' ', '_'), fileSize,
                 ed2kHash))


def display_results(fileToHash, obtainedHash, checksumFileHash=None,
                    checksumFileGeneration=False):
    '''Displays results of a hashing operation'''

    # Splitting based on whether a checksum file is being checked/generated or
    # not
    if not checksumFileHash and not checksumFileGeneration:
        try:

            # It isn't - called from crc32_hash_mode. Obtaining the hash from
            # the filename (penultimate fragment) - remember that re does not
            # support POSIX character classes
            dest_sum = re.split(r'([a-f0-9]{8})', fileToHash,
                                flags=re.IGNORECASE)[-2]

            # Setting colours depending on good/bad hash and registering a
            # corrupt file as appropriate
            if obtainedHash == dest_sum.upper():
                h_in = H_GREEN
            else:
                h_in = H_RED
                currentHashingTask_file_corrupt(fileToHash)

            # Obtaining filename fragments before and after the hash
            sfile = fileToHash.split(dest_sum)

            # Printing results with coloured hash at the beginning and in
            # the file path
            print("%s%s%s   %s%s%s%s%s" % (h_in, obtainedHash, H_NULL,
                                           sfile[0], h_in, dest_sum, H_NULL,
                                           sfile[1]))

        except(IndexError, ValueError):

            # No CRC32 has been found - outputting calculated value and file
            # path
            print("%s   %s" % (obtainedHash, fileToHash))

            # If hashes are to be added to filenames, adding to the list
            if options.addHashMode != 'none':
                hashedFile = [fileToHash, obtainedHash]
                addHashModeFiles.append(hashedFile)

            # Registering no hash file
            currentHashingTask_file_no_hash(fileToHash)

    elif checksumFileHash:

        # hash is from checksum file - setting colours depending on good/bad
        # hash. obtainedHash is uppercased here as md5 hashes are outputted
        # lowercase. Registering a corrupt file as appropriate
        if obtainedHash.upper() == checksumFileHash.upper():
            h_in = H_GREEN
        else:
            h_in = H_RED
            currentHashingTask_file_corrupt(fileToHash)

        # Printing results with coloured hash at the beginning and in the
        # file path
        print("%s%s%s   %s" % (h_in, obtainedHash, H_NULL, fileToHash))

    elif checksumFileGeneration:

        # Hash is from hashing a file as part of checksum file generation
        # No colours are to be used here
        print("%s   %s" % (obtainedHash, fileToHash))


def normalise_and_validate_files(files, checksumType):
    '''Validates then returns a list of given files, ensuring they have
    absolute paths'''

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
                sys.stderr.write('%s\n%s create mode was requested, but the '
                                 'passed files to hash do not share a common '
                                 'root directory:\n\n%s\n' %
                                 (parser.get_usage(), checksumType,
                                  normalisedFiles))
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
        sys.stderr.write('%s\n%s create mode was requested, but the '
                         'calculated common root directory (\'%s\') of '
                         'the passed files to hash is not valid:\n\n%s\n' %
                         (parser.get_usage(), checksumType, commonPrefix,
                          normalisedFiles))
        sys.exit(1)

    # Making sure that commonPrefix doesnt have a trailing slash
    if commonPrefix[-1:] == os.sep:
        commonPrefix = commonPrefix[:-1]

    # Returning results
    return normalisedFiles, commonPrefix


def recursive_file_search(pathsToSearch):
    '''Recurses through all directories and files given to generate a complete
    list of files'''

    global listingError

    # Initialising variables
    foundFiles = []
    sanitisedFiles = []

    # Looping through all passed files and directories
    for path in pathsToSearch:
        if os.path.isdir(path):

            # Preparing the path to submit to os.walk - in Python 2, if a
            # unicode string is passed and a subsequent file/directory has
            # invalid bytes (invalid codepoint sequence) in its' name, any
            # attempt by Python to manipulate the string will cause an
            # unhandled UnicodeDecodeError. Bytes or strings don't have this
            # issue as they are raw data and therefore not interpreted. In
            # Python 3, strings are unicode by default, and the default
            # behaviour for invalid bytes is to represent them by surrogate
            # pairs rather than throwing an error
            # Note that 'bytes()' in Python 2 is an alias to 'str()'
            if sys.version_info.major < 3:
                path = str(path)

            # Recursively walking through directories discovered. If you don't
            # pass an error handler, errors associated with listing the passed
            # directory are silently ignored!!
            for directory_path, _, directory_files in os.walk(path,
                                                onerror=walk_error_handler):

                # Adding all discovered files to the main list
                for directory_file in directory_files:
                    foundFiles.append(os.path.join(directory_path,
                                                   directory_file))
        elif os.path.isfile(path):
            foundFiles.append(path)

        else:

            # Alerting user to invalid path and exiting
            sys.stderr.write('Path \'%s\' is invalid' % path)
            sys.exit(1)

    # Checking the file paths for invalid bytes in filenames (this can
    # happen due to extracting a zip that doesn't properly maintain or deal
    # with the encoding the filenames were compressed in, e.g.)
    for foundFile in foundFiles:
        try:

            if sys.version_info.major < 3:

                # File paths at this point should be bytes - converting to
                # unicode (and subsequently catching invalid encoding). Note
                # that replacing/escaping invalid characters at this stage
                # merely causes a later stage to cock up
                sanitisedFiles.append(unicode(foundFile))
            else:

                # For Python 3, the string is already a unicode one, with
                # invalid bytes represented by surrogate pairs. Therefore, to
                # detect the invalid data, I need to encode it with UTF-8 to
                # return bytes - the encoder will choke and throw an error. I
                # don't keep the result as I want a unicode string, not bytes
                _ = foundFile.encode('utf-8')
                sanitisedFiles.append(foundFile)

        except Exception:

            # Invalid encoding detected - warning user and recording the fact
            # a listing error happened. In Python 2, foundFile is a string and
            # therefore plain bytes that needs to be decoded to unicode, in
            # Python 3 the string is already unicode with surrogate pairs used
            # to mark the invalid bytes and is therefore safe to print and
            # write
            if sys.version_info.major < 3:
                badPath = unicode(foundFile, errors='replace')
            else:
                badPath = foundFile
            sys.stderr.write('\nThe file \'%s\' has invalid encoding in its '
                             'path and will not be hashed!\n' % badPath)
            listingError = True

    # Returning sanitised files
    return sanitisedFiles


def walk_error_handler(walkError):
    '''Function called when recursive_file_search's os.walk call encounters
    errors'''

    global listingError

    # Detecting OSErrors (the only error that is supposed to be propagated)
    # These occur during the initial directory listing of os.walk so should
    # indicate a directory isn't hashable
    if isinstance(walkError, OSError):

        # Warning user
        sys.stderr.write('\nERROR: Unable to list the directory \'%s\' - files'
                         ' contained will not be hashed!\nReported error: %s\n'
                         % (walkError.filename, str(walkError)))
    else:

        # Unknown error detected - warning user
        sys.stderr.write('\nERROR: Unexpected error whilst listing files in a '
                         'directory - please read the error message to see '
                         'which directory will not be hashed:\n%s' %
                         str(walkError))

    # Recording the fact an error has occurred (this happens before the
    # hashing task has been initialised)
    listingError = True


def open_file(fileToOpen):
    '''Opens files regardless of encoding...'''

    # Custom function has been created as Python, even though it is 'unicode
    # capable', cannot cope with Just Reading a UTF-16 file (so far)

    # Reading whole file in at once - done like this to work around
    # encoding issues (binary to prevent any attempt at interpretation
    # which would just lead to corruption). Even io.open fails miserably
    # on its own when it automatically tries to convert the leading BOM into
    # UTF-8
    fileData = io.open(fileToOpen, 'rb').read()

    # Detecting utf16 encoding and decoding to sane data. Appears
    # to also thankfully kill off the BOM. The following StringIO wants
    # unicode so everything else is encoded accordingly (even with
    # unicode_literals encoding is NOT UTF-8 by default)
    if fileData.startswith(codecs.BOM_UTF16):
        fileData = fileData.decode('utf16')
    else:
        fileData = fileData.decode('utf8')

    # You apparently cant just split the resulting string into newlines and
    # then iterate over them, so returning a file-like object
    # io's StringIO translates newlines, raw StringIO doesnt - however even
    # though io's 'universal newlines' translation is supposed to be default
    # on (None), it isnt unless you explicitly pass None!!
    return io.StringIO(fileData, None)


def humanise_bytes(byteCount, precision=2):
    '''Return a humanised string representation of a number of bytes.

    >>> humanise_bytes(1)
    '1 byte'
    >>> humanise_bytes(1024)
    '1.0 kB'
    >>> humanise_bytes(1024*123)
    '123.0 kB'
    >>> humanise_bytes(1024*12342)
    '12.1 MB'
    >>> humanise_bytes(1024*12342,2)
    '12.05 MB'
    >>> humanise_bytes(1024*1234,2)
    '1.21 MB'
    >>> humanise_bytes(1024*1234*1111,2)
    '1.31 GB'
    >>> humanise_bytes(1024*1234*1111,1)
    '1.3 GB'
    '''

    # Modified from Version 2
    # Source: http://code.activestate.com/recipes/577081-humanized-representation-of-a-number-of-bytes/
    # License: See COPYING.MIT

    # Bitshifting n digits to the left (more significant bits direction), every
    # 10 = multiplying by 2^10 = 1024
    abbrevs = (
        (1 << 50, 'PB'),
        (1 << 40, 'TB'),
        (1 << 30, 'GB'),
        (1 << 20, 'MB'),
        (1 << 10, 'kB'),
        (1, 'bytes')
    )
    if byteCount == 1:
        return '1 byte'
    for factor, suffix in abbrevs:
        if byteCount >= factor:
            break

    # Obtaining initial formatted byte count (decimal of user-defined
    # precision from the given float). This keeps insignificant
    # trailing zeros which must be removed. g does this but takes in the data
    # as a double, and therefore formats it with exponentiation which is not
    # appropriate
    formattedByteCount = '%.*f' % (precision, byteCount / factor)  # pylint: disable=W0631

    # Removing trailing zeros and decimal place then returning
    return formattedByteCount.rstrip('0').rstrip('.') + suffix  # pylint: disable=W0631


def get_date(ctime):
    '''Function to return a local date in standard format'''

    # Converting given ctime to struct_time based off local time
    localTime = time.localtime(ctime)

    # Generating date parts and ensuring they are correctly zero-padded as
    # appropriate
    timeDay = (str(localTime.tm_mday) if len(str(localTime.tm_mday)) == 2
               else '0' + str(localTime.tm_mday))
    timeMonth = (str(localTime.tm_mon) if len(str(localTime.tm_mon)) == 2
                 else '0' + str(localTime.tm_mon))
    timeYear = str(localTime.tm_year)[-2:]
    timeHour = (str(localTime.tm_hour) if len(str(localTime.tm_hour)) == 2
                else '0' + str(localTime.tm_hour))
    timeMinute = (str(localTime.tm_min) if len(str(localTime.tm_min)) == 2
                  else '0' + str(localTime.tm_min))
    timeSecond = (str(localTime.tm_sec) if len(str(localTime.tm_sec)) == 2
                  else '0' + str(localTime.tm_sec))

    # Returning standard format
    return '%s/%s/%s %s:%s:%s' % (timeDay, timeMonth, timeYear, timeHour,
                                  timeMinute, timeSecond)


def currentHashingTask_initialise(files):
    '''Initialises current hashing task record'''

    # Persisting currentHashingTask changes
    global currentHashingTask  # pylint: disable=W0603

    # Defining here so it is in one place only
    currentHashingTask = {
                          # Time task has started
                          'hashStartTime': 0,
                          'dataHashed': 0,
                          'dataToHash': 0,
                          'filesToHash': 0,
                          'filesHashed': 0,
                          'lastUpdatedSpeed': 0,
                          'lastUpdatedTime': 0,

                          # Records amount hashed on last terminal update
                          'lastUpdatedDataHashed': 0,

                          # Speeds are initialised as strings in case 0 is a
                          # valid recorded speed
                          'speed1': '',
                          'speed2': '',
                          'speed3': '',
                          'speed4': '',

                          # Cached speed value to avoid constantly changing
                          # output
                          'cachedAverageSpeed': '',

                          # Time at which the value was cached
                          'cachedAverageSpeedTime': 0,
                          'corruptFileCount': 0,
                          'noHashFileCount': 0,
                          'errorFileNotFoundCount': 0,
                          'errorOtherCount': 0}

    # Looping for all passed files
    for fileToHash in files:

        try:

            # Recording the scale of the task ahead
            currentHashingTask['filesToHash'] += 1
            currentHashingTask['dataToHash'] += os.path.getsize(fileToHash)

        # Skipping all errors (probably caused by the above getsize) - the
        # actual hashing code will raise the relevant errors
        except:  # pylint: disable=W0702
            continue

    # Setting start time
    currentHashingTask['hashStartTime'] = time.time()


def currentHashingTask_update(hashedData=0, fileSize=0, hashedSoFar=0,
                              fileHashed=False):
    '''Updates current hashing task record'''

    # Persisting currentHashingTask changes
    global currentHashingTask

    # Updating task - splitting based on whether the update is more data
    # hashed or a file has been completed
    if hashedData != 0:

        # Validating hashedData
        if hashedData > currentHashingTask['dataToHash']:
            raise Exception('currentHashingTask_update was informed that %dB '
                            'had been hashed, however only %dB remains to '
                            'hash' % (hashedData,
                                      currentHashingTask['dataToHash']))

        # TODO: Bug here in sfv creation mode - have had an instance of the
        # above. Can't recreate though... 14.01.13: Another instance after
        # hashing >400,000 files...

        # Updating data amounts
        currentHashingTask['dataHashed'] += hashedData
        currentHashingTask['dataToHash'] -= hashedData

        # Obtaining duration
        lastUpdatedTime = (currentHashingTask['lastUpdatedTime']
                           if currentHashingTask['lastUpdatedTime']
                           else currentHashingTask['hashStartTime'])
        duration = time.time() - lastUpdatedTime

        # Debug code
        #print('\n' + str(duration) + '\n')

        # Checking if at least half a second has elapsed since the last
        # average calculation. Running stats off the raw reads seems to
        # result in largely overblown speeds?
        if duration >= 0.5:

            # It has - obtaining hashedData during the interval
            hashedData = (currentHashingTask['dataHashed'] -
                          currentHashingTask['lastUpdatedDataHashed'])

            # Updating recorded speeds
            if (currentHashingTask['lastUpdatedSpeed'] == 0 or
            currentHashingTask['lastUpdatedSpeed'] == 4):

                # No speed yet recorded or the records have looped
                currentHashingTask['speed1'] = hashedData / duration
                currentHashingTask['lastUpdatedSpeed'] = 1

            elif currentHashingTask['lastUpdatedSpeed'] == 1:
                currentHashingTask['speed2'] = hashedData / duration
                currentHashingTask['lastUpdatedSpeed'] = 2

            elif currentHashingTask['lastUpdatedSpeed'] == 2:
                currentHashingTask['speed3'] = hashedData / duration
                currentHashingTask['lastUpdatedSpeed'] = 3

            elif currentHashingTask['lastUpdatedSpeed'] == 3:
                currentHashingTask['speed4'] = hashedData / duration
                currentHashingTask['lastUpdatedSpeed'] = 4

            # Updating lastUpdatedTime and lastUpdatedDataHashed
            currentHashingTask['lastUpdatedTime'] = time.time()
            currentHashingTask['lastUpdatedDataHashed'] = currentHashingTask['dataHashed']

            # Determining average speed
            # Creating a list of the speeds
            speedList = [currentHashingTask['speed1'],
                         currentHashingTask['speed2'],
                         currentHashingTask['speed3'],
                         currentHashingTask['speed4']]

            # Calculating the average speed. Denominator works as a speed has
            # not been recorded if it is '' - cant use a truth test as 0 may
            # be a valid result
            speedSum = sum([speed for speed in speedList if speed != ''])
            records = sum([1 for speed in speedList if speed != ''])
            if records:
                averageSpeed = humanise_bytes(speedSum / records) + "/Sec"
            else:
                averageSpeed = '0B/Sec'

            # Updating terminal - print digit in 7 character field with right
            # justification
            if fileSize > 0:
                sys.stdout.write('%7d%% %s%s' % (hashedSoFar * 100 / fileSize,
                                                 averageSpeed, P_RESET))
            else:
                sys.stdout.write('%7d%% %s%s' % (100, averageSpeed, P_RESET))
            sys.stdout.flush()

    elif fileHashed != False:

        # Updating file counts
        currentHashingTask['filesToHash'] -= 1
        currentHashingTask['filesHashed'] += 1

        # Resetting lastUpdatedTime
        currentHashingTask['lastUpdatedTime'] = time.time()

    else:

        # Function has been called without valid parameters - raising error
        raise Exception('currentHashingTask_update was called with either no '
                        'parameters or default parameters')


def currentHashingTask_error(e):
    '''Registers an error with the current hashing task record'''

    # Persisting currentHashingTask changes
    global currentHashingTask

    # Dealing with various errors
    if isinstance(e, IOError) and e.errno == 2:

        # File not found error
        currentHashingTask['errorFileNotFoundCount'] += 1

    else:

        # Any other error - not aware of details yet
        currentHashingTask['errorOtherCount'] += 1


def currentHashingTask_file_corrupt(corruptFile):
    '''Registers a corrupt file with the current hashing task record'''

    # Persisting currentHashingTask changes
    global currentHashingTask

    # Updating corrupt file count
    currentHashingTask['corruptFileCount'] += 1


def currentHashingTask_file_no_hash(noHashFile):
    '''Registers a file with no hash information with the current hashing task
    record'''

    # Persisting currentHashingTask changes
    global currentHashingTask

    # Updating no hash file count
    currentHashingTask['noHashFileCount'] += 1


def currentHashingTask_summary():
    '''Generates a summary of the completed current hashing task'''

    # Obtaining stats to display
    notFoundCount = currentHashingTask['errorFileNotFoundCount']
    otherErrorCount = currentHashingTask['errorOtherCount']
    fileCount = (currentHashingTask['filesHashed'] + notFoundCount +
                 otherErrorCount)
    filesDescription = 'files' if fileCount > 1 else 'file'
    corruptCount = currentHashingTask['corruptFileCount']
    noHashCount = currentHashingTask['noHashFileCount']
    successCount = (currentHashingTask['filesHashed'] - corruptCount -
                    noHashCount)
    started = currentHashingTask['hashStartTime']
    finished = time.time()
    elapsed = timedelta(seconds=(finished - started))
    dataHashed = humanise_bytes(currentHashingTask['dataHashed'])
    averageSpeed = humanise_bytes(currentHashingTask['dataHashed'] /
                                  elapsed.total_seconds())

    # Displaying summary of hashing task
    print('\nHashing task complete: %d %s, %d not found, %d other error, %d'
          ' corrupt, %d no hash, %d hashed successfully' % (fileCount,
                                                            filesDescription,
                                                            notFoundCount,
                                                            otherErrorCount,
                                                            corruptCount,
                                                            noHashCount,
                                                            successCount))
    print('Started %s, finished %s, elapsed %s, %s hashed (%s/Sec)\n'
          % (get_date(started), get_date(finished), elapsed, dataHashed,
             averageSpeed))

    # Alerting user to the fact listing errors have happened - otherwise the
    # potential 0 errors reported above is a lie
    if listingError:
        sys.stderr.write('WARNING: Some directories/files were not hashed due '
                         'to failures in the initial discovery stage - please '
                         'see errors noted before hashing started\n\n')


def crc32_hash_mode(files):
    '''CRC32 hashes passed files and displays results'''

    # Converting potential passed directories into their nested files
    files = recursive_file_search(files)

    # Initialising hashing task (files are the leftover arguments from the
    # OptionParser processing)
    currentHashingTask_initialise(files)

    # Looping through files to process
    for fileToHash in files:
        try:

            # Hashing file
            crc = crc32_checksum(fileToHash)

            # Updating hashing task
            currentHashingTask_update(fileHashed=True)

            # Displaying results
            display_results(fileToHash, crc)

        except Exception as e:  # pylint: disable=W0703

            # Informing user
            sys.stderr.write('\nFailed to hash the file \'%s\':\n\n%s\n\n%s\n'
                             % (fileToHash, e, traceback.format_exc()))

            # Registering error and moving to next file
            currentHashingTask_error(e)
            continue

    # Displaying a summary of the hashing task's progress - also adds a note
    # about listing errors
    currentHashingTask_summary()

    # If files without hashes exist and the add hash mode is 'ask', proceeding
    # only if the user wants to
    if (len(addHashModeFiles) > 0
        and options.addHashMode == 'ask'
        and input('Do you want to add CRC32 hashes to the filenames of files'
        ' without them (Y/n)? ').lower() == 'n'):
        print('Hashes will not be added to files without them')
        sys.exit()

    # Looping for all files that need a hash adding to - this will only be
    # populated if the addHashMode is not 'none'
    for hashedFile in addHashModeFiles:

        try:

            # Obtaining file name and file extension
            (filePath, fileName) = os.path.split(hashedFile[0])
            (fileName, fileExtension) = os.path.splitext(fileName)

            # Renaming file with the hash (note that the hash does not end up
            # before the first fullstop in a filename - however my usage will
            # not include files with more than one fullstop
            filePath = (os.path.join(filePath, addHashFormat.format(
                        name=fileName,
                        hash=hashedFile[1]) + fileExtension))
            shutil.move(hashedFile[0], filePath)

        except Exception as e:  # pylint: disable=W0703
            sys.stderr.write('Addition of CRC32 hash \'%s\' to the filename of'
                             ' \'%s\' failed:\n\n%s\n\n%s\n'
                             % (crc, hashedFile[0], e,
                                traceback.format_exc()))
            continue


def md5_hash_mode(files):
    '''Displays md5 hashes of passed files'''

    # Converting potential passed directories into their nested files
    files = recursive_file_search(files)

    # Initialising hashing task
    currentHashingTask_initialise(files)

    # Generating md5 hashes for all passed files
    for fileToHash in files:
        try:
            print(fileToHash, md5_checksum(fileToHash))

        except Exception as e:  # pylint: disable=W0703

            # Informing user
            sys.stderr.write('\nFailed to generate an md5 hash for the file '
                             '\'%s\':\n\n%s\n\n%s\n' %
                             (fileToHash, e, traceback.format_exc()))

            # Registering error and moving to next file
            currentHashingTask_error(e)
            continue


def check_sfv_file(checksumFile):
    '''CRC32 hashes files described in the checksum file and displays
    results'''

    # Initialising variables
    # List used here as I want to preserve the file-based order
    files = []

    try:

        # Opening file, resulting in usable text regardless of original
        # encoding
        fileData = open_file(checksumFile)

        # Looping through all lines
        for line in fileData:

            # Ignoring comments
            if line[0] != ';':

                # Extracting hash (last 'word' on line) and the file to hash.
                # Regex is used as basic splitting on space screws up when
                # there are contiguous spaces. As a capturing group is at the
                # start, '' is returned in 0
                match = re.split(r'^(.*)\s+([a-f0-9]{8})$', line,
                                flags=re.IGNORECASE)
                path, checksumFileCRC = match[1], match[2]

                # Coping with nested directories in the path depending on
                # platform
                if os.name == 'posix':
                    path = path.replace('\\', '/')
                elif os.name == 'nt':
                    path = path.replace('/', '\\')

                # Constructing full path to hash and adding it to the list
                files.append([os.path.join(os.path.dirname(checksumFile),
                                          path), checksumFileCRC])

        # Lines processed - initialising hashing task
        currentHashingTask_initialise([fileToHash[0] for fileToHash in files])

        # Looping through files to process
        for fileToHash, checksumFileCRC in files:
            try:

                # Hashing file
                crc = crc32_checksum(fileToHash)

                # Updating hashing task
                currentHashingTask_update(fileHashed=True)

                # Displaying results
                display_results(fileToHash, crc, checksumFileCRC)

            # Capturing I/O errors to detect missing files
            except IOError as e:

                # Checking if the error relates to a missing file
                if e.errno == 2:

                    # It is - reporting the missing file concisely
                    sys.stderr.write('Failed to hash \'%s\' - file does not '
                                     'exist!\n' % fileToHash)

                else:

                    # It doesn't - treating as a normal unknown error
                    sys.stderr.write('Failed to hash \'%s\':\n\n%s\n\n%s\n' %
                                     (fileToHash, e, traceback.format_exc()))

                # Registering error and moving to next file
                currentHashingTask_error(e)
                continue

            # Capturing unknown errors
            except Exception as e:  # pylint: disable=W0703

                # Informing user
                sys.stderr.write('Failed to hash \'%s\':\n\n%s\n\n%s\n' %
                                 (fileToHash, e, traceback.format_exc()))

                # Registering error and moving to next file
                currentHashingTask_error(e)
                continue

        # Displaying a summary of the hashing task's progress
        currentHashingTask_summary()

    except Exception as e:  # pylint: disable=W0703
        sys.stderr.write('Failed to process the checksum file \'%s\':\n\n%s\n'
                         '\n%s\n' % (checksumFile, e, traceback.format_exc()))


def check_md5_file(checksumFile):
    '''MD5 hashes files described in the checksum file and displays results'''

    # Initialising variables
    # List used here as I want to preserve the file-based order
    files = []

    try:

        # Opening file, resulting in usable text regardless of original
        # encoding
        fileData = open_file(checksumFile)

        # Looping through all lines
        for line in fileData:

            # Ignoring comments
            if line[0] != ';':

                # Extracting hash (last 'word' on line) and the file to hash.
                # '*' preceeding the filename indicates the file was read in
                # binary/text mode, and therefore isnt always present. Regex
                # is used as basic splitting on space screws up when there are
                # contiguous spaces. As a capturing group is at the start, ''
                # is returned in 0
                match = re.split(r'^([a-f0-9]{32})\s+\*?(.+)$', line,
                                flags=re.IGNORECASE)
                path, checksumFileMD5 = match[2], match[1]

                # Coping with nested directories in the path depending on
                # platform
                if os.name == 'posix':
                    path = path.replace('\\', '/')
                elif os.name == 'nt':
                    path = path.replace('/', '\\')

                # Constructing full path to hash and adding it to the list
                files.append([os.path.join(os.path.dirname(checksumFile),
                                          path), checksumFileMD5])

        # Lines processed - initialising hashing task
        currentHashingTask_initialise([fileToHash[0] for fileToHash in files])

        # Looping through files to process
        for fileToHash, checksumFileMD5 in files:
            try:

                # Hashing file
                md5 = md5_checksum(fileToHash)

                # Updating hashing task
                currentHashingTask_update(fileHashed=True)

                # Displaying results
                display_results(fileToHash, md5, checksumFileMD5)

            # Capturing I/O errors to detect missing files
            except IOError as e:

                # Checking if the error relates to a missing file
                if e.errno == 2:

                    # It is - reporting the missing file concisely
                    sys.stderr.write('Failed to hash \'%s\' - file does not '
                                     'exist!\n' % fileToHash)

                else:

                    # It doesn't - treating as a normal unknown error
                    sys.stderr.write('Failed to hash \'%s\':\n\n%s\n\n%s\n' %
                                     (fileToHash, e, traceback.format_exc()))

                # Registering error and moving to next file
                currentHashingTask_error(e)
                continue

            # Capturing unknown errors
            except Exception as e:  # pylint: disable=W0703

                # Informing user
                sys.stderr.write('Failed to hash \'%s\':\n\n%s\n\n%s\n' %
                                 (fileToHash, e, traceback.format_exc()))

                # Registering error and moving to next file
                currentHashingTask_error(e)
                continue

        # Displaying a summary of the hashing task's progress
        currentHashingTask_summary()

    except Exception as e:  # pylint: disable=W0703
        sys.stderr.write('Failed to process the checksum file \'%s\':\n\n%s\n'
                         '\n%s\n' % (checksumFile, e, traceback.format_exc()))


def checksum_read_mode(files):
    '''Processes any checksum files present in the passed files'''

    # Initialising variables
    fileProcessed = False

    # Looping for all files passed to detect checksum files and then calling
    # the relevant procedure
    for passedFile in files:
        extension = os.path.splitext(passedFile)[1]

        if extension == '.md5':
            print('\nProcessing \'' + passedFile + '\'...\n')
            check_md5_file(passedFile)
            fileProcessed = True

        if extension == '.sfv':
            print('\nProcessing \'' + passedFile + '\'...\n')
            check_sfv_file(passedFile)
            fileProcessed = True

    # Warning user if no valid files have been detected
    if not fileProcessed:
        print('No valid checksum files have been detected!\n')


def md5_create_mode(files):
    '''Creates an md5 checksum file based off passed files'''

    # Initialising variables - checksumFileOutput is used in error handler
    checksumFile = None
    errorOccurred = False
    checksumFileOutput = None

    try:

        # Converting potential passed directories into their nested files
        files = recursive_file_search(files)

        # Normalising and validating passed files
        files, commonPrefix = normalise_and_validate_files(files, 'md5')

        # Debug code
        #print commonPrefix
        #print os.path.basename(commonPrefix[:-1])

        # Setting checksumFileOutput. Basename implementation is broken,
        # removing trailing os.sep to make it work...
        if options.checksumOutput:
            checksumFileOutput = options.checksumOutput
        else:
            checksumFileOutput = (commonPrefix + os.sep +
            os.path.basename(commonPrefix) + '.md5')

        # User feedback
        print('\nGenerating \'%s\'...\n' % checksumFileOutput)

        # Writing out header to checksum file
        with io.open(checksumFileOutput, 'w') as checksumFile:
            checksumFile.writelines('; Generated by %s v%s on %s' %
                (os.path.split(sys.argv[0])[1], VERSION,
                datetime.now().isoformat() + '\n;\n'))

            # Initialising hashing task
            currentHashingTask_initialise(files)

            # Looping for all files to hash
            for fileToHash in files:

                # Removing common root directory from file path (first item in
                # the list will be empty). Removing directory slash as needed
                relativePath = fileToHash.split(commonPrefix)[1]
                if relativePath[:1] == os.sep:
                    relativePath = relativePath[1:]

                try:

                    # Obtaining file hash
                    fileHash = md5_checksum(fileToHash)

                    # Updating hashing task
                    currentHashingTask_update(fileHashed=True)

                    # Giving user feedback
                    display_results(fileToHash, fileHash,
                                    checksumFileGeneration=True)

                except Exception as e:  # pylint: disable=W0703

                    # Informing user
                    sys.stderr.write('Failed to hash \'%s\':\n\n%s\n' %
                                     (fileToHash, e))

                    # Recording error in checksum file so that the user is in
                    # no doubt that the resulting checksum file contains this
                    # issue
                    checksumFile.writelines(['; \'%s\' occurred whilst hashing'
                                             ' the below file:\n' % e,
                                             '00000000000000000000000000000000'
                                             + ' *' + relativePath + '\n'])

                    # Registering error and moving to next file
                    currentHashingTask_error(e)
                    errorOccurred = True
                    continue

                # Writing out file record, '*' indicates the hash is from a
                # binary mode read
                checksumFile.write(fileHash + ' *' + relativePath + '\n')

        # Reporting to the user on the success of writing the checksum file
        if errorOccurred == False:
            print('\nChecksum file \'' + checksumFileOutput + '\' has been '
                  'written successfully')
        else:
            sys.stderr.write('\nWARNING: Checksum file \'%s\' has not been '
                             'written successfully! See above for errors\n'
                             % checksumFileOutput)

        # Displaying a summary of the hashing task's progress
        currentHashingTask_summary()

    except Exception as e:  # pylint: disable=W0703
        sys.stderr.write('Failed to write to the checksum file \'%s\':\n\n%s'
                         '\n\n%s\n' % (checksumFileOutput, e,
                                       traceback.format_exc()))
        sys.exit(1)


def sfv_create_mode(files):
    '''Creates an sfv checksum file based off passed files'''

    # Initialising variables - checksumFileOutput is used in error handler
    checksumFile = None
    errorOccurred = False
    checksumFileOutput = None

    try:

        # Converting potential passed directories into their nested files
        files = recursive_file_search(files)

        # Normalising and validating passed files
        files, commonPrefix = normalise_and_validate_files(files, 'sfv')

        # Debug code
        #print(type(commonPrefix))
        #print(type(files))

        # Setting checksumFileOutput. Basename implementation is broken,
        # removing trailing os.sep to make it work...
        if options.checksumOutput:
            checksumFileOutput = options.checksumOutput
        else:
            checksumFileOutput = (commonPrefix + os.sep +
            os.path.basename(commonPrefix) + '.sfv')

        # User feedback
        print('\nGenerating \'%s\'...\n' % checksumFileOutput)

        # Writing out header to checksum file
        with io.open(checksumFileOutput, 'w') as checksumFile:
            checksumFile.writelines('; Generated by %s v%s on %s' %
                (os.path.split(sys.argv[0])[1], VERSION,
                datetime.now().isoformat() + '\n;\n'))

            # Initialising hashing task
            currentHashingTask_initialise(files)

            # Looping for all files to hash
            for fileToHash in files:

                # Removing common root directory from file path (first item in
                # the list will be empty). Removing directory slash as needed
                relativePath = fileToHash.split(commonPrefix)[1]
                if relativePath[:1] == os.sep:
                    relativePath = relativePath[1:]

                try:

                    # Obtaining file hash
                    fileHash = crc32_checksum(fileToHash)

                    # Updating hashing task
                    currentHashingTask_update(fileHashed=True)

                    # Giving user feedback
                    display_results(fileToHash, fileHash,
                                    checksumFileGeneration=True)

                except Exception as e:  # pylint: disable=W0703

                    # Informing user
                    sys.stderr.write('Failed to hash \'%s\':\n\n%s\n' %
                                     (fileToHash, e))

                    # Recording error in checksum file so that the user is in
                    # no doubt that the resulting checksum file contains this
                    # issue
                    checksumFile.writelines(['; \'%s\' occurred whilst hashing'
                                             ' the below file:\n' %
                                             e, relativePath + ' 00000000\n'])

                    # Registering error and moving to next file
                    currentHashingTask_error(e)
                    errorOccurred = True
                    continue

                # Writing out file record
                checksumFile.write(relativePath + ' ' + fileHash + '\n')

        # Reporting to the user on the success of writing the checksum file
        if errorOccurred == False:
            print('\nChecksum file \'' + checksumFileOutput + '\' has been '
                  'written successfully')
        else:
            print('\nWarning! Checksum file \'' + checksumFileOutput + '\' has'
                  ' not been written successfully! See above for errors')

        # Displaying a summary of the hashing task's progress
        currentHashingTask_summary()

    except Exception as e:  # pylint: disable=W0703
        sys.stderr.write('Failed to write to the checksum file \'%s\':\n\n%s\n'
                         '\n%s\n'
                         % (checksumFileOutput, e, traceback.format_exc()))
        sys.exit(1)


def ed2k_link_mode(files):
    '''Displays eD2k links of passed files'''

    # Converting potential passed directories into their nested files
    files = recursive_file_search(files)

    # Initialising hashing task
    currentHashingTask_initialise(files)

    # Generating eD2k links for all passed files
    for fileToHash in files:
        try:
            print(ed2k_link(fileToHash))

        except Exception as e:  # pylint: disable=W0703

            # Informing user
            sys.stderr.write('\nFailed to generate an eD2k link for the file '
                             '\'%s\':\n\n%s\n\n%s\n'
                             % (fileToHash, e, traceback.format_exc()))

            # Registering error and moving to next file
            currentHashingTask_error(e)
            continue


# Configuring and parsing passed options
parser = OptionParser(version=('%%prog %s%s' % (VERSION, GPL_NOTICE)))
parser.add_option('-a', '--add-hash-mode', dest='addHashMode', help='mode to '
'define when a CRC32 hash is added to a filename where none has been found. '
'Defaults to \'none\', \'ask\' prompts the user after hashing and \'always\' '
'causes the hash to automatically be added when missing',
metavar='addHashMode', choices=('none', 'ask', 'always'), default='none')
parser.add_option('-c', '--checksum-read-mode', dest='checksum_read_mode',
help='mode to look for checksum files and then hash the files as \
described within. All files passed are searched for recognised checksum files'
' (others are ignored) and processed in order of discovery',
metavar='checksumMode', action='store_true', default=False)
parser.add_option('-e', '--ed2k-link-mode', dest='ed2k_link_mode',
help='mode to hash given files and output eD2k links',
metavar='checksumMode', action='store_true', default=False)
parser.add_option('-m', '--md5-create-mode', dest='md5_create_mode',
help='mode to create an md5 file from the files passed - see -o',
metavar='md5_create_mode', action='store_true', default=False)
parser.add_option('-M', '--md5-hash-mode', dest='md5_hash_mode',
help='mode to hash given files and output md5 hashes',
metavar='md5_hash_mode', action='store_true', default=False)
parser.add_option('-o', '--checksum-output', dest='checksumOutput',
help='path to output checksum file to (only valid in checksum file creation '
'modes). If omitted, the file is output to the hashed files\' common root '
'directory', metavar='checksumOutput', default=None)
parser.add_option('-s', '--sfv-create-mode', dest='sfv_create_mode',
help='mode to create an sfv file from the files passed - see -o',
metavar='sfv_create_mode', action='store_true', default=False)
(options, args) = parser.parse_args()

# Validating options
# Ensuring no other modes are enabled when add-hash-mode is
if (options.addHashMode != 'none'
    and (options.checksum_read_mode
    or options.md5_create_mode
    or options.md5_hash_mode
    or options.sfv_create_mode
    or options.ed2k_link_mode)):
    sys.stderr.write(parser.get_usage() + '\nadd-hash-mode can only be used \
when no other modes are enabled\n')
    sys.exit(1)

# Ensuring one mode is enabled at one time
if (options.checksum_read_mode + options.sfv_create_mode +
    options.md5_create_mode + options.md5_hash_mode +
    options.ed2k_link_mode) > 1:
    sys.stderr.write(parser.get_usage() + '\nOnly one mode can be enabled at '
                     'once\n')
    sys.exit(1)

# cfv cannot cope even with opening rapidcrc mod files, let alone intelligently
# dealing with Windows-based nested directory structures inside - dropping
# Ensuring cfv is available if a relevant mode has been requested
#if (options.checksum_read_mode + options.sfv_create_mode +
#options.md5_create_mode) > 0:
#    try:
#        # Quashing stdout and stderr (Python 3.3 allows you to do this
#        # properly...)
#        subprocess.call('cfv --version', stdout=open(os.devnull, 'w'), \
#                        stderr=subprocess.STDOUT)
#
#    except (Exception) as e:
#        sys.stderr.write('%s\nA cfv mode was requested, however the following'
#                        ' error occurred when testing to see if cfv is '
#                        'installed:\n\n%s\n\n' % (parser.get_usage(), e))
#        sys.exit(1)

# Dealing with various modes to run
if options.checksum_read_mode:
    checksum_read_mode(args)

elif options.md5_create_mode:
    md5_create_mode(args)

elif options.md5_hash_mode:
    md5_hash_mode(args)

elif options.sfv_create_mode:
    sfv_create_mode(args)

elif options.ed2k_link_mode:
    ed2k_link_mode(args)

elif not args:

    # Optparse does not properly deal with no arguments, so this needs to be
    # manually handled
    parser.print_help()

else:

    # Normal CRC32 hashing needed
    crc32_hash_mode(args)


# Possible future improvement: How do I get a permanent line at the bottom
# representing general progress + speed? Print permanently prints to the
# screen, sys.stdout.write with backspaces is transient.
# <speed MB/Sec> <files to go /MB/GB>
