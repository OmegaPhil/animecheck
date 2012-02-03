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

import os, re, shutil, sys, zlib
from optparse import OptionParser

# Variable declaration
addHashModeFiles = []

# Defining terminal escape codes
c_null = "\x1b[00;00m"
c_red = "\x1b[31;01m"
c_green = "\x1b[32;01m"
p_reset = "\x08"*8

def crc32_checksum(filename):

    # Variable allocation
    crc = 0
    done = 0
    
    # Opening file to hash, buffer is large presumably to ensure its read in fast
    file = open(filename, "rb")
    buff_size = 65536
    size = os.path.getsize(filename)
    
    try:
        while True:
	    
            # Reading in a chunk of the data and updating the terminal
            data = file.read(buff_size)
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
        file.close()
        sys.exit(1)
    
    # Clearing up terminal and file
    sys.stdout.write(p_reset)
    file.close()
    
    # If the crc hex value is negative, bitwise and it with the maximum 32bit value. Apparently this is a 'bit mask' resulting in a 32bit long value (rather than an infinitely long value, see http://stackoverflow.com/a/7825412). It is also guaranteed to return a positive number
    if crc < 0:
        crc &= 2 ** 32 - 1
        
    # Return 8-digit precision decimal hex integer in uppercase
    return "%.8X" % (crc)

# Configuring and parsing passed options
parser = OptionParser()
parser.add_option('-a', '--add-hash-mode', dest='addHashMode', help='mode to define when a CRC32 hash is added to a filename where none has been found. Defaults to \'none\', \'ask\' prompts the user after hashing and \'always\' causes the hash to automatically be added when missing', metavar='addHashMode', choices=('none', 'ask', 'always'), default='none')
(options, args) = parser.parse_args()

# Debug code
#print(args))

# Looping for all passed files - these are left over in args after the options have been processed
for file in args:
    try:
        
        # Hashing file
        crc = crc32_checksum(file)
        
        # Obtaining the hash from the filename (penultimate fragment) - remember that re does not support POSIX character classes
        dest_sum = re.split("([a-fA-F0-9]{8})", file)[-2]
        
        # Setting colours depending on good/bad hash
        if crc == dest_sum.upper():
            c_in = c_green
        else:
            c_in = c_red
        
        # Obtaining a list of the filename before and after the hash
        sfile = file.split(dest_sum)
        
        # Printing results with coloured hash at the beginning and in the file path
        print("%s%s%s   %s%s%s%s%s" % (c_in, crc, c_null, sfile[0], c_in, dest_sum, c_null, sfile[1]))
    
    except(IndexError, ValueError):
        
        # No CRC32 has been found - outputting calculated value and file path
        print("%s   %s" % (crc, file))
        
        # If hashes are to be added to filenames, adding to the list
        if options.addHashMode != 'none':
            hashedFile = [file, crc]
            addHashModeFiles.append(hashedFile)

    except(IOError) as e:
        sys.stderr.write(e)
        continue

# If files without hashes exist and the add hash mode is 'ask', proceeding only if the user wants to
if len(addHashModeFiles) > 0 and options.addHashMode == 'ask' and raw_input('\nDo you want to add CRC32 hashes to the filenames of files without them (y/n)?').lower() != 'y':
    print('Hashes will not be added to files without them')
    sys.exit()
    
# Looping for all files that need a hash adding to
for hashedFile in addHashModeFiles:
        
    try:
        
        # Obtaining file name and file extension
        (filePath, fileName) = os.path.split(hashedFile[0])
        (fileName, fileExtension) = os.path.splitext(fileName)
        
        # Renaming file with the hash (note that the hash does not end up before the first fullstop in a filename - however my usage will not include files with more than one fullstop
        filePath = os.path.join(filePath, fileName + ' [' + hashedFile[1] + ']' + fileExtension)
        shutil.move(hashedFile[0], filePath)
    
    except(Error) as e:
        sys.stderr.write('Addition of CRC32 hash \'%s\' to the filename of \'%s\' failed: %s' % (crc, file, e))
        continue

# TODO: Extend with sfv and md5 file parsing via cfv, including creation
# TODO: Add ed2k hashing if possible?