#!/bin/bash

# Accepts the following arguments: the first argument is a full path to a
# file (including filename) on the filesystem, referred to below as
# writefile; the second argument is a text string which will be written
# within this file, referred to below as writestr

# Exits with value 1 error and print statements if any of the arguments
# above were not specified
if [ $# -ne 2 ]; then
	echo "Usage - ./writer.sh writefile writestr"
	exit 1
fi

# Creates a new file with name and path writefile with content writestr,
# overwriting any existing file and creating the path if it doesn’t exist.
# Exits with value 1 and error print statement if the file could not be
# created.

test -d $(dirname $1) || mkdir -p $(dirname $1)

echo $2 > $1

if [ $? -ne 0 ]; then
	echo "Failed to write to the file $1"
	exit 1
fi

exit 0
