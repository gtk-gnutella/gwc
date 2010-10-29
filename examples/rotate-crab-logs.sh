#! /bin/sh

# This is the assumed location of the log files
cd "$HOME/logs" || exit

# Use the hour to have a unique name for one day
stamp=$(LC_ALL=C date '+%H') || exit

# We assume the log files are all in the same directory and use a common
# suffix ".log" and have otherwise the following names:
files="access alert checks dns main uhc"

# Remove the old log files (one day old) if they exist and move the
# current log files.
for f in ${files}; do
	rm -f "${f}-${stamp}.log.gz"
	mv "${f}.log" "${f}-${stamp}.log"
done

# Send a SIGHUP to the gwc process(es) so that they reopen their log files.
pkill -HUP gwc

# Compress the moved log files
for f in ${files}; do
	gzip -9 "${f}-${stamp}.log"
done

exit
