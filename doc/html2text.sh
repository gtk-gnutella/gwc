# !/bin/sh
sed 's/<[^>]*>//g; s/\&[a-zA-Z]*;//g; s/^[ \t]*$//g' readme.html|uniq
