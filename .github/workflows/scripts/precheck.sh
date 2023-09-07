#!/usr/bin/env bash

# Check trailing whitespaces
files=$(find . -type f \
    -not -path "./.git/*" \
    -not -path "*/.gradle/*" \
    -not -path "*/build/*" \
    -not -name "*.jar" \
    -exec egrep -l " +$" {} \;)

count=0
for file in $files; do
    ((count++))
    echo "$file"
done

if [ $count -ne 0 ]; then
    echo "Error: trailing whitespace(s) in the above $count file(s)"
    exit 1
fi
