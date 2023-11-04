#!/bin/bash

# Run dpkg -l and filter package names with awk
dpkg -l | awk '$1 == "ii" { print $2 }' > installed_packages.txt

echo "Installed package names recorded in installed_packages.txt"
