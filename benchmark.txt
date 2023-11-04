#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <depth> <filepath> <baseline_file>"
  exit 1
fi

depth="$1"
filepath="$2"
baseline_file="$3"

if [ ! -e "$filepath" ]; then
  echo "Error: The specified path does not exist."
  exit 1
fi

# Check if the baseline file exists
if [ ! -e "$baseline_file" ]; then
  echo "Error: The specified baseline file does not exist."
  exit 1
fi

# Function to check if a set of attributes exists in the baseline file
attributes_exist_in_baseline() {
  local attributes="$1"
  local baseline_file="$2"

  if grep -q "^$attributes" "$baseline_file"; then
    return 0  # Attributes exist in the baseline file
  else
    return 1  # Attributes not found in the baseline file
  fi
}

# Function to benchmark a file or folder
benchmark_path() {
  local path="$1"
  local current_depth="$2"

  # Check if the path is /tmp, /proc, or /dev and skip them
  if [[ "$path" == "/tmp" || "$path" == "/proc" || "$path" == "/dev" ]]; then
    return
  fi

  # Get the attributes of the path (including SUID bit)
  local attributes="$(stat -c %A "$path")"

  # Get the owner of the path
  local owner="$(stat -c %U "$path")"

  # Initialize checksum for files
  local checksum=""

  # Initialize file size for folders
  local file_size=""

  # Check if the path is a file and has a size less than 1MB, then calculate the MD5 checksum
  if [ -f "$path" ]; then
    local file_size=$(stat -c %s "$path")
    if [ $file_size -le 1048576 ]; then  # 1MB = 1048576 bytes
      checksum="$(md5sum "$path" | cut -d' ' -f1)"
    fi
  elif [ -d "$path" ]; then
    file_size=$(du -s "$path" | cut -f1)
  fi

  # Get lsattr for the path
  local lsattr="$(lsattr -d "$path" | awk '{ print $1 }')"

  # Print the path, owner, attributes (including SUID bit), checksum (for files), file size (for folders), and lsattr to "out.txt"
  echo "$path,$owner,$attributes,$checksum,$file_size,$lsattr" >> out.txt

  # Combine all attributes to check in the baseline file
  local all_attributes="$path,$owner,$attributes,$checksum,$file_size,$lsattr"

  # Check if the path does not exist in the baseline file or if all attributes exist in the baseline
  if ! grep -q "^$path" "$baseline_file" || attributes_exist_in_baseline "$all_attributes" "$baseline_file"; then
    return
  fi

  # If depth is greater than 0 and the path is a directory, traverse its content
  if [ "$current_depth" -lt "$depth" ] && [ -d "$path" ]; then
    find "$path" -maxdepth 1 | while read -r subpath; do
      if [ "$subpath" != "$path" ]; then
        benchmark_path "$subpath" "$((current_depth + 1))"
      fi
    done
  fi
}

# Create or overwrite "out.txt" file
> out.txt

benchmark_path "$filepath" 0

echo "Benchmarking completed. Results are saved in out.txt."
