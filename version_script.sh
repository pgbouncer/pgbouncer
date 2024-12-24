git_hash=$(git describe --always --abbrev=5 --exclude "*" || echo unknown)
numeric_version="1.23.1"
if [[ $git_hash == "unknown" ]]; then
  printf $numeric_version
else
  printf $numeric_version-$git_hash
fi
