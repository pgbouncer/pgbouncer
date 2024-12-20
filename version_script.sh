echo 1.23.1-$(git describe --always --abbrev=5 --exclude "*" || echo "unknown" )
