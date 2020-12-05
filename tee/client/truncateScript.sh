# $1: name
# $2: line number what you want to truncate

tail=$2
sed -n "1, $tail p" scripts/$1 > scripts/truncated_$1
