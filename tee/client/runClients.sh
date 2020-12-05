# $1: name
# $2: start
# $3: end

start=`expr $2 + 1`
round=`expr $3 - 1`
for i in `seq $start 1 $round`; do
	# echo $i
	python3 client.py < scripts/$1$i signed &
done
python3 client.py < scripts/$1$2 signed
