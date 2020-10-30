round=`expr $1 - 1`
for i in `seq 1 1 $round`; do
	python3 client.py $2 &
done
python3 client.py $2

