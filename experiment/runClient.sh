#!/bin/bash

#
# rouTEE evaluation script
# run docker image for rouTEE & run this script anywhere you want
#

# get input
echo ""
read -p "how many users: " userNumber
read -p "how many payments per client: " paymentNumber
read -p "how many clients: " clientNumber
echo ""

# make create channels script
echo "Making scripts..."
docker exec -it routee bash -c "cd && cd rouTEE/tee/client/scripts && python3 makeScript.py 1 ${userNumber} scc${userNumber}"

# make random payments scripts concurrently
RANGE=$(seq 1 ${clientNumber})
makeScriptCmd=""
for i in $RANGE
do
	makeScriptCmd="${makeScriptCmd} cd && cd rouTEE/tee/client/scripts && python3 makeScript.py 2 ${paymentNumber} ${userNumber} sp${userNumber}_${paymentNumber}_$i &"
done
makeScriptCmd=${makeScriptCmd% *&} # cut out string " &" at the last
docker exec -it routee bash -c "${makeScriptCmd}"

# run create channels script & save log
docker exec -it routee bash -c "cd && cd rouTEE/tee/client && python3 client.py scc${userNumber} > resultLogs/scc${userNumber}"

# run random payments scripts concurrently & save log
paymentCmd=""
for i in $RANGE
do
	scriptName="sp${userNumber}_${paymentNumber}_$i"
	paymentCmd="${paymentCmd} cd && cd rouTEE/tee/client && python3 client.py ${scriptName} > resultLogs/${scriptName} &"
done
paymentCmd=${paymentCmd% *&} # cut out string " &" at the last
echo "\nRunning payment scripts..."
docker exec -it routee bash -c "${paymentCmd}"

echo "\nAll Done!\n"
