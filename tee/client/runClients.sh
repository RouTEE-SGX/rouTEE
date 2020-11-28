# AddUser
# DepositReq
# DepositTx
# Payment <- loop
# SettleReq <- Optional

python3 client.py < scripts/signedAddUser signed
python3 client.py < scripts/signedDepositReq signed
python3 client.py < scripts/signedDepositTx signed

round=`expr $1 - 1`
for i in `seq 1 1 $round`; do
	python3 client.py < scripts/signedPayment signed &
done
python3 client.py < scripts/signedPayment signed

# python3 client.py < scripts/signedSettleReq signed
