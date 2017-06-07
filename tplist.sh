#!/bin/sh

sed -i 's/^template_[0-9]*=//g' $1
grep ".*auth.*type.*disabled.*hidden" $1 >/dev/null 2>&1

if [ $? -eq 1 ];then
	sed -i 's/$/&|auth=0|type=0|disabled=0|hidden=0/g' $1
fi

sync
