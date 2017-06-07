local sproto = require "sprotoparser"

local sp = sproto.parse [[
.package {
	type 				0 : integer
	session 			1 : integer
}

status 1 {
	request {
		apstatus   		0  : integer
		stanum 			1  : integer
		hver 			2  : string
		sver 			3  : string
		mac  			4  : string
		sn 	 			5  : string
		aip  			6  : string
		.sta{
			stamac 		0  : string
		}
		smac 			7  : *sta
		model 			8  : string
	}
	response {
		ok 				0  : boolean
	}
}

info 2 {
	request {
		ssid       		0  : string
		channel  		1  : string
		encrypt 		2  : string
		key 			3  : string
		txpower 		4  : string
		aip 			5  : string
		type 			6  : string
		hidden 			7  : string
		disabled		8  : string
	}
	response {
		ok 				0 : boolean
	}
}

cmd 3 {
	request {
		apcmd      		0  : integer
		addr 			1  : string
		md5 			2  : string
	}
	response {
		ok 				0 : boolean
	}
}

sta_info 4 {
	request {
	     sta_mac 		0: 	string
	     sta_bssid 		1:	string
	     sta_status 	2: 	integer
	     sta_ssid 		3: 	string
		 sta_type 		4:	integer
		 sta_ap_mac 	5:	string
	}
	response {
		ok 0 : boolean
	}

}
]]

local f = io.open("./apc.sp", "w+")
assert(f)
f:write(sp, #sp)
f:close()
print(#sp)
