local sproto = require "sprotoparser"

local sp = sproto.parse [[
.package {
	type 0 : integer
	session 1 : integer
}

status 1 {
	request {
		apstatus   0  : integer
		stanum 1  : integer
		hver 2  : string
		sver 3  : string
		mac     4  : string
		sn 5  : string
		aip 6  : string
		.sta{
			stamac 0: string
		}
		smac 7: *sta
		model 8: string
	}
	response {
		ok 0 : boolean
	}
}

info 2 {
	request {
		ssid       0  : string
		encrypt 1  : string
		key 2  : string 
		channel  3  : string
		txpower 4  : string
		aip 5: string
	}
	response {
		ok 0 : boolean
	}
}

cmd 3 {
	request {
		apcmd      0  : integer
		addr 1  : string
		md5 2  : string
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
