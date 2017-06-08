local uci = require "luci.model.uci".cursor()	


-- iptables rules for auth
local has_rules
uci:foreach("firewall", "include", function (s)
	if s.path == "/etc/firewall.guest" then
		has_rules = true
	end
end)

if not has_rules then
	uci:section("firewall", "include", "_wifi_guest",
		{ path = "/etc/firewall.guest" })
end

uci:save("firewall")
uci:commit("firewall")

if has_rules then
	os.execute('/etc/init.d/firewall reload')
else
	os.execute('/etc/init.d/firewall restart')
end
