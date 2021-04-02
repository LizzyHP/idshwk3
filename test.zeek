global IPtable :table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string) 
{
	local IP: addr = c$id$orig_h;
	if (c$http?$user_agent)
	{
		local user_agent: string = to_lower(c$http$user_agent);
		if (IP in IPtable)
		{
			add IPtable[IP][user_agent];
		} 
		else 
		{
			IPtable[IP] = set(user_agent);
		}
	}
}

event zeek_drone() {
	local IP: addr;
	for (IP in IPtable) {
		if (|IPtable[IP]| >= 3) {
			print(IP, " is a proxy");
		}
	}
}
