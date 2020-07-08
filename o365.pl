#!/usr/bin/perl

local $ip;
local $i = 0;

print '{"listId":"fb9e5c35-af35-4cda-1212-121212121212","name":"prefix-o365","type":"dataPrefix","description":"Desc Not Required","entries":[';

while (<>)
{
	if (($f1, $ip, $f2) = ($_ =~ /(^\s+)(\"\d+\.\d+\.\d+\.\d+\/\d+\")(.*$)/)){
		if($i > 0){
			print ',';
		}
		$i = $i + 1;	
		print '{"ipPrefix":';
		print "$ip}";
	}
}

print '],"lastUpdated":1585194061850,"owner":"admin","readOnly":false,"version":"0","infoTag":"","referenceCount":0,"references":[],"isActivatedByVsmart":false}';
