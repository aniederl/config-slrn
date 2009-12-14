variable fetchnews_cmd = "sudo /usr/sbin/fetchnews -vvv";

define fetchnews () {
	() = system (fetchnews_cmd);
	call ("refresh_groups");
}

define fetchnews_server (server) {
	() = system (fetchnews_cmd + " -S " + server);
	call ("refresh_groups");
}

define postnews () {
	() = system (fetchnews_cmd + " -P");
}
