define fetchnews ()
{
	() = system ("sudo /usr/sbin/fetchnews    -vvv");
	call ("refresh_groups");
}

define postnews ()
{
	() = system ("sudo /usr/sbin/fetchnews -P -vvv");
}
