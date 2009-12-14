% emulate pager behaviour like mutt / newsbeuter
%

define muttpager_quit () {
	if (_is_article_visible () & 1)
		call ("hide_article");
	else
		call ("quit");
}

define muttpager_show_article () {
	ifnot (_is_article_visible () & 1)
		call ("hide_article");
}

define muttpager_line_down () {
	if (_is_article_visible () & 1)
		call ("article_line_down");
	else
		call ("header_line_down");
}

define muttpager_line_up () {
	if (_is_article_visible () & 1)
		call ("article_line_up");
	else
		call ("header_line_up");
}

define muttpager_page_down () {
	if (_is_article_visible () & 1)
		call ("article_page_down");
	else
		call ("header_page_down");
}

define muttpager_page_up () {
	if (_is_article_visible () & 1)
		call ("article_page_up");
	else
		call ("header_page_up");
}

define muttpager_eob () {
	if (_is_article_visible () & 1)
		call ("article_eob");
	else
		call ("header_eob");
}

define muttpager_bob () {
	if (_is_article_visible () & 1)
		call ("article_bob");
	else
		call ("header_bob");
}
