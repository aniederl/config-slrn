% -*- mode: slang; mode: fold -*-

% gnupg.sl - a macro for using GNU Privacy Guard (GnuPG) with SLRN.

% Copyright (C) 2000-2002 Emmanuele Bassi <emmanuele.bassi@iol.it>
% Based on `posthook.sl' by John E. Davis and `pgp-stuff.sl' by Ren? Scholz.
% set_preference() mechanism borrowed from J.B. Nicholson-Owens
 
% This file may be redistributed and / or modified under the terms of the
% GNU General Public License, version 2, as published by the Free Software
% Foundation.

% Version: 1.6.6 - Mon Aug 04 00:14:02 CEST 2003 $

#iffalse % Documentation %{{{
Description:

This macro permits to sign articles with GNU Privacy Guard (GnuPG),
or Pretty Good Privacy (PGP).  It also consents to verify signed articles 
and to import new keys into your keyring.

Installation:

* Sign (ONLY IF YOU HAVE SLRN < "0.9.7.0")

Define this new (if you don't already have it) function in a macro file (e.g.
add_on.sl):

  define post_file_hook (file)
  {
    gnupg->sign_article (file);
  }

And make SLRN interpret this file *after* gnupg.sl.
Remember to remove every call to `register_hook', at the bottom of the macro.
If you have SLRN with version > "0.9.7.0", the hook will be registered
automagically by this macro.

* Verify Articles and/or import keys.

Verify signed articles with Shift+V; import new keys into your keyring, with
ESC-Ctrl-K.  If you wish to change those two keybinding, simply bind the
verify_signature and the import_key functions to whatever key you like,
e.g.:

  setkey article gnupg->verify_signature "V"
  setkey article gnupg->import_key       "\e^K"

* Usage:

The macro sign_article() is called by the post_file_hook.  The user will be
prompted to choose whether to sign the article or not.  If the user mistypes
the passphrase (typical with long and strong passphrases), the macro will ask
it again until 1. the passphrase is correct or 2. the user press `return`: in
the latter case, the macro simply aborts, and the unsigned post is sent.

Once the passphrase is used for the first time, it will be stored for later
use, until "pass_timeout" is expired, or if the forget_passphrase() function
is invoked (default keymap: Ctrl-F).

Note: You must specify a keyserver into your GnuPG configuration file
(tipically ~/.gnupg/options), for the import_key() function to work.

You can use the set_preferences() function to customize the macro behaviour:

  gnupg->set_preference ("sign_command", "gpg --batch --passphrase-fd 0 -a -q --clearsign")
  gnupg->set_preference ("verify_command", "gpg --verify-files")
  gnupg->set_preference ("import_key", "gpg --recv-keys")

  -- These are the default for using GnuPG.

  gnupg->set_preference ("verify_command", "pgp +VERBOSE=0 -o /dev/null")
  
  -- This is for verifing a signed article with PGP 2.6.3in.

  gnupg->set_preference ("auto_sign", 1)
  gnupg->set_preference ("pass_timeout", 300)

  -- These are for a mutt-like behaviour.

You may want to append your signature, thus avoiding the signature delimiter
to change from `-- ' to `- -- ' (this is done by GnuPG/PGP when creating the
clearsign of a Usenet article); in order to achieve this, set the "append_sig"
option to a non-zero value:

  gnupg->set_preference ("append_sig", 1);

  Note: this option imply the "include_sig" option; setting "include_sig"
  to zero will automatically set the "append_sig" option to zero.

If you want to specify the keyid you want to use when signing an article, you
can use the "default_key" preference:

  gnupg->set_preference ("default_key", "0xA4320FF4");

  Note: remember to enclose the keyid inside double quotes ("), otherwise the
  S-Lang interpreter will choke when signing articles.  If you are using PGP,
  you must change the command line option inside the "dfl_key_option"
  preference too, since it defaults to the GnuPG switch.

The default_key preference is also used when adding the keyid header (which is
used by gnupg.sl when you want to import a key from a signed article):

  gnupg->set_preference ("add_key_header", 1);

  Note: leaving empty the default_key preference will de-activate the keyid
  header even if you set "add_key_header" to non-zero.

Credits:

*  John E. Davis,    for slrn and the posthook.sl macro
*  Ren? Scholtz,     for his pgp-stuff.sl macro
*  Matthew Hunter,   for his useful suggestions
*  Jurriaan Kalkman, for his popen() code
*  Johan Lindquist,  for his append_signature code

History:

v1.6.6  sign_command is sent through a pipe, in order to mask it from ps
        (thanks to Philip Willoughby);
v1.6.5  improved documentation;
v1.6.4  the keyid header is added only when posting a signed article;
v1.6.3  corrected a bug in add_key_header();
v1.6.2  corrected a bug that prevented the use of special characters in
        passphrases (thanks to Sandy Herring);
v1.6.1  check on *custom_headers in add_key_header() (thanks to Johan
        Lindquist);
v1.6.0  add_key_header() adds to the custom headers the "X-PGP-KeyID:"
        header, containing your default keyid. To de-activate this option,
        set the "add_key_header" preference to 0; import_key() now searches
        for the "X-PGP-KeyID:" header, and shows the (eventually) found keyid
        as default for importing; added the "append_sig" preference: it will
        append the user's signature at the end of the PGP-signed article body
        (thanks to Johan Lindquist); changed "include_sign" preference to
        "include_sig";
v1.5.2  added a message in forget_passphrase();
v1.5.1  added the "default_key" preference, that defines the default key to be
        used when signing articles;
v1.5.0  set compatibility for slrn 0.9.7.3;
v1.4.1  all functions are back to static;
v1.4.0  added the ability to store the passphrase in memory for later use;
        implemented the forget_passphrase() function, to remove the passphrase
        from memory;
v1.3.2  added the "auto_sign" preference: setting it to "1" will make SLRN not
        to prompt user for signing articles, and will directly ask the
        passphrase;
v1.3.1  import_key() and verify_signature() functions are now public;
        default key assignment at the end of this macro;
v1.3.0  now using intrinsic function popup_window();
        new function import_key(): imports a key into you keyring;
        using popen() for calling external programs;
v1.2.0  corrected a bug that prevented using passphrases with non-alphabetic
        chars;
v1.1.0  it is now possible to include signature in signed articles;
v1.0.0  initial release;

#endif %}}}

implements ("gnupg");

% Preferences variable %{{{
private variable
  Prefs = Assoc_Type [];
%}}}

% Set default preferences %{{{
Prefs["sign_command"]   = "gpg --batch --passphrase-fd 0 -aq --clearsign";
Prefs["verify_command"] = "gpg --verify-files";
Prefs["import_command"] = "gpg --recv-keys";
Prefs["dfl_key_option"] = "--default-key";
Prefs["default_key"]    = "";
Prefs["include_sig"]    = 1;
Prefs["append_sig"]     = 0;
Prefs["auto_sign"]      = 0;
Prefs["pass_timeout"]   = 300;
Prefs["add_key_header"] = 1;
Prefs["key_header"]     = "X-PGP-KeyID";

%}}}

% Global variables %{{{
private variable
  Passphrase = "",
  TimeStamp  = 0;

%}}}

static define set_preference (preference, value) %{{{
{
  !if (assoc_key_exists (Prefs, preference))
    error ("Preference does not exist: " + string (preference));
    
  variable desired_type = typeof (Prefs[preference]);
  
  if (typeof (value) != desired_type)
    verror ("Wrong type for %s: This preference wants %s not %s",
            string (preference),
            string (desired_type),
            string (typeof(value)));
  
  Prefs[preference] = value;
} %}}}

static define get_key_header () %{{{
{
   variable pgp_header;

   if (0 == strlen (Prefs["key_header"]))
     return "";

   if (0 == strlen (Prefs["default_key"]))
     return "";
  
   pgp_header = sprintf ("%s: %s\n",
                         Prefs["key_header"],
                         Prefs["default_key"]);
   
   return pgp_header;
} %}}}

static define sign_article (file) %{{{
{
  variable header_file, body_file, body_file_signed, sig_file;
  variable fp, header_fp, body_fp, sig_fp;
  variable line;
  variable str;
  variable has_signature = 0;
  variable sign_ret;
  
  % sanity check: no use in appending signature if the user do not want the
  % signature at all.
  if (Prefs["include_sig"] == 0)
    Prefs["append_sig"] = 0;
  
  !if (Prefs["auto_sign"])
    if (1 != get_yes_no_cancel ("Execute GnuPG signature on message"))
      return;
    
  fp = fopen (file, "r");
  if (fp == NULL)
    return;
   
  header_file = file + "-header";
  body_file = file + "-body";
  sig_file = file + "-sig";
  body_file_signed = body_file + ".asc";
  
  % Do some cleanup before: useful only if use_tmpdir is set to 0.
  if (0 == get_variable_value ("use_tmpdir"))
    {
       () = remove (header_file);
       () = remove (body_file);
       () = remove (sig_file);
       () = remove (body_file_signed);
    }
  
  header_fp = fopen (header_file, "w");
  body_fp = fopen (body_file, "w");
  sig_fp = fopen (sig_file, "w");
  
  % Error: unable to write.
  if ((header_fp == NULL) or (body_fp == NULL) or (sig_fp == NULL))
    return;
   
  % Split file into parts.
  % Do headers...
  while (-1 != fgets (&line, fp))
    {
       if (line == "\n") break;
		 
       () = fputs (line, header_fp);
    }

  () = fclose (header_fp);
   
  % Now do body...
  while (-1 != fgets (&line, fp))
    {
       if (line == "-- \n")
         {
	         has_signature = 1;
				
				if (Prefs["append_sig"] or not (Prefs["include_sig"]))
				  break;
			}
       
       () = fputs (line, body_fp);
    }
    
  !if (has_signature)
    () = fputs ("\n", body_fp);
  
  () = fclose (body_fp);

  % And finally the signature part...
  % No data if the "include_sig" preference is true
  % or if the "append_sig" preference is false
  if (Prefs["include_sig"] and Prefs["append_sig"])
    while (-1 != fgets (&line, fp))
      () = fputs (line, sig_fp);
  else
    has_signature = 0;
  
  do
    {
       variable sign_cmd;
		 variable sign_fp;
      
       if (Prefs["pass_timeout"] <= (_time - TimeStamp))
         Passphrase = "";
	
       if (0 == strlen(Passphrase))
		   {
			   str = read_mini_no_echo (
					"Enter your GnuPG passphrase (press ENTER to send unsigned): ",
					"", "");
			}
       else
         str = Passphrase;

       % If the user did not insert the passphrase, abort
       % everything, and post the unsigned article.
       %if (str == "") return;
      
       if (0 != strlen (Prefs["default_key"]))
		   {
			   sign_cmd = sprintf ("%s %s %s",
                                Prefs["sign_command"],
                                Prefs["dfl_key_option"],
                                Prefs["default_key"]);
			}
       else
         sign_cmd = Prefs["sign_command"];
	    
		 % open a pipe and send the sign_command to it, so that the passphrase
		 % won't be showed in the processes listing.
		 sign_fp = popen (sprintf ("%s '%s'", sign_cmd, body_file), "w");
		 if (sign_fp == NULL)
		   {
            error ("Unable to open pipe for signing article.");
		      return;
		   }
		 
		 % send the passphrase through the pipe.
	    fputs (str, sign_fp);
		 
		 sign_ret = pclose(sign_fp);
		 
		 % a little hack: since a pipe is unidirectional, if there's an error
		 % gpg will puke on everything; hence, the cleanup.
		 if (0 != sign_ret)
		   call("redraw");
    }
  while (0 != sign_ret);
  
  Passphrase = str;
  TimeStamp  = _time;
  
  % Now we bring back together all the parts, using the signed body instead of
  % the original one.
  fp = fopen (file, "w");
  body_fp = fopen (body_file_signed, "r");
  header_fp = fopen (header_file, "r");
  sig_fp = fopen (sig_file, "r");
        
  while (-1 != fgets (&line, header_fp))
    () = fputs (line, fp);
  
  % if needed, add the keyid header
  if (Prefs["add_key_header"])
    {
       variable header = get_key_header();

       !if (0 == strlen(header))
         () = fputs (header, fp);
    }
  
  () = fputs ("\n", fp);
   
  while (-1 != fgets (&line, body_fp))
    () = fputs (line, fp);

  % If append_sig is set, we also know for sure that include_sig is set, so
  % we do not check it.
  if (Prefs["append_sig"] and has_signature)
    {
       % assume a blank line between pgp signature and user's signature.
       () = fputs ("\n" + "-- \n", fp);

       while (-1 != fgets (&line, sig_fp))
         () = fputs (line, fp);
    }
} %}}}

static define forget_passphrase () %{{{
{
  Passphrase = "";
  TimeStamp  = -1;

  message ("GnuPG passphrase forgotten...");
} %}}}

static define verify_signature () %{{{
{
  variable tmpfile = ".slrn-tmpfile.asc";
  variable gnupg_fp;
  
  % Exit if not in article mode.
  if (is_group_mode)
    error (_function_name () + " doesn\'t work in group mode!");
  	
  if (save_current_article (tmpfile) != 0)
    % Something went wrong...
    error("Error while writing temporary file. Aborting... ");
  
  gnupg_fp = popen (sprintf ("%s '%s' 2>&1", Prefs["verify_command"], tmpfile), "r");
  
  if (gnupg_fp == NULL) return;
  
  popup_window ("Verify Signature:", strjoin (fgetslines(gnupg_fp), ""));
  () = pclose (gnupg_fp);
} %}}}

static define import_key () %{{{
{
  variable key_id, cmd, parent_key_id = "";
  variable gnupg_fp;

  if (is_group_mode)
    error (_function_name () + " doesn\'t work in group mode!");

  parent_key_id = extract_article_header (Prefs["key_header"]);

  key_id = read_mini ("Enter the key ID: ", parent_key_id, "");

  if (key_id == "") return;

  cmd = sprintf ("%s '%s' 2>&1", Prefs["import_command"], key_id);
  
  gnupg_fp = popen (cmd, "r");
  
  if (NULL == gnupg_fp) return;
  
  popup_window ("Import Key", strjoin (fgetslines(gnupg_fp), ""));
  () = pclose (gnupg_fp);
} %}}}

% Register hook %{{{
!if (1 == register_hook ("post_file_hook", "gnupg->sign_article"))
  error ("gnupg.sl: register_hook (post_file_hook) failed");
% }}}

% Set default key assignment %{{{
definekey ("gnupg->verify_signature",  "V",     "article");
definekey ("gnupg->import_key",        "\e^K",  "article");
definekey ("gnupg->forget_passphrase", "^F",    "article");
%}}}

% vim:tw=80 ts=3 noet
