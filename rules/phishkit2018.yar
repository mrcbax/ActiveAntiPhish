rule phishkit {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        created_on = "2018-06-11"

    strings:
        $geo_detection = "geoplugin" nocase
        $geo_detection2 = "geoiptool" nocase
        $UA_detection = "$_SERVER['HTTP_USER_AGENT']" nocase
        $IP_detection = "$_SERVER['HTTP_CLIENT_IP']" nocase
        $IP_detection2 = "$_SERVER['REMOTE_ADDR']" nocase
        $IP_detection3 = "gethostbyaddr(" nocase
        $timestamping = "date(" nocase
        $credential_harvest = "$_POST['userid']" nocase
        $credential_harvest2 = "$_POST['pass']" nocase
        $credential_harvest3 = "$_POST['Email']" nocase
        $credential_harvest4 = "$_POST['Passwd']" nocase
        $email_exfil_headers = "MIME-Version: 1.0" nocase
        $email_exfil = "mail(" nocase
        $log_tags = "Vict!m" nocase
        $log_tags2 = "Created BY" nocase
        $redirect = "header(\"Location: " nocase
        $code_comments = "//change ur email here"
        $php_header = "<?"
        $php_footer = "?>"


    condition:
        6 of them
}
