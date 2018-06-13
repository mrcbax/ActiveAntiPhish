import "hash"

rule generic_phishkit {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        created_on = "2018-06-12"
        description = "Triggers on php files that contain indicators that the file is used for stolen credential exfiltration."

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
        $file_exfil = "fopen(" nocase
        $file_exfil2 = "fputs(" nocase
        $log_tags = "Vict!m" nocase
        $log_tags2 = "Created BY" nocase
        $redirect = "header(" nocase
        $code_comments = "//change ur email here"
        $php_header = "<?php"
        $php_header2 = "<?"
        $php_footer = "?>"


    condition:
        ($php_header or $php_header2) and $php_footer and 6 of them
}

rule docusign_phishkit {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        created_on = "2018-06-12"
        description = "Known Docusign PhishKits"

    condition:
        hash.sha256(0, filesize) == "9136e3ca8d6425e9ccc529accfb6e321e3048b7e84c87940b9f40297bc704120"

}

rule google_phishkit {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        created_on = "2018-06-11"
        description = "Known Google PhishKits"

    condition:
        hash.sha256(0, filesize) == "1cc4118e6e16ce0ea202a0576f616b72f5ef809cef559ca8d57a75ae994f3430"

}

rule microsoft_phishkit {
    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        created_on = "2018-06-12"
        description = "Known Microsoft PhishKits"

    condition:
        hash.sha256(0, filesize) == "2b64dd4eb9357254ca8315df7b03858b2b8b10d556065c71ff2b7218dc2a2a3d" or
        hash.sha256(0, filesize) == "cb1d550d55af7e3a8c327e829fa5686fb6a27295cd0839b13aca4484127fda92" or
        hash.sha256(0, filesize) == "a963f7907009c1cdcb49b4a8a36a0de38e801aa67dbbf949f75a3f1294abb530" or
        hash.sha256(0, filesize) == "562a172e0957278b6c0f1f047b0a2e48187fb91d1d96b76f24f26ccc05cc6c5b"

}

rule dropbox_phishkit {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        created_on = "2018-06-12"
        description = "Known DropBox PhishKits"

    condition:
        hash.sha256(0, filesize) == "2573c007b4e2a0e212000aaa890f74ed93131f19bdd6b007d38d5838a3b7213b"

}

rule adobe_phishkit {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        created_on = "2018-06-12"
        description = "Known Adobe PhishKits"

    condition:
        hash.sha256(0, filesize) == "40af3b2320e8b96dade4e833e1bb69dc358e7d3a8d2c7e7f861bd7029b7a37ed"

}
