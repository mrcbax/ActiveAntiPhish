import "hash"

rule phishkit_generic {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-12"
        updated = "2018-06-15"
        description = "Triggers on php files that contain indicators that the file is used for stolen credential exfiltration."

    strings:
        $geo_detection0 = "geoplugin" nocase
        $geo_detection1 = "geoiptool" nocase
        $geo_detection2 = "ip-address-lookup-v4"
        $geo_detection4 = "ipinfodb"
        $UA_detection = "$_SERVER['HTTP_USER_AGENT']" nocase
        $IP_detection0 = "$_SERVER['HTTP_CLIENT_IP']" nocase
        $IP_detection1 = "$_SERVER['REMOTE_ADDR']" nocase
        $IP_detection2 = "gethostbyaddr(" nocase
        $IP_detection3 = "getenv(\"REMOTE_ADDR\")"
        $timestamping = "date(" nocase
        $credential_harvest0 = "$_POST['userid']" nocase
        $credential_harvest1 = "$_POST['pass']" nocase
        $credential_harvest2 = "$_POST['Email']" nocase
        $credential_harvest3 = "$_POST['Passwd']" nocase
        $credential_harvest4 = "$_POST['username']" nocase
        $credential_harvest5 = "$_POST['eMailAdd']" nocase
        $credential_harvest6 = "$_POST['recEmail']" nocase
        $credentail_harvest7 = "$_POST['phoneNumber']" nocase
        $credential_harvest8 = "$_POST['em']" nocase
        $credentail_harvest9 = "$_POST['psw']" nocase
        $credential_harvest10 = "$_POST['id']" nocase
        $email_headers0 = "MIME-Version: 1.0" nocase
        $email_headers1 = "MIME-Version:1.0" nocase
        $email_exfil = "mail(" nocase
        $file_exfil0 = "fopen(" nocase
        $file_exfil1 = "fputs(" nocase
        $log_tags0 = "Vict!m" nocase
        $log_tags1 = "Created BY" nocase
        $log_tags2 = "You have a new drop" nocase
        $log_tags3 = "Rezultz" nocase
        $log_tags4 = "Spam ReZulT" nocase
        $redirect = "header(" nocase
        $code_comments0 = "//change ur email here"
        $code_comments1 = "---"
        $code_comments2 = "==="
        $code_comments3 = "+++"
        $code_comments4 = "|||"
        $php_header = "<?php"
        $php_header2 = "<?"
        $php_footer = "?>"


    condition:
        any of ($php*) and any of ($credential_harvest*) and any of ($*exfil*)
        and 4 of them
}

rule phishkit_uids {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-13"
        updated = "2018-06-15"
        description = "Unique IDs used in phish kits, often emails, usernames, and numbers. This may trigger many false positives depending on what you are scanning"

    strings:
        $0 = "garrethwebb010"
        $1 = "xConsoLe"
        $2 = "+nJoY+"
        $3 = "dddresult"
        $4 = "office465"
        $5 = "office3655"
        $5 = "phishtank" //used in blocking scripts that block the good guy crawlers.
        $6 = "strictlydomain"
        $7 = "*B0y"
        $8 = "doublerror404"
        $9 = "gxn31lb1hn5th2kp66zl60tw"
        $10 = "t2ladon"
        $11 = "valentinacare11"
        $12 = "neversaydie"
        $13 = "shrtt111"
        $14 = "supertool"
        $15 = "kevin9angelo"
        $16 = "ISI PESAN" nocase
        $17 = "Spam Result" nocase
        $18 = "freshdude001"
        $19 = "valinc0147"
        $20 = "NC3778N12E999MDM3429" nocase
        $21 = "MR.Int.Tunisien"
        $22 = "ABCDEMN0123456789" //create regex for filenames created with the function that uses these characters for random filenames. Filenames are 20 chars long.
        $23 = "JOkEr7"
        $24 = "dropyefe"
        $25 = "LvRxDnOnA" nocase
        $26 = "666133716"
        $27 = "tacomrcreator"
        $28 = "jamonte drop" nocase
        $29 = "goggle.comm"
        $30 = "REEHDG78273"
        $40 = "HBUD8373293"
        $41 = "BigNattY"
        $42 = "franksam12340"
        $43 = "jameshang12340"
        $44 = "bc637518"
        $45 = "q1y7lddxendi07jbj0mksvf4"
        $46 = "slimclasss77"
        $47 = "ericjasonminks150"
        $48 = "dhotmuller"
        $49 = "_JeHFUq_VJOXK0QWHtoGYDw1774256418"
        $50 = "" nocase
        $51 = "mailworkstrong1"
        $52 = "rcazconstructionllc"
        $53 = "dallasvendorllc"
        $54 = "junkycrazy"
        $55 = "dbenito202"
        $56 = "blessed.muno1"
        $57 = "cyveillance"
        $58 = "Hacker Bamo"
        $59 = "joananndradelozano"
        $60 = "eppinigeria"
        $70 = "bdf624a70b290f75ecdf08f61ba30bb97b946fcd08a5dd35eeaabbc7b6b3f354"
        $71 = "kingservar"
        $72 = "K1nG^SeRvAr"
        $73 = "babaservar"
        $74 = "hackedbykoko"
        $75 = "jamesalfred2012"
        $76 = "enricobenettti"
        $77 = "blessedalilogz"
        $78 = "Jboi" nocase
        $79 = "gloryfirmltd"
        $80 = "OLUWA"
        $81 = "banklogs1"
        $82 = "Unknown(doit)com"
        $83 = "baithwire"
        $84 = "fud.page" nocase
        $85 = "fudpage" nocase
        $86 = "igma"
        $87 = "670486322"
        $88 = "LulzSec"
        $89 = "harolbwalt"
        $90 = "iLNxAnb"


    condition:
        any of them


}

rule phishkit_docusign {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-12"
        description = "Known Docusign PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "9136e3ca8d6425e9ccc529accfb6e321e3048b7e84c87940b9f40297bc704120"

}

rule phishkit_google {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-12"
        updated = "2018-06-15"
        description = "Known Google PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "1cc4118e6e16ce0ea202a0576f616b72f5ef809cef559ca8d57a75ae994f3430" or
        hash.sha256(0, filesize) ==
        "894d75e8c73498b5ef2abaa8b7322db6f544ef28120ce62227897c9206b21532"

}

rule phishkit_microsoft {
    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-12"
        updated = "2018-06-15"
        description = "Known Microsoft PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "2b64dd4eb9357254ca8315df7b03858b2b8b10d556065c71ff2b7218dc2a2a3d" or
        hash.sha256(0, filesize) ==
        "cb1d550d55af7e3a8c327e829fa5686fb6a27295cd0839b13aca4484127fda92" or
        hash.sha256(0, filesize) ==
        "a963f7907009c1cdcb49b4a8a36a0de38e801aa67dbbf949f75a3f1294abb530" or
        hash.sha256(0, filesize) ==
        "562a172e0957278b6c0f1f047b0a2e48187fb91d1d96b76f24f26ccc05cc6c5b" or
        hash.sha256(0, filesize) ==
        "86324ead56827e09121baffd919e4e6b972eef68fed1ef972860242d331555f7" or
        hash.sha256(0, filesize) ==
        "c107e45c35c979f9347f2c43c616b967fea409dad905c8297e939571d75fc6bc" or
        hash.sha256(0, filesize) ==
        "f3695975ee6c330514836b87c82374e19d6b44107f213c38ee0bed3521880c65" or
        hash.sha256(0, filesize) ==
        "ddf32e74b524b8c70f585d41e9b08137c710d14e1549b100560c4aa30db1414b" or
        hash.sha256(0, filesize) ==
        "5f532405e37ec3a399d9d7d43c45ab7d1cf04f916d1b6003c8c508dda549b025" or
        hash.sha256(0, filesize) ==
        "8aabdbd1f03084548383a36a4ba432f3d661dbf42c6f6202be8157768d5de7d6" or
        hash.sha256(0, filesize) ==
        "33a7d6ee2ae2a968bef2482b1f21c1751e37348d0bb577b2be4027f7596d7d73" or
        hash.sha256(0, filesize) ==
        "44c6f3ee1d2365434f6ad35d8911f49e2d50d900c00baf1352e9279c8ae0c18d" or
        hash.sha256(0, filesize) ==
        "748536449d6ce08180eb29ff1b7959e13d409c5c915196986791f5f7097acde2" or
        hash.sha256(0, filesize) ==
        "3fce7f5cdb17832e9a8e3b75a4654741cb1febb77df3ad9f0dcdd228286ec21f"

}

rule phishkit_dropbox {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-12"
        updated = "2018-06-15"
        description = "Known DropBox PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "2573c007b4e2a0e212000aaa890f74ed93131f19bdd6b007d38d5838a3b7213b" or
        hash.sha256(0, filesize) ==
        "f142b9d1c062ab03d2ba654a62db59c56e094bbe7cbdb2186cf4720f0bd94c71" or
        hash.sha256(0, filesize) ==
        "79cf5811a1978495d2b3889decadb8b804e84a6112b28d5ef09131efb3ea8b0e"

}

rule phishkit_adobe {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-12"
        description = "Known Adobe PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "40af3b2320e8b96dade4e833e1bb69dc358e7d3a8d2c7e7f861bd7029b7a37ed"

}

rule phishkit_banking {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-13"
        updated = "2018-06-15"
        description = "Known banking PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "362f680698361c71427e2020546a397d08c287530d2c96cf53c6876b0c481ede" or
        hash.sha256(0, filesize) ==
        "bf1971f78baef3b06064065b917c8c947846071a20cb50d8ca85ee0c3683a8df" or
        hash.sha256(0, filesize) ==
        "2cd5d8921cffc85b97ff78404ad6ff40ac7bc792e0490e873a094031e2c96f3c" or
        hash.sha256(0, filesize) ==
        "ac7357307f4703e891f5efd2a6af05358e7206a968f07b82edfc1e0ee2988a02"

}

rule phishkit_telecom {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-15"
        description = "Known telecommunications PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "2df34379555e4ed0bed9cac3ef262fc9b401608f3a54692a1479e18a8e875472" or
        hash.sha256(0, filesize) ==
        "cb850a4b1aa17c242f425a0ce15fc93a1b27d732f77b8f08892f745f99f26916"

}

rule phishkit_yahoo {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-15"
        description = "Known Yahoo PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "81689970d6d2c70ba5168cb43bcbc54603950a2b59fa581d0e415fa5b7cb18a4"

}

rule phishkit_multi {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-15"
        description = "Known multi-account PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "e5196ccbf1480d54f9af749d2ad136b0081b499cac71015db9094fcb10cfd91a" or
        hash.sha256(0, filesize) ==
        "d3bf33d3fdd2ceddeb2bf66004c0eda34368763caeeb2b75b35e7427e573eb6a"
}

rule phishkit_unknown {
    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-15"
        description = "hashes of unknown PhishKits"


    condition:
        hash.sha256(0, filesize) ==
        "d139dae69d056958e8b7cc3deaad5a8509aac27e3f2af44ec0861e519f020a1b" or
        hash.sha256(0, filesize) ==
        "abff679ee32bc36d009d5fc282d31176ea5c626a24a1bff8446f91a4ed58a5f4" or
        hash.sha256(0, filesize) ==
        "323ffa607fd2104b821c6862228be2dc5f28731ddaffc7475b29bc159c039605"
}
