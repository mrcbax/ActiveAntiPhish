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
        $card_verification0 = "lookup.binlist"
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
        $credential_harvest7 = "$_POST['phoneNumber']" nocase
        $credential_harvest8 = "$_POST['em']" nocase
        $credentail_harvest9 = "$_POST['psw']" nocase
        $credential_harvest10 = "$_POST['id']" nocase
        $credential_harvest11 = "$_SESSION['_email_']" nocase
        $credential_harvest12 = "$_SESSION['_password1_']" nocase
        $credential_harvest13 = "$_SESSION['Eamil']" nocase
        $credential_harvest14 = "$_POST['pass']" nocase
        $credential_harvest15 = "$_SESSION['epass']" nocase
        $credential_harvest16 = "$_SESSION['clientemail']" nocase
        $credential_harvest17 = "$_POST['EML']" nocase
        $credential_harvest18 = "$_POST['PWD']" nocase
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
        any of ($php*) and any of ($credential_harvest*) and any of ($email*) and 4 of them
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
        // $22 = /((?:[a-zA-Z0-9]{20}))/
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
        $50 = "iLNxAnb"
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
        $90 = "phishtank" //used in blocking scripts that block the good guy crawlers.
        $91 = "mb4504319"
        $92 = "david_1sc"
        $93 = "scama-yahya-xhack"
        $94 = "sand_email"
        $95 = "❤ ●•۰۰۰۰•● ❤ ●•۰۰۰•●••●●••"
        $96 = "yahya_email"
        $97 = "samehman575"
        $98 = "Bassem_Almasry"
        $99 = "Scam Page V1"
        $100 = "SpamRezault"
        $101 = "NourBlog1"
        $102 = "rmlacey01"
        $103 = "ISPA.Team"
        $104 = "WeStGiRl"
        $105 = "attahvictorcity"
        $106 = "oussamadwissel"
        $107 = "radwanadra12"
        $108 = "Pro.Spaming"
        $109 = "spamtools.pro"
        $110 = "your1@email.com,your2@email.com"
        $111 = "LI DAMDOUMA KYB9A DAMDOUMA"
        $112 = "spyus_Hacker"
        $113 = "yahyazarir"
        $114 = "YLEH LOOOD T7OWA B L3RBIYA TA3RABT"
        $115 = "1639-7537-1062-1478<--!-->391f00c002bba88bqs4fs8df865fe15466b8<--!-->9974-5263-1008-8889"
        $116 = "Officiel.Exploiter"
        $117 = "By Libyan Shell"
        $118 = "teamspyus"
        $119 = "18ac6487d78d85342105b7b34e0d9f38b27a2f92"
        $120 = "MRX_JOKER"
        $121 = "omoiyachameh"
        $122 = "maskyinka"
        $123 = "codercvvs"
        $124 = "99,111,100,101,114,99,118,118,115,64,103,109,97,105,108,46,99,111,109"
        $125 = "zetas.oujda"
        $126 = "morsyabdo793"
        $127 = "murphyray123"
        $128 = "Xclusiv-3D"
        $129 = "Surelogins2016"
        $130 = "leesun101"
        $131 = "kinglawish01"
        $132 = "shawnpee31"
        $133 = "ahmed4dam"
        $134 = "bassem.hithem"
        $135 = "706704896"
        $136 = "fudtool" nocase
        $137 = "ceo.marcoaaron"
        $138 = "Anonisma-Free-Tools"
        $139 = "aimenboussadia"
        $140 = "Anonisma"
        $141 = "moghul.haroon"

    condition:
        any of them

}

rule phishkit_amazon {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-12"
        updated = "2018-06-15"
        description = "Known Amazon PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "3d840b104aea1f863ce456c202d7a92274050812343fc691c4e323ea6f99e21d" or
        hash.sha256(0, filesize) ==
        "8ad782b520ac0b38ff32167e1785ab74ac6f775df0aee9822d86f051499725b2" or
        hash.sha256(0, filesize) ==
        "ff82d61087f9ef12e6ff43c8f40c3a33200a340c26dccd92a5142f153f441e43" or
        hash.sha256(0, filesize) ==
        "f6002679aa5401afc6c1612ba81d64e71a5115817ee8115f797bd4a4015b1d67"
}

rule phishkit_apple {
    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-12"
        updated = "2018-06-15"
        description = "Known Apple PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "0c260bb6109a24bd10d93b8cdf89fb025747cd7cc9bf12f99a3daf7de1250cdc" or
        hash.sha256(0, filesize) ==
        "5a9df9199a1f0b5b690d5c409c7dca0d41a439d51dda1ab63d67e64d34000860" or
        hash.sha256(0, filesize) ==
        "81ff4fe2dca587bb5edd8c41b9fe2822f4d602b6364acaead67730940aab99ca" or
        hash.sha256(0, filesize) ==
        "4792e12148e632272c953ebfdcc36313ff8386168b3391fd29c27a40a21192d1" or
        hash.sha256(0, filesize) ==
        "793796df99f2dd0266e14c19279d8f0b305de463f79d73c7495bdd1b9827d547" or
        hash.sha256(0, filesize) ==
        "fbf74082ba2ca009f87c2f511e9a118c3bf42e5bde39bdacbca3db3854f4da76" or
        hash.sha256(0, filesize) ==
        "d4800d5b5dae03411d1bcd85d230840edf93e49e5e9dc2cd95751a58165ce931" or
        hash.sha256(0, filesize) ==
        "b77720d888f5153e0c569d0fac3d456ef962472ca790f744a1631097be6c418e"

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

rule phishkit_ebay {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-12"
        updated = "2018-06-15"
        description = "Known EBay PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "1f2877f7d321db68f846ef31da699de369ce4e2f3ea7b2ddfe380a8a112504f8" or
        hash.sha256(0, filesize) ==
        "568c68ba79ab068322d8677f4de419d8d9fe9a381d93fcbb6c978357030fb6ca" or
        hash.sha256(0, filesize) ==
        "920d5aa45a4e373eb56d3face29df6991a9363c5e64ebbabad0136011efd25af" or
        hash.sha256(0, filesize) ==
        "892f6ae0bb05af17c0277390d37e76cc5351abf166779322a5ace3e274617077"
}

rule phishkit_facebook {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-12"
        updated = "2018-06-15"
        description = "Known Facebook PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "c2dfb3881e597fe8956013e542d714a13008d5504261ec9a1fed23ca700ae676"
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
        "894d75e8c73498b5ef2abaa8b7322db6f544ef28120ce62227897c9206b21532" or
        hash.sha256(0, filesize) ==
        "f3413e26426829ba37e57bcbf90bafed995678a848cec796cb2d25a688abf4bb" or
        hash.sha256(0, filesize) ==
        "e64f325fe9dcb3a2ed115a746af95a805eafa801805308846c75443b22724461"

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
        "3fce7f5cdb17832e9a8e3b75a4654741cb1febb77df3ad9f0dcdd228286ec21f" or
        hash.sha256(0, filesize) ==
        "52eab3f8787dcd6a5e23b500338c155a02c31d39c6b52e29fc990ead2833aba4" or
        hash.sha256(0, filesize) ==
        "2a08ac711e94d792e9be47b24a14042b5c28c19d48aa62add78b90693b7ff69a" or
        hash.sha256(0, filesize) ==
        "191915231f57c0cea1b73155fd16edd739a36fbda769eae164765151ebf3d869"

}

rule phishkit_netflix {
    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-12"
        updated = "2018-06-15"
        description = "Known Netflix PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "38bb956cf6c355a64121e52b7888923c2b673a9469c1d0e3e5f197667763d1b3" or
        hash.sha256(0, filesize) ==
        "73fafa2d39d978b1225da2517743dd57ffd9074d6f03d0f56a75b8bd3c794a34" or
        hash.sha256(0, filesize) ==
        "2776cca9605b87533b11e4fcfc26f8727511a105d9a209c44bbe4f60f46a0ae8" or
        hash.sha256(0, filesize) ==
        "98865e0b1df4557a0563ff7121572b9792a10be082dc265d485decfaa6f92dca"
}

rule phishkit_paypal {
    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-12"
        updated = "2018-06-15"
        description = "Known PayPal PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "2af1d0c69e9507fe7b28c68aaee1969c75d5b9992fd8602c0ceefc79330f24ab" or
        hash.sha256(0, filesize) ==
        "5e7c567e561a59f93db854ac91cd7f933fa1dac2622e9a05906964c9e03935fb" or
        hash.sha256(0, filesize) ==
        "08d12a7b8c920bddd5cf5e8911856e4e93d6fe744b2ca6b32bba2849b520f207" or
        hash.sha256(0, filesize) ==
        "8d227789cd38e568a25474b590f3bc9834200d24c97ee82235245ca46e1a0926" or
        hash.sha256(0, filesize) ==
        "11eac11a9fc79e80145c16bce2444fd45873da5c295bbd741f9ae776a3ddfd14" or
        hash.sha256(0, filesize) ==
        "15bb10f24aff0f3d347e55100985e89376a5090600aa2a761dd8944f2c35269e" or
        hash.sha256(0, filesize) ==
        "38e3ed4a6382ae2fb2be7a98b17ea84beb58aabd9bfdb49fed831dd875cb9cdc" or
        hash.sha256(0, filesize) ==
        "53f1c9d054f52798989c675ca40625406e23a3855d9f8d15e40075bb502826ae" or
        hash.sha256(0, filesize) ==
        "93d2a3b65c422ebf0d4fb4c047cf641d0c702f1aaa3fa0e89e98b65a0cd5cb1f" or
        hash.sha256(0, filesize) ==
        "334d0495d419fbc96fd27817b42bc4cefceeb3fc859e40dec8fb38ce33423336" or
        hash.sha256(0, filesize) ==
        "52411f46f3436e4db49d20fed586f839a9b0ed5c7497a8ea694847560fc3a396" or
        hash.sha256(0, filesize) ==
        "70328f271f9658f7c36844477f83eca3f87400f2fcc2957f14bf0d37c5a743f8" or
        hash.sha256(0, filesize) ==
        "009448403a4959b2db39f6c44216de6a277c80900ce557ff7e513d58c9085697" or
        hash.sha256(0, filesize) ==
        "11629446fa8a80173ecc60bbb67ddf3b1895e3f676bd83b19deba3279004331e" or
        hash.sha256(0, filesize) ==
        "81485290f3cc8d6d69c14ea4afaea67c87c462224c8a37c9b43411edeee75d83" or
        hash.sha256(0, filesize) ==
        "e4e2b465bb8c33955fabd71ec2abe185d8a6dcfbfb5230cb88004b18278131fd" or
        hash.sha256(0, filesize) ==
        "db507e846a242b1f2a6254ca8ab2a42fa27251e0798a705f6c2259ad35e868c3" or
        hash.sha256(0, filesize) ==
        "a706cdb539dc23caeb6dfb511069b7c3e66bb409284c1c2c97bbbb48c1a7e7b6" or
        hash.sha256(0, filesize) ==
        "bd16bda0222a61d63610b1ef0faec3484042861161e5c16dd8db07cfb0723698" or
        hash.sha256(0, filesize) ==
        "cbf79385a4cad1f17aab8e6a4211f1da8783774a8dc0687a7d9e6e6ff6246fd5" or
        hash.sha256(0, filesize) ==
        "58785a1fd0ab239dbd8d4da194e15391e389de59f90e9a8d4a9875d077e7fe00" or
        hash.sha256(0, filesize) ==
        "9987917f50299c03bd25d68e4dcbe5b905b3ef5c6e4456b2ca9ce8588e43988a" or
        hash.sha256(0, filesize) ==
        "76755776dd5d1168cd307c4789d6190145f6a0250ab06679c434b7d1b4f00a4e" or
        hash.sha256(0, filesize) ==
        "b57858e1ea7a2c32dedf68703afab680b8718df6f82f6d2db2ce860b7c5e853c"
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
        "79cf5811a1978495d2b3889decadb8b804e84a6112b28d5ef09131efb3ea8b0e" or
        hash.sha256(0, filesize) ==
        "230acb8e2d503f7afbe44f327fbb97e0e9bb4211a4829734f79462084ffc12f7"

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
        "ac7357307f4703e891f5efd2a6af05358e7206a968f07b82edfc1e0ee2988a02" or
        hash.sha256(0, filesize) ==
        "c77d594904e754d099b64c2ce48c52e225f2b90d1f0a7f2e72b42404c29332a8" or
        hash.sha256(0, filesize) ==
        "3cc66884444fed57419aee787130d6cb2bc9bc30a4b7043988df2cff2a9ae6c5" or
        hash.sha256(0, filesize) ==
        "7b75705ab3e9c2101309b557a24aef130c97f13eb71bf7ec6e9c3b425c625eba" or
        hash.sha256(0, filesize) ==
        "85d990b9177d5a5a79a14a6464f98733df48d472a64a48eac9f598b87259dc88" or
        hash.sha256(0, filesize) ==
        "a1dd2feb403bce675c1a363f70b130cb859b2d81e3b26087c998f563ef9d5774" or
        hash.sha256(0, filesize) ==
        "81773583cfacd55287833896048da4ca1aa3bfff5be10080d11efc3419a53428"

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
        "cb850a4b1aa17c242f425a0ce15fc93a1b27d732f77b8f08892f745f99f26916" or
        hash.sha256(0, filesize) ==
        "c8b3f703b1539d0882ca6941320625d62867d09552f68db5faf8faacb3d9a6b3"

}

rule phishkit_yahoo {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-15"
        description = "Known Yahoo PhishKits"

    condition:
        hash.sha256(0, filesize) ==
        "81689970d6d2c70ba5168cb43bcbc54603950a2b59fa581d0e415fa5b7cb18a4" or
        hash.sha256(0, filesize) ==
        "ba09cfcc5bf34305bfb063bfce77cff7bf3f2f1714731872decdbeec813636f0"

}

rule phishkit_logistics {

    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-15"
        description = "Known Logistics PhishKits (USPS, DHL, China EMS, etc.)"

    condition:
        hash.sha256(0, filesize) ==
        "356e7a17be57e36239f3aad7d8c7c6c362ae272700b639ec230f032cb8980f23" or
        hash.sha256(0, filesize) ==
        "424357066cb9585a02bc918515ca4fe365ef10d3e3e32017bf4f025346dedb97"

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
        "d3bf33d3fdd2ceddeb2bf66004c0eda34368763caeeb2b75b35e7427e573eb6a" or
        hash.sha256(0, filesize) ==
        "b7b84d9fc009049a3d5f9b94eed6bb797df47ef855f8d8450fb5f70b7165d190"
}

rule phishkit_cryptotrading {
    meta:
        author = "Chad Baxter"
        author_email = "cbaxter@mail.umw.edu"
        date = "2018-06-15"
        description = "hashes of CryptoCurrency trading platform PhishKits"


    condition:
        hash.sha256(0, filesize) ==
        "14ffe686bc6afba5efa577063fedd89b66977ac939fae03504a39b8b85d86569" or
        hash.sha256(0, filesize) ==
        "35b36d56c5e753cf08a5af0c020fdc351e165509b0bd12f96845bd6ce314eb14" or
        hash.sha256(0, filesize) ==
        "82a7f11e2dd14c8ccf0b4904b29bc9f3a1d649e69416fd3e697c2ac57b0aefc4" or
        hash.sha256(0, filesize) ==
        "619275b9a9a26e0093b4d15696a1c33565d24710c9825536444dbd4bde7d2085"
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
        "323ffa607fd2104b821c6862228be2dc5f28731ddaffc7475b29bc159c039605" or
        hash.sha256(0, filesize) ==
        "51819d3abdb48a05ed2ba7e15287534e33d27722ddb168c596e3f8bf4d07d090" or
        hash.sha256(0, filesize) ==
        "cc98207885c0531a5cb05692e847f534bf4284c417883075fd4fbeab9c94226c" or
        hash.sha256(0, filesize) ==
        "c0ddb7ae4e3f543ef80c12dcc3a02541b824fc901bc64b4b1063be8cfac93dd4" or
        hash.sha256(0, filesize) ==
        "b660bf63ee9968145578b3dd61490f499ac2a885b026423a0adbe8f849b19f32"
}
