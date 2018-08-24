# ActiveAntiPhish

# THERE IS A BIG BATCH OF 50 KITS COMING
Currently on upload round 1/5
---

Theory
---
This repo takes advantage of a technique called database saturation. If your organization is successfully phished this tool allows the organization to increase the noise in the signal to noise ratio of the hacker's stolen credentials. This is done by providing the tool with a fake password list, fake username list, proxy list, the phishing page's callback url, and your organizations email domain extension.

It generates hundreds of fake username/password pairs that are injected into the phishing page.

The theory is that the phisher will abandon their database as validating thousands of fake accounts just to find the small amount of valid accounts is very annoying.

Phish Kit Collection
---
This project maintains a collection of active and inactive phish kits that are unredacted. They are encrypted to protect from leechers and to protect the identities of hackers. Please contact me to be vetted for the decryption password.

YARA Rules
---
In the `rules` directory you can find a yara ruleset for the phishkits in this repo as well as a generic rule for detecting phishing page source code (phish kits all use a similar design/coding style).

Advisories
---
You can find current phishing advisories in `ADVISORIES.md`.
