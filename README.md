# ActiveAntiPhish 

Legal
---
Since the new Georgia hack back law is making its way through Congress this repository hopes to take advantage of that. For now this repo is to only be used in jurisdictions where hacking back is legal. 

Theory
---
This repo takes advantage of a technique called database saturation. If your organization is successfully phished this tool allows the organization to decrease the signal to noise ratio of the hacker's stolen credentials. This is done by providing the tool with a fake password list, fake username list, proxy list, the phishing page's callback url, and your organizations email domain extension.

It generates hundreds of fake username/password pairs that are injected into the phishing page.

The theory is that the phisher will abandon their database as validating thousands of fake accounts just to find the small amount of valid accounts is very annoying.

Phish Kit Collection
---
This project maintains a collection of active and inactive phish kits that are unredacted. They are encrypted to protect from leechers. Please see `kits/_PASSWORD.md`.
