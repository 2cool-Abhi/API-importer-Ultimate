# API-importer-Ultimate
API Collection Importer - Ultimate Edition is a Burp Suite extension written in Jython (Python 2) that supercharges API security testing workflows. It allows you to import Postman collections directly into Burp Suite, fuzz API endpoints with a custom wordlist, and inject a global Bearer token across every request — all from a single unified tab.

#**Key Features**
**Postman Collection Importer**

Load Postman v2/v2.1 JSON collections and environment files. All endpoints are parsed and displayed in a searchable, sortable table with live request preview.
**Burp Suite Integration**

Send any endpoint to Repeater, Intruder, or the Target Site Map with a single click. Supports bulk operations across the entire collection.
**API Endpoint Fuzzer**

Fuzz a target host with a custom wordlist .txt file. Multi-threaded execution with configurable thread count, status code filtering, and live progress tracking.
**Global Authorization Manager**

Inject a Bearer token into every request (collection importer + fuzzer) globally. Masked password field with show/hide toggle and live ACTIVE/OFF status badge.

#**Requirements**

Burp Suite	Community or Professional	Version 2021.x or later recommended
Jython	2.7.x standalone JAR	Required for running Python extensions in Burp
Java	JDK 8 or later (JDK 11+ recommended)	Bundled with Burp Suite installer
Python	2.7 (via Jython)	Extension uses Python 2 syntax throughout
OS	Windows, macOS, or Linux	Tested on Windows 10/11 and Ubuntu 22.04

#**Setup & Installation**

Open Burp Suite
Go to Extender → Extensions
Add extension
Type = Python
Select API importer Ultimate.py
Make sure Jython is configured in Extender → Options
Add the target domain in Host scope before using this extension, so that you get all the relevant information.
