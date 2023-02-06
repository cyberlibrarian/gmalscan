# gmalscan
Google Malvertising Scanner

In December 2022 there was a sudden increase in the number of Google 
Advertisements offering downloads of malware by impersonating popular 
software packages. The Google Ads would lead to websites that were
often clones of legimate download sites. 

The diversity of malware being distributed and the number of software
packages being impersonated was substantial.

This python script can help identify malware distributed via
Google Ads. It was inspired by the work of Randy McEoin @rmceoin who
published a bash/python program to do the same thing.

Randy's gmalvertising script used bash and curl to search Google for a list of
popular software packages. It used a python script to parse out the Google Ad
links and compare them against a list of known malicious and known acceptable
links.

This python script (gmalscan) takes a similar but different approach. We use
Selenium Webdriver to control a Chrome web browser. We will search google for
specified search terms (just like Randy's gmalvertising) but we will take
screenshot of the results, and parse out metadata. By using Selenium we can
visit the sites listed in the Google Ads and then parse out any Download links.

A future version of the script will download potential malware and submit it to
public Sandbox APIs.

This script also differs in that it logs all the Ad and metadata in a JSON file.
Why? So that we can later perform automated analysis on how often each malvertising
campaign appears, and which destination URLs and malware are found.

## Installation

This has only been tested on Microsoft Windows. In theory it will work on Linux 
or MacOS however some of the Selenium command may not work across Operating Systems
or Browsers. A future version will be more broadly compatible.

1. You will need to install python 3
2. You will need to pip install selenium
3. You will need to install the Google WebDriver

./gmalscan --help

