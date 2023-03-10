"""Google Software Download Malvertising Scanner

This script will search google ads for malvertisements that offer fake 
software downloads.

Command line arguments can be used to configure sites to ignore in
advertising results.

The output will include:
    - a screenshot of the search results page
    - a list of ads with google ad-specific data parsed out
    - a list of a every webpage visited by clicking the ad
    - screenshots of all webpages visited
    - any downloaded files
"""

#########################################################################
#### TODO:
####    - save webdriver ad elements in serialized (pickle?) format
####    - save the performance data from webdriver, and extract history
####    - download malware files
####    - submit downloaded files to sandbox APIs and record links
####    - screenshot the full page not just the visible portion
####    - command line args to print different output in different formats
####    - extract metdata about IP address and DNS at the time of lookup
####        -- this is good threat intel as domains may fast flux
####        -- looking it up later might not be so helpful, it might change
####    - save full pages from sites linked to by ads as they may 
####      go offline and not be fetchable later.
#########################################################################

import argparse
from datetime import datetime
import json
import time
import uuid

from urllib.parse import urlparse

from selenium import webdriver

from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.wait import WebDriverWait

from selenium.webdriver.chrome.service import Service as ChromeService
#from selenium.webdriver.edge.service import Service as EdgeService
#from selenium.webdriver.firefox.service import Service as FirefoxService
#from selenium.webdriver.ie.service import Service as IEService

def load_list_from_file(filename):
    """ Load a list of hostnames to ignore from a file and return as a list """
    
    with open(filename) as hostnames:
        return [hostname.rstrip() for hostname in hostnames]
    
def main():
    app_version = '11' # I will use single integer version ID

    # The time this session ran
    timestamp = datetime.now().isoformat()

    ## Get command line arguments and configure settings
    parser = argparse.ArgumentParser(
        prog = 'gmalscan.py',
        description=__doc__,
        epilog = '')

    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-s', '--search-terms', dest='search_terms', default='', action='append', type=str, help='Google search query')
    parser.add_argument('-g', '--search-file', dest="search_terms_file", type=str, help='File containing search terms.')
    parser.add_argument('-i', '--ignore-site', dest='ignore_list', default='', action='append', type=str, help='DNS name to ignore in google ads. Can be specified multiple times.')
    parser.add_argument('-f', '--ignore-file', dest='ignore_list_file', type=str, help='A file with DNS names to ignore in google ads. One hostname per line.')
    parser.add_argument('-x', '--x-position', dest='x_pos', type=int, default=0, help='X-axis position for the browser window.')
    parser.add_argument('-y', '--y-position', dest='y_pos', type=int, default=0, help='Y-axis position for the browsre window.')
    parser.add_argument('-w', '--width', dest="width", type=int, default=1920, help='Width of the browser window.')
    parser.add_argument('-t', '--height', dest="height", type=int, default=1080, help='Height of the browser window.')  
    parser.add_argument('-o', '--output-file', dest="output_file", type=str, help='Save to specified output file in JSON format. Default is named with search terms and a UUID.')
    parser.add_argument('-l', '--headless', action='store_true', help='Run in headless mode. Chrome with no visible window.')
    parser.add_argument('--bottom', dest='scan_bottom_ads', action='store_true', default=False, help='Scan Bottom Ad Words. Default is to not scan bottom ads.')
    # TODO: parser.add_argument('-a', '--user-agent', dest="user_agent", type=str, help='User-agent to use instead of the default.')
    # TODO: Support changing the browser used by WebDriver (this requires changing search/xpath/css/Key syntax)
    # TODO: Detect operating system (this requires Key syntax changes maybe)
        
    args = parser.parse_args()

    search_terms = []
    search_terms += args.search_terms
    
    if args.search_terms_file:
        try:
            search_terms += load_list_from_file(args.search_terms_file)
        except:
            print(f'Failed to load search terms from {args.search_terms_file}.') if args.verbose else None

    print(f'Search Terms: {search_terms}') if args.verbose else None

    ignore_list = []
    ignore_list += args.ignore_list

    if args.ignore_list_file:
        try:
            ignore_list += load_list_from_file(args.ignore_list_file)
        except:
            print(f'Failed to load ignore list from {args.ignore_list_file}.') if args.verbose else None

    print(f'Ignore list: {ignore_list}') if args.verbose else None

    ## Configure WebDriver
#    profile.set_preference("general.useragent.override", args.user_agent)
#    driver = webdriver.Chrome(profile)
    options = webdriver.ChromeOptions()
    options.add_experimental_option("excludeSwitches", ["enable-logging"])

    if args.headless:
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        print('Running headless. No window will be displayed. Screenshots will still be taken.') if args.verbose else None

    driver = webdriver.Chrome(options=options)

    if not args.headless:
        driver.set_window_position(args.x_pos, args.y_pos)
        driver.set_window_size(args.width, args.height)

    results = []
    
    for search_term in search_terms:

        # Start logging our session
        session = { 
            'session' : {
                'uuid' :        str(uuid.uuid1()),
                'start_time' :  datetime.now().isoformat(),
                'app_version' : app_version,
                'webdriver' : driver.capabilities,
                'search_terms' : args.search_terms,
                'ignore_list' : ignore_list
            },
            'results' : []
        }

        driver.get("https://www.google.com")

        # Make sure we got the Google search page and not another page
        title = driver.title
        assert title == "Google"
        driver.implicitly_wait(2)

    #    text_box = driver.find_element(by=By.CSS_SELECTOR, value='[name="q"]')
    #    submit_button = driver.find_element(by=By.TAG_NAME, value="input")
    #    text_box.send_keys("bitwarden download")
    #    submit_button.click()

        # search google
        driver.find_element(By.NAME, "q").click()
        driver.find_element(By.NAME, "q").send_keys(search_term)
        driver.find_element(By.NAME, "q").send_keys(Keys.ENTER)

        # screenshot the search results page
        driver.save_screenshot(f"{session['session']['uuid']}-{search_term}.png")
        session['session']['search_screenshot'] = f"{session['session']['uuid']}-{search_term}.png"

        # look for ads anchor tags, separately in top ads and bottom ads
        try:
            ads = driver.find_elements(By.CSS_SELECTOR, 'div[id=taw] div[data-text-ad] :not(div[role=listitem]) > a[data-rw]')
        except:
            top_ads = None

        if args.scan_bottom_ads:
            try:
                bottom_ads = driver.find_elements(By.CSS_SELECTOR, 'div[id=bottomads] div[data-text-ad] :not(div.dcuivd) > a[data-rw]') # these tend to have more download links than top ads
                ads += bottom_ads
                bottom_ad_count = len(bottom_ads)
            except:
                bottom_ads = None
                bottom_ad_count = 0

        print(f'-----------------------------------------')
        print(f'Found {len(ads)} ads for {search_term} ({bottom_ad_count} bottom ads)') if args.verbose else None
        # Exam every ad on the 1st search results page
        for ad in ads:
            log = {}
            # parse destination domain from href
            href = ad.get_attribute('href')
            uri = urlparse(href)
            hostname = uri.netloc

            # Record the ad metadata                    
            log['href'] = href
            log['uri'] = uri
            log['hostname'] = hostname
            log['pcu'] = ad.get_attribute('data-pcu')
            log['rw'] = ad.get_attribute('data-rw')
            log['ved'] = ad.get_attribute('data-ved')
            log['agch'] = ad.get_attribute('data-agch')
            log['agdh'] = ad.get_attribute('data-agdh')
            log['ohtml'] = ad.get_attribute('outerHTML')
            log['ihtlm'] = ad.get_attribute('innerHTML')
            try:
                aspan = ad.find_element(By.CSS_SELECTOR, 'span[data-dtld]')
                dtld = aspan.get_attribute('data-dtld')
                log['dtld'] = dtld
            except:
                aspan = None

            if aspan:
                alink = aspan.get_attribute('innerHTML')
                log['alink'] = alink
            else:
                alink = None
            
            downlinks = []

            if "softonic.com" in hostname:
                log['ignored'] = True

            elif not hostname in ignore_list:
                # Do not investigate ads for hostnames on our ignore list
                log['ignored'] = False

                # Open the link for the ad in a new window
                # Q :   Will this correctly set the referer? Or do I need do something else?
                #       Referer is vital to defeating malvertising destination's evasive tactics
                #       According to a 2009 issue in the Chromium repo, YES referer should be
                #       correctly passed for control-click and right-click-menu "open in new tab"
                # TODO: make this compatible with multiple browsers
                ActionChains(driver).move_to_element(ad).key_down(Keys.CONTROL).click(ad).key_up(Keys.CONTROL).perform()

                # switch focus to the new tab
                try:
                    driver.switch_to.window(driver.window_handles[1])
                    time.sleep(1) if args.verbose else None
                    switch_to_tab = True
                except:
                    print("Switching to the new tab failed. Switching back to main window to continue.") if args.verbose else None
                    switch_to_tab = False

                if switch_to_tab:
                    driver.save_screenshot(f"{session['session']['uuid']}-{hostname}.png")
                    log['screenshot'] = f"{session['session']['uuid']}-{hostname}.png"

                    # Search the page for download links
                    # TODO: make this compatible with multiple browsers
                    downloads = driver.find_elements(By.XPATH, '//a[contains(translate(., "DOWNLAD", "downlad"), "download")]')
                    downlinks = []
                    for download in downloads:
                        # log each download link
                        downlink = {}
                        downlink['ohtml'] = download.get_attribute('outerHTML')
                        downlink['ihtml'] = download.get_attribute('innerHTML')
                        downlink['href'] = download.get_attribute('href')
                        downlinks.append(downlink)

                    log['downlinks'] = downlinks
                    # close the tab and return to the original window
                    driver.close()
                    driver.switch_to.window(driver.window_handles[0])
                
            else:
                # The ad is on our ignore list
                log['ignored'] = True
            
            if log['ignored']:
                ignored='Ignored'
            else:
                ignored='Visited'

            if len(downlinks):
                downhref = downlinks[0]['href']
            else:
                downhref = 'None'

            print(f"{search_term}, {hostname}, {dtld}, {href}, {ignored}, {downhref}") if args.verbose else None

            session['results'].append(log)

        results.append(session)
        
        # follow the first unapproved ad url
    driver.quit()
    
    #print(json.dumps(results, indent=4)) if args.verbose else None
    if args.output_file:
        output_file = args.output_file
    else:
        output_file = f'output.json'
        
    # save session output to json file
    with open(output_file, "w") as outfile:
        json.dump(session, outfile, indent=4)

if __name__ == "__main__":
    main()
