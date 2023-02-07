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
####    - save screenshots of all visited pages
####    - save the performance data from webdriver, and extract history
####    - visite ad links, find download links, and download files
####    - submit downloaded files to sandbox APIs and record links
####    - parse out ad metadata and save to database or CSV
####    - save the outer html for every ad
####    - screenshot the ad's DIV element seperatly from the page
####    - command line args to print different output in different formats
####    - load search specifications with ignore list from a file
####    - extract metdata about IP address and DNS at the time of lookup
####        -- this is good threat intel as domains may fast flux
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

def load_ignore_list_from_file(filename):
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
    parser.add_argument('-s', '--search-terms', dest='search_terms', type=str, help='Google search query')
    parser.add_argument('-i', '--ignore-site', dest='ignore_list', action='append', type=str, help='DNS name to ignore in google ads. Can be specified multiple times.')
    parser.add_argument('-f', '--ignore-file', dest='ignore_list_file', type=str, help='A file with DNS names to ignore in google ads. One hostname per line.')
    parser.add_argument('-x', '--x-position', dest='x_pos', type=int, default=0, help='X-axis position for the browser window.')
    parser.add_argument('-y', '--y-position', dest='y_pos', type=int, default=0, help='Y-axis position for the browsre window.')
    parser.add_argument('-w', '--width', dest="width", type=int, default=1920, help='Width of the browser window.')
    parser.add_argument('-t', '--height', dest="height", type=int, default=1080, help='Height of the browser window.')  
    parser.add_argument('-o', '--output-file', dest="output_file", type=str, help='Save to specified output file in JSON format. Default is named with search terms and a UUID.')
    # TODO: parser.add_argument('-a', '--user-agent', dest="user_agent", type=str, help='User-agent to use instead of the default.')
    # TODO: Support changing the browser used by WebDriver (this requires changing search/xpath/css/Key syntax)
    # TODO: Detect operating system (this requires Key syntax changes maybe)
        
#    parser.add_argument('', type=shelp='')
    args = parser.parse_args()

    if args.ignore_list_file:
        try:
            ignore_list = args.ignore_list + load_ignore_list_from_file(args.ignore_list_file)
        except:
            print(f'Failed to load ignore list from {args.ignore_list_file}.') if args.verbose else None

    ## Configure WebDriver
#    profile.set_preference("general.useragent.override", args.user_agent)
#    driver = webdriver.Chrome(profile)
    options = webdriver.ChromeOptions()
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    driver = webdriver.Chrome(options=options)
    driver.set_window_position(args.x_pos, args.y_pos)
    driver.set_window_size(args.width, args.height)

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
    driver.implicitly_wait(5)

#    text_box = driver.find_element(by=By.CSS_SELECTOR, value='[name="q"]')
#    submit_button = driver.find_element(by=By.TAG_NAME, value="input")
#    text_box.send_keys("bitwarden download")
#    submit_button.click()

    # search google
    driver.find_element(By.NAME, "q").click()
    driver.find_element(By.NAME, "q").send_keys(args.search_terms)
    driver.find_element(By.NAME, "q").send_keys(Keys.ENTER)

    # look for ads anchor tags
    # We need tags that have data-rw attributes; they may optionally have data-pcu tags, we want to record the entire tag though
    ads = driver.find_elements(By.CSS_SELECTOR, 'a[data-rw]')
    
    driver.save_screenshot(f"{session['session']['uuid']}-{session['session']['search_terms']}.png")
    session['session']['search_screenshot'] = f"{session['session']['uuid']}-{session['session']['search_terms']}.png"

    ## Visit every ad in the ad results
    print(f'Ignore list: {ignore_list}') if args.verbose else None

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
        except:
            aspan = None

        if aspan:
            log['alink'] = aspan.get_attribute('innerHTML')
        else:
            alink = None

        if not hostname in ignore_list:
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
                
                # close the tab and return to the original window
                driver.close()
                driver.switch_to.window(driver.window_handles[0])
            
        else:
            # The ad is on our ignore list
            log['ignored'] = True
        
        session['results'].append(log)
    # follow the first unapproved ad url
    driver.quit()

    
    print(json.dumps(session, indent=4)) if args.verbose else None
    if args.output_file:
        output_file = args.output_file
    else:
        output_file = f'{session["session"]["search_terms"]}-{session["session"]["uuid"]}.json'
        
    # save session output to json file
    with open(output_file, "w") as outfile:
        json.dump(session, outfile, indent=4)

if __name__ == "__main__":
    main()
