import random
import asyncio
import aiohttp
import string
import re
import colorama
import argparse
import validators

from itertools import groupby
from colorama import Fore

colorama.init()

# logging.basicConfig(format='%(asctime)s %(message)s', datefmt='[%H:%M:%S]')
# log = logging.getLogger()
# log.setLevel(logging.INFO)

globalRequests = 0


def main():
    parser = argparse.ArgumentParser(description="Reflected XSS Scanner")
    parser.add_argument('-l', '--list', type=str, required=True, metavar='',
                        help='List of URLS to scan')
    parser.add_argument('-w', '--worker', type=int, required=False, metavar='', default=20,
    help='Number of workers')
    arguments = parser.parse_args()
    urls = readURLS(arguments.list)
    limit = asyncio.Semaphore(arguments.worker)

    print(Fore.GREEN + "Started Scanning of: " + str(len(urls)) + " URLS")
    asyncio.get_event_loop().run_until_complete(startScan(urls, limit))
    print(globalRequests)

def readURLS(path):
    with open(path, 'r', encoding="utf8") as file:
        URLS = file.readlines()
        URLS = [x.strip() for x in URLS]

    urls_cleaned = filterURLS(URLS)
    return urls_cleaned

def filterURLS(URLS):
    hostAndparams = []  # list['https//www.test.com/search', ['q', 'lang'] ]

    for url in URLS:
        if '?' not in url or not validators.url(url):
            continue

        fragments = url.split('?')
        host = fragments[0]
        parameters = []
        for param in fragments[1].split('&'):
            parameters.append(param.split('=')[0])
        hostAndparams.append([host, parameters])

    hostAndparams = [k for k, v in groupby(sorted(hostAndparams))]
    return hostAndparams

async def startScan(URLS, limit):

    async with aiohttp.ClientSession() as session:
        tasks = []

        for url in URLS:
            tasks.append(asyncio.ensure_future(scanURL(session, url, limit)))

        for completed_result in asyncio.as_completed(tasks):
            result = await completed_result
            saveResults(result)
            
async def scanURL(session, url, limit):
    global globalRequests

    async with limit:
        result = {"finalURL": "", "reflectedPayloads": []}

        Identifier = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=5))
        PAYLOAD = f'{Identifier}"</>{Identifier}'

        host = url[0]
        parameters = "?"
        for index, param in enumerate(url[1]):
            if index == len(url[1]) - 1:
                parameters += param + "=" + PAYLOAD
                break
            parameters += param + "=" + PAYLOAD + "&"

        finalURL = host + parameters
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0'
        }

        try:
            async with session.get(finalURL, headers=headers, ssl=False) as response:
                globalRequests += 1
                status = response.status
                responseType = response.content_type
                html = await response.text(encoding='utf8')
                if not status == 200 or 'application/json' in responseType:
                    return result
                reflectedPayloads = re.findall(f'{Identifier}(.*?){Identifier}', html)

                result["finalURL"] = finalURL
                result["reflectedPayloads"] = reflectedPayloads
                return result
        except:
            return result

def saveResults(result):
    highscore = 0
    charactersReflected = ''
    badChars = ['"', '/', '>', '<']

    for reflected in result["reflectedPayloads"]:
        score = 0
        characters = ''

        for char in badChars:
            if char in reflected:
                score += 1
                characters += char
        
        if score >= highscore:
            highscore = score
            charactersReflected = characters

    if not highscore == 0:
        if highscore <= 2:
             print(
                Fore.CYAN + f'{result["finalURL"]}\t' + Fore.WHITE + f'Reflected Characters: {charactersReflected} Score: {highscore}')
        elif highscore == 3:
             print(
                Fore.YELLOW + f'{result["finalURL"]}\t' + Fore.WHITE + f'Reflected Characters: {charactersReflected} Score: {highscore}')
        else:
             print(
                Fore.RED + f'{result["finalURL"]}\t' + Fore.WHITE + f'Reflected Characters: {charactersReflected} Score: {highscore}')

        with open('reflectedXSS_results.txt', 'a') as file:
            file.write(f'{result["finalURL"]}\tReflected Characters: {charactersReflected} Score: {highscore}\n')

if __name__ == '__main__':
    main()
