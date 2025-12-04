import re
import httpx, uuid
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import html
import json, uuid

def string_to_byte(lst):
    return [ord(num) for num in lst]

authToken = "ub55dc4316dcc3b92c6bac5609bedb42b:aWF0OiAxNzYyNTA3Njk1MTc3Cg==..s2XhgKQAKwpCqwfKA66YVW78ZV0="
LIFF_ID = '2008621645-PpZpgapO' #Don't edit if you don't know.
HOST = "https://legy.line-apps.com"

user_agent_line = 'Line/14.10.0'
user_agent = f'Mozilla/5.0 (Linux; Android 13; SM-A045F Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.6478.133 Mobile Safari/537.36 {user_agent_line}'
Application = 'ANDROID\t14.10.0\tAndroid OS\t13'

client = httpx.Client(http2=True, verify=False)

headers = {
    'user-agent': user_agent,
    'x-lal':'th_TH',
    'x-line-access': authToken,
    'x-line-application': Application,
    'X-Line-Liff-Id':LIFF_ID,
    'x-lpv': '1',
    'Content-Type': 'application/x-thrift'
}
def issueLiffView(gid:str):
    global headers
    """
    Issue LIFF View Token
    :param gid: Group ID to issue LIFF View Token
    :return: JWT Token
    """
    Bytes_liff = [130, 33, 1, 13, 105, 115, 115, 117, 101, 76, 105, 102, 102, 86, 105, 101, 119, 28, 24, 19] + string_to_byte(LIFF_ID)
    Bytes_liff += [28, 44, 24] + string_to_byte(f'!{gid}')
    Bytes_liff += [0, 0, 44, 17, 28, 24] + string_to_byte(f'${uuid.uuid4()}')
    Bytes_liff += [17, 0, 0, 34, 24, 12, 108, 105, 102, 102, 46, 108, 105, 110, 101, 46, 109, 101, 0, 0]
    r = client.post(f'{HOST}/LIFF1', headers=headers, data=bytes(Bytes_liff))
    jwt_re = re.compile(
        b'ey[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+'
    )
    jwts = jwt_re.findall(r.content)
    if not jwts:
        AllowLIFF()
        return
    jwt_token = jwts[1].decode()
    print("\x1b[1;32;40m>> \x1b[1;37mLIFF View Issued\x1b[0m")
    return jwt_token

def AllowLIFF():
    global headers
    """
    Allow LIFF Permission
    """
    Bytes_liff = [130, 33, 1, 13, 105, 115, 115, 117, 101, 76, 105, 102, 102, 86, 105, 101, 119, 28, 24, 19] + string_to_byte(LIFF_ID)
    Bytes_liff += [28, 44, 24] + string_to_byte('!u23ab8d51ab1f3e99b8180ecd48b57ad5')
    Bytes_liff += [0, 0, 44, 17, 28, 24] + string_to_byte(f'${uuid.uuid4()}')
    Bytes_liff += [17, 0, 0, 34, 24, 12, 108, 105, 102, 102, 46, 108, 105, 110, 101, 46, 109, 101, 0, 0]

    r = client.post(f'{HOST}/LIFF1', headers=headers, data=bytes(Bytes_liff))
    jwt_re = re.compile(
        b'ey[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+'
    )
    jwts = jwt_re.findall(r.content)
    if not jwts:
        try:
            decoded_string = r.content.decode('raw_unicode_escape')
            start = decoded_string.find("https://")
            end = decoded_string.find("\x00", start)
            url = decoded_string[start:end]
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            session_string = query_params.get('sessionString', [None])[0]
            headers = {
                'user-agent': user_agent,
                'x-line-access': authToken,
                'x-line-application': Application,
            }
            r = client.get(url, headers=headers)
            print("\x1b[1;32;40m>> \x1b[1;37mAccessing LIFF URL...\x1b[0m")
            soup = BeautifulSoup(r.content, 'html.parser')
            raw_data = soup.find("app")["app-data"]
            decoded_data = html.unescape(raw_data)
            json_data = json.loads(decoded_data)
            csrf = None
            channelId = None
            for field in json_data["slots"]["serverside_field"]:
                if field.get("name") == "__csrf":
                    csrf = field.get("value")
                if field.get("name") == "channelId":
                    channelId = field.get("value")

            cookies = {
                'X-SCGW-CSRF-Token': csrf,
                'sessionString': session_string,
            }
            data = {
                'allPermission': ['P', 'CM', 'OC'],
                'approvedPermission': ['P', 'CM', 'OC'],
                'channelId': channelId,
                '__csrf': csrf,
                'addFriendInAggressiveMode': True,
                'allow': True
            }
            _headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'user-agent': user_agent,
                'X-Requested-With': 'jp.naver.line.android',
                'Upgrade-Insecure-Requests': '1'
            }
            r = client.post('https://access.line.me/oauth2/v2.1/authorize/consent', headers=_headers, data=data, cookies=cookies)
            if r.status_code == 200:
                print("\x1b[1;33;40m>> \x1b[1;32mAllow LIFF Finish\x1b[0m")
            else:
                print("\x1b[1;33;40m>> \x1b[1;31mFailed to Allow LIFF\x1b[0m")
        except Exception as e:
            print("\x1b[1;33;40m>> \x1b[1;31mError Occurred:", str(e), "\x1b[0m")
            return
    else:
        print("\x1b[1;33;40m>> \x1b[1;32mLIFF Already Allowed\x1b[0m")

def send_liff_share_message(title, jsn, access_token):
    """
    Docstring for send_liff_share_message
    
    :param title: Description
    :param jsn: flex json
    :param access_token: JWT Token
    """
    payload = {
        "messages": [
            {
                "type": "flex",
                "altText": title,
                "contents": jsn
            }
        ]
    }
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Line/14.10.0",
        "Authorization": f"Bearer {access_token}",
    }
    resp = client.post(
        "https://api.line.me/message/v3/share",
        headers=headers,
        data=json.dumps(payload)
    )
    print(f"\x1b[1;33;40m[{resp.status_code}] \x1b[1;32;40m>> \x1b[1;37mLIFF Share Message Sent\x1b[0m")
    return resp

if __name__ == "__main__":

    jwt_token = issueLiffView("cef0aabe29d2ea261d866a8c2af25fee1")
    send_liff_share_message("Test LIFF Share Message", {
  "type": "bubble",
  "body": {
    "type": "box",
    "layout": "vertical",
    "contents": [
      {
        "type": "text",
        "text": "Hello, my name is John.",
        "weight": "bold"
      }
    ]
  }
}, jwt_token)

    
