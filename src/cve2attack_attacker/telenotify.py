
import requests

from secret import TELEGRAM_BOT_TOKEN, RECEIVER_CHAT_ID


IS_ENABLED = len(TELEGRAM_BOT_TOKEN) > 0 and len(RECEIVER_CHAT_ID) > 0
print(f'Is Telegram notify module enabled? {str(IS_ENABLED)}')


def send_text(text: str) -> bool:
    if IS_ENABLED:
        req = requests.post(f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage',
                      data={'chat_id': RECEIVER_CHAT_ID, 'text': text})

        return req.status_code == 200

    else:
        return False
