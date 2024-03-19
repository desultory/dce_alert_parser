__version__ = "0.1.0"
__author__ = "desultory"

from aiohttp.web import Application, Response, post, run_app
from aiohttp import ClientSession
from dce_alert import DCEAlert


class AlertProxy:
    def __init__(self, target, address='127.0.0.1', port=8080, user=None, password=None):
        self.address = address
        self.port = port
        self.user = user
        self.password = password
        self.target = target

        self.app = Application()
        self.app.add_routes([post('/', self.handle_post)])

    @property
    def auth_key(self):
        from base64 import b64encode
        return b64encode(f'{self.user}:{self.password}'.encode()).decode()

    async def handle_post(self, request):
        from time import time
        if request.headers['Authorization'] != f'Basic {self.auth_key}':
            return Response(text='Unauthorized', status=401)

        alert_payload = await request.text()
        alert = DCEAlert(alert_payload)

        async with ClientSession() as session:
            async with session.post(self.target, data=alert.to_json(),
                                    headers={'Authorization': f'Basic {self.auth_key}',
                                             'Content-Type': 'application/json'}) as response:
                text = await response.text()
                print(f"[{request.remote}: {time()}] {text}")
                return Response(text=text, status=response.status)

    def start(self):
        run_app(self.app, host=self.address, port=self.port)
