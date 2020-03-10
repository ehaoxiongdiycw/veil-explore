import asyncio
import aiohttp
import chardet
import re
from difflib import SequenceMatcher
import traceback

class AsnycGrab(object):

    def __init__(self, url_list, max_threads, origin_title, origin_page, host_name):
        self.urls = url_list
        self.max_threads = max_threads
        self.origin_title = origin_title
        self.origin_page = origin_page
        # self.host_name = host_name
        self.results = []
        self.headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
            'Host': host_name
        }

    def __parse_results(self, url, html):
        try:
            title = None
            encoding = chardet.detect(html).get('encoding', 'utf-8')
            resp_text = html.decode(encoding)
            match = re.search('<title>(.*?)</title>', resp_text, re.S|re.I)
            if match and len(match.groups()) == 1:
                title = match.group(1).strip()[:80]
                print('[TITLE] {}, site: {}'.format(title, url))
            ratio = SequenceMatcher(None, resp_text, self.origin_page).quick_ratio()
        except Exception as e:
            raise e
        if title == self.origin_title and ratio > 0.9:
            self.results.append(str(url))

    async def get_body(self, url):
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10, headers=self.headers, ssl=False) as response:
                assert response.status == 200
                html = await response.read()
                return response.url, html

    async def get_results(self, url):
        url, html = await self.get_body(url)
        self.__parse_results(url, html)
        return 'Completed'

    async def handle_tasks(self, task_id, work_queue):
        while not work_queue.empty():
            current_url = await work_queue.get()
            try:
                task_status = await self.get_results(current_url)
            except Exception as e:
                print('[Error] {}, {}'.format(current_url, e))
                # traceback.print_exc()

    def eventloop(self):
        q = asyncio.Queue()
        [q.put_nowait(url) for url in self.urls]
        loop = asyncio.get_event_loop()
        tasks = [self.handle_tasks(task_id, q, ) for task_id in range(self.max_threads)]
        loop.run_until_complete(asyncio.wait(tasks))
        loop.close()

if __name__ == '__main__':
    async_example = AsnycGrab([
        'https://www.baidu.com',
        'https://hyvanpuoleiset.fi',
        'http://www.jjwater.com',
        'http://sxbgsq.com',
        'https://dida365.com'
    ], 5)
    async_example.eventloop()
    print(async_example.results)