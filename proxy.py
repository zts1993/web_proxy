# -*- coding: utf-8 -*-
# Created on 2014/11/13
import random

__author__ = 'restran'

# 导入设置信息
from urlparse import urlparse, urlunparse
import re
import logging

import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.httpclient
from tornado.web import HTTPError, asynchronous
from tornado.httpclient import HTTPRequest
from tornado.options import define, options

from subs_filter import SubsFilter
from settings import config, forward_list

logger = logging.getLogger(__name__)

try:
    from tornado.curl_httpclient import CurlAsyncHTTPClient as AsyncHTTPClient
except ImportError:
    from tornado.simple_httpclient import SimpleAsyncHTTPClient as AsyncHTTPClient

define("port", default=config.local_port, help="run on the given port", type=int)


class ProxyHandler(tornado.web.RequestHandler):
    """
    """

    def _rewrite_location(self, url):
        """
        重写headers的location url
        :param url:
        :return:
        """
        # logger.debug(u"重写Location %s " % url)

        url_parsed = urlparse(url)
        netloc = url_parsed.netloc
        scheme = url_parsed.scheme
        path = url_parsed.path

        # 检查跳转的地址是后端哪个网站
        is_exist = False
        for site in forward_list.values():
            if site.netloc == netloc:
                is_exist = True
                break

        if is_exist:
            scheme = config.local_protocol
            netloc = config.local_netloc
            # 地址是后端网站，需要添加站点标识
            path = url_parsed.path

        # scheme, netloc, path, params, query, fragment
        return urlunparse((scheme, netloc, path,
                           url_parsed.params, url_parsed.query, url_parsed.fragment))

    def _parse_site(self, uri):
        self._site_name = "default"

        forward_site = forward_list.get(self._site_name, None)
        if forward_site is None:
            return False, None, None
        else:
            url = "%s%s" % (forward_site.url, uri)

            self._backend_site = forward_site
            return True, url, forward_site.netloc

    @asynchronous
    def get(self):
        self._do_fetch('GET')

    @staticmethod
    def _get_fake_ip():
        ip_pool = ["218", "218", "22", "66", "218", "218", "129", "54", "202", "204", "70", "62", "67", "59", "61",
                   "69", "222", "221", "100", "3", "53", "60", "40", "218", "217", "62", "63", "64", "199", "62", "122",
                   "211"]
        face_ip = random.choice(ip_pool) + "." + random.choice(ip_pool) + "." + random.choice(
            ip_pool) + "." + random.choice(ip_pool)
        return face_ip

    def _do_fetch(self, method):
        uri = self.request.uri
        # 解析是哪个站点
        result, url, host = self._parse_site(uri)
        self._backend_url = url  # 后端站点
        # 未找到站点
        if not result:
            raise HTTPError(404)

        logger.debug(u'请求的后端网站 %s' % url)

        headers = dict(self.request.headers)
        # 更新host字段为后端访问网站的host
        headers['Host'] = host

        if config.using_fake_ip:
            fake_ip = self._get_fake_ip()
            headers['CLIENT-IP'] = fake_ip
            headers['X-FORWARDED-FOR'] = fake_ip

        if config.no_cookie:
            headers['Cookie'] = ""

        if 'Authorization' in headers:
            auth_header_value = headers['Authorization']
            m = re.match('(NTLM [A-Za-z0-9+\-/=]+)', auth_header_value)
            if m:
                if len(auth_header_value) < 100:
                    pass
                else:
                    # todo 解析ntlm Authorization数据，修改IP
                    pass

        logger.debug(u'修改后的 headers %s' % headers)

        try:
            if method == 'POST':
                body = self.request.body
            else:
                body = None

            AsyncHTTPClient().fetch(
                HTTPRequest(url=url,
                            method=method,
                            body=body,
                            headers=headers,
                            follow_redirects=False),
                self._on_proxy)
        except tornado.httpclient.HTTPError, x:
            if hasattr(x, "response") and x.response:
                self._on_proxy(x.response)
            else:
                logger.error("Tornado signalled HTTPError %s", x)

    @asynchronous
    def post(self):
        self._do_fetch('POST')

    def _on_proxy(self, response):

        if response.error and not isinstance(response.error,
                                             tornado.httpclient.HTTPError):
            # todo 友好的请求出错提示和跳转回主页或返回上页的提示
            logger.info("proxy failed for %s, error: %s" % (self._backend_url, response.error))
            raise HTTPError(500)
        else:
            try:
                # 有可能会出现 unknown status code
                self.set_status(response.code)
            except ValueError:
                logger.info("proxy failed for %s, error: unknown status code,  %s" % (self._backend_url, response.code))
                raise HTTPError(500)

            logger.debug(u"后端站点响应 headers: %s" % response.headers)

            for (k, v) in response.headers.get_all():
                if k == 'Server':
                    pass
                elif k == 'Transfer-Encoding':
                    if v == 'chunked':
                        # 如果设置了分块传输编码，但是实际上代理这边已经完整接收数据
                        # 到了浏览器端会导致(failed)net::ERR_INVALID_CHUNKED_ENCODING
                        pass
                elif k == 'Location':
                    self.set_header('Location', self._rewrite_location(v))
                elif k.lower() == 'content-length':
                    # 代理传输过程如果采用了压缩，会导致remote传递过来的content-length与实际大小不符
                    # 会导致后面self.write(response.body)出现错误
                    # 可以不设置remote headers的content-length
                    # "Tried to write more data than Content-Length")
                    # HTTPOutputError: Tried to write more data than Content-Length
                    pass
                elif k.lower() == 'content-encoding':
                    # 采用什么编码传给请求的客户端是由Server所在的HTTP服务器处理的
                    pass
                elif k == 'Set-Cookie':
                    # Set-Cookie是可以有多个，需要一个个添加，不能覆盖掉旧的
                    self.add_header(k, v)
                elif k == 'Content-Disposition':
                    # todo 下载文件，中文文件名，会有编码问题
                    # 中文文件名采用GB2312编码时会乱码
                    self.set_header(k, v)
                else:
                    self.set_header(k, v)

            body = response.body
            if body:
                if self._backend_site.enable_filter:
                    body = SubsFilter.exec_filter(self.request.uri, body,
                                                  self._backend_site.filter_rules)

                self.write(body)

            logger.info("proxy success for %s" % self._backend_url)
            self.finish()


app = tornado.web.Application([
    (r"/.*", ProxyHandler),
])


def main():
    # 该方法会将根日志的级别设置为INFO
    tornado.options.parse_command_line()
    # 将日志的级别重新设置为LOGGING_LEVEL指定的级别
    logger.setLevel(config.LOGGING_LEVEL)

    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(options.port)

    logger.info('tornado server is running on %s' % options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
