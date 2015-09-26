# -*- coding: utf-8 -*-
# Created on 2014/11/13
__author__ = 'restran'

import logging


class BackendSite():
    """
    后端站点的配置信息
    """
    # 是否启用内容替换
    enable_filter = True

    def __init__(self, name, url, netloc, filter_rules):
        self.name = name
        # 完整的URL，如 http://192.168.10.2:9090
        self.url = url
        # 网络地址，如 192.168.10.2:9090
        self.netloc = netloc
        # 过滤规则
        self.filter_rules = filter_rules


class Config(object):
    # 令牌将在多久后过期
    token_expires_seconds = 3600 * 24

    # 站点变换的时候，是否清除旧站点的cookies
    is_to_clear_old_cookies = True
    using_fake_ip = True
    no_cookie = True


class Development(Config):
    DEBUG = True
    # 可以给日志对象设置日志级别，低于该级别的日志消息将会被忽略
    # CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET
    # logging.Logger.level = logging.DEBUG
    LOGGING_LEVEL = logging.DEBUG
    local_netloc = '127.0.0.1:9999'
    local_protocol = 'http'
    local_port = 9999


class Testing(Config):
    TESTING = True
    DEBUG = True
    # logging.Logger.level = logging.DEBUG
    LOGGING_LEVEL = logging.DEBUG
    local_protocol = 'http'
    local_netloc = '127.0.0.1:9999'
    local_port = 9999


class Production(Config):
    """
    生产环境
    """
    DEBUG = False
    logging.Logger.level = logging.WARNING
    # LOGGING_LEVEL = logging.INFO
    local_protocol = 'http'
    local_netloc = '127.0.0.1:9000'
    local_port = 9000


# 设置默认配置为开发环境
# config = Production()
config = Development()

logging.basicConfig(
    level=config.LOGGING_LEVEL,
    format='%(asctime)s %(levelname)s [%(module)s] %(message)s',
)

from subs_filter import SubsFilterRules
# 转发到后端需要代理的网站的地址列表
forward_list = {
    "default": BackendSite('baidu', 'http://ebook.jiani.info/', 'ebook.jiani.info', [
        SubsFilterRules('.', r'http://img3\.douban\.com', '/.site.img3.douban'),
    ]),

}
