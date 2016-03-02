# WASE - Web Audit Search Engine
# doc_HttpRequestResponse.py: Implementation of the core data structure
# 
# Copyright 2016 Thomas Patzke <thomas@patzke.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from elasticsearch_dsl import DocType, String, Integer, Short, Date, Object, Nested, MetaField
from datetime import datetime
import re

reHeader = re.compile("^(.*?):\s*(.*)$")

def parse_header(header):
    # BUG: erste Zeile auch enthalten
    # TODO: support for multiline headers
    match = reHeader.search(header)
    if match:
        return { 'name': match.group(1), 'value': match.group(2) }
    else:
        raise ValueError("No header matched")

class DocHTTPRequestResponse(DocType):
    class Meta:
        doc_type = 'HTTPRequestResponse'
        all = MetaField(enabld=True)

    timestamp = Date()
    protocol = String()
    host = String()
    port = Integer()
    request = Object(
            properties = {
                'method': String(index='not_analyzed'),
                'url': String(),
                'requestline': String(),
                'content_type': String(),
                'headernames': String(multi=True, index='not_analyzed'),
                'headers': Nested(
                    properties = {
                        'name': String(index='not_analyzed'),
                        'value': String()
                        }
                    ),
                'parameternames': String(multi=True, index='not_analyzed'),
                'parameters': Nested(
                    properties = {
                        'type': String(index='not_analyzed'),
                        'name': String(index='not_analyzed'),
                        'value': String()
                        }
                    ),
                'body': String(include_in_all=False)
                }
            )
    response = Object(
            properties = {
                'status': Short(),
                'responseline': String(),
                'content_type': String(),
                'inferred_content_type': String(),
                'headernames': String(multi=True, index='not_analyzed'),
                'headers': Nested(
                    properties = {
                        'name': String(index='not_analyzed'),
                        'value': String()
                        }
                    ),
                'cookienames': String(multi=True, index='not_analyzed'),
                'cookies': Nested(
                    properties = {
                        'domain': String(),
                        'expiration': Date(),
                        'name': String(index='not_analyzed'),
                        'path': String(),
                        'value': String()
                        }
                    ),
                'body': String(include_in_all=False),
                # TODO: implement the following
                'doctype': String(),
                'frames': String(multi=True)
                }
            )

    def add_request_header(self, header):
        parsed = parse_header(header)
        self.request.headers.append(parsed)
        self.request.headernames.append(parsed['name'])

    def add_response_header(self, header):
        parsed = parse_header(header)
        self.response.headers.append(parsed)
        self.response.headernames.append(parsed['name'])

    def add_request_parameter(self, typename, name, value):
        param = { 'type': typename, 'name': name, 'value': value }
        self.request.parameters.append(param)
        self.request.parameternames.append(param['name'])

    def add_response_cookie(self, name, value, domain=None, path=None, expiration=None):
        cookie = { 'name': name, 'value': value, 'domain': domain, 'path': path, 'expiration': expiration }
        self.response.cookies.append(cookie)
        self.response.cookienames.append(cookie['name'])

    def save(self, **kwargs):
        self.timestamp = datetime.now()                 # TODO: adjust timestamp to current timezone
        return super(DocHTTPRequestResponse, self).save(**kwargs)

