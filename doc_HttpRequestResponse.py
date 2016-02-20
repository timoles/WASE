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

from elasticsearch_dsl import DocType, String, Integer, Short, Date, Object, Nested
from datetime import datetime
import re

reHeader = re.compile("^(.*?):\s*(.*)$")

def parse_header(header):
    match = reHeader.search(header)
    if match:
        return { 'name': match.group(1), 'value': match.group(2) }
    else:
        raise ValueError("No header matched")

class DocHTTPRequestResponse(DocType):
    class Meta:
        doc_type = 'HTTPRequestResponse'

    timestamp = Date()
    protocol = String()
    host = String()
    port = Integer()
    request = Object(
            properties = {
                'method': String(),
                'url': String(),
                'content_type': String(),
                'headers': Nested(
                    properties = {
                        'name': String(),
                        'value': String()
                        }
                    ),
                'parameters': Nested(
                    properties = {
                        'type': String(),
                        'name': String(),
                        'value': String()
                        }
                    ),
                'body': String()
                }
            )
    response = Object(
            properties = {
                'status': Short(),
                'stated_content_type': String(),
                'inferred_content_type': String(),
                'headers': Nested(
                    properties = {
                        'name': String(),
                        'value': String()
                        }
                    ),
                'cookies': Nested(
                    properties = {
                        'domain': String(),
                        'expiration': Date(),
                        'name': String(),
                        'path': String(),
                        'value': String()
                        }
                    ),
                'body': String()
                }
            )

    def add_request_header(self, header):
        parsed = parse_header(header)
        self.request.headers.append(parsed)

    def add_response_header(self, header):
        parsed = parse_header(header)
        self.response.headers.append(parsed)

    def add_request_parameter(self, typename, name, value):
        param = { 'type': typename, 'name': name, 'value': value }
        self.request.parameters.append(param)

    def add_response_cookie(self, name, value, domain=None, path=None, expiration=None):
        cookie = { 'name': name, 'value': value, 'domain': domain, 'path': path, 'expiration': expiration }
        self.response.cookies.append(cookie)

    def save(self, **kwargs):
        self.timestamp = datetime.now()
        return super(DocHTTPRequestResponse, self).save(**kwargs)

