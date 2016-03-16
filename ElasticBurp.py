# ElasticBurp
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

from burp import IBurpExtender, IBurpExtenderCallbacks, IHttpListener, IRequestInfo, IParameter, IContextMenuFactory
from javax.swing import JMenuItem, ProgressMonitor
from elasticsearch_dsl.connections import connections
from elasticsearch_dsl import Index
from doc_HttpRequestResponse import DocHTTPRequestResponse
from datetime import datetime
from email.utils import parsedate_tz, mktime_tz
from tzlocal import get_localzone
import re

tz = get_localzone()
reDateHeader = re.compile("^Date:\s*(.*)$", flags=re.IGNORECASE)

### Config (TODO: move to config tab) ###
ES_host = "localhost"
ES_index = "burp"
Burp_Tools = IBurpExtenderCallbacks.TOOL_PROXY
Burp_onlyResponses = True       # Usually what you want, responses also contain requests
#########################################

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Storing HTTP Requests/Responses into ElasticSearch")
        self.callbacks.registerHttpListener(self)
        self.callbacks.registerContextMenuFactory(self)
        self.out = callbacks.getStdout()

        self.lastTimestamp = None

        res = connections.create_connection(hosts=[ES_host])
        idx = Index(ES_index)
        idx.doc_type(DocHTTPRequestResponse)
        DocHTTPRequestResponse.init()
        try:
            idx.create()
        except:
            pass

    ### IHttpListener ###
    def processHttpMessage(self, tool, isRequest, msg):
        if not tool & Burp_Tools or isRequest and Burp_onlyResponses:
            return

        self.saveToES(msg)

    ### IContextMenuFactory ###
    def createMenuItems(self, invocation):
        menuItems = list()
        selectedMsgs = invocation.getSelectedMessages()
        if selectedMsgs != None and len(selectedMsgs) >= 1:
            menuItems.append(JMenuItem("Add to ElasticSearch Index", actionPerformed=self.genAddToES(selectedMsgs, invocation.getInputEvent().getComponent())))
        return menuItems

    def genAddToES(self, msgs, component):
        def menuAddToES(e):
            progress = ProgressMonitor(component, "Feeding ElasticSearch", "", 0, len(msgs))
            i = 0
            for msg in msgs:
                if not Burp_onlyResponses or msg.getResponse():
                    self.saveToES(msg, timeStampFromResponse=True)
                i += 1
                progress.setProgress(i)
            progress.close()
        return menuAddToES

    ### Interface to ElasticSearch ###
    def saveToES(self, msg, timeStampFromResponse=False):
        httpService = msg.getHttpService()
        doc = DocHTTPRequestResponse(protocol=httpService.getProtocol(), host=httpService.getHost(), port=httpService.getPort())

        request = msg.getRequest()
        response = msg.getResponse()

        if request:
            iRequest = self.helpers.analyzeRequest(msg)
            doc.request.method = iRequest.getMethod()
            doc.request.url = iRequest.getUrl().toString()

            headers = iRequest.getHeaders()
            for header in headers:
                try:
                    doc.add_request_header(header)
                except:
                    doc.request.requestline = header

            parameters = iRequest.getParameters()
            for parameter in parameters:
                ptype = parameter.getType()
                if ptype == IParameter.PARAM_URL:
                    typename = "url"
                elif ptype == IParameter.PARAM_BODY:
                    typename = "body"
                elif ptype == IParameter.PARAM_COOKIE:
                    typename = "cookie"
                elif ptype == IParameter.PARAM_XML:
                    typename = "xml"
                elif ptype == IParameter.PARAM_XML_ATTR:
                    typename = "xmlattr"
                elif ptype == IParameter.PARAM_MULTIPART_ATTR:
                    typename = "multipartattr"
                elif ptype == IParameter.PARAM_JSON:
                    typename = "json"
                else:
                    typename = "unknown"
                
                name = parameter.getName()
                value = parameter.getValue()
                doc.add_request_parameter(typename, name, value)

            ctype = iRequest.getContentType()
            if ctype == IRequestInfo.CONTENT_TYPE_NONE:
                doc.request.content_type = "none"
            elif ctype == IRequestInfo.CONTENT_TYPE_URL_ENCODED:
                doc.request.content_type = "urlencoded"
            elif ctype == IRequestInfo.CONTENT_TYPE_MULTIPART:
                doc.request.content_type = "multipart"
            elif ctype == IRequestInfo.CONTENT_TYPE_XML:
                doc.request.content_type = "xml"
            elif ctype == IRequestInfo.CONTENT_TYPE_JSON:
                doc.request.content_type = "json"
            elif ctype == IRequestInfo.CONTENT_TYPE_AMF:
                doc.request.content_type = "amf"
            else:
                doc.request.content_type = "unknown"

            bodyOffset = iRequest.getBodyOffset()
            doc.request.body = request[bodyOffset:].tostring().decode("ascii", "replace")

        if response:
            iResponse = self.helpers.analyzeResponse(response)

            doc.response.status = iResponse.getStatusCode()
            doc.response.content_type = iResponse.getStatedMimeType()
            doc.response.inferred_content_type = iResponse.getInferredMimeType()

            headers = iResponse.getHeaders()
            dateHeader = None
            for header in headers:
                try:
                    doc.add_response_header(header)
                    match = reDateHeader.match(header)
                    if match:
                        dateHeader = match.group(1)
                except:
                    doc.response.responseline = header

            cookies = iResponse.getCookies()
            for cookie in cookies:
                expCookie = cookie.getExpiration()
                expiration = None
                if expCookie:
                    try:
                        expiration = datetime.fromtimestamp(expCookie.time / 1000)
                    except:
                        pass
                doc.add_response_cookie(cookie.getName(), cookie.getValue(), cookie.getExpiration(), cookie.getPath(), expiration)

            bodyOffset = iResponse.getBodyOffset()
            doc.response.body = response[bodyOffset:].tostring().decode("ascii", "replace")

            if timeStampFromResponse:
                if dateHeader:
                    try:
                        doc.timestamp = datetime.fromtimestamp(mktime_tz(parsedate_tz(dateHeader)), tz) # try to use date from response header "Date"
                        self.lastTimestamp = doc.timestamp
                    except:
                        doc.timestamp = self.lastTimestamp      # fallback: last stored timestamp. Else: now

        doc.save()
