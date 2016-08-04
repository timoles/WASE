#!/usr/bin/python3

import argparse
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q, A
import sys

def print_debug(*arglist):
    if args.debug:
        print(file=sys.stderr, *arglist)

### Query Subcommands ###
def query_missingheader(s, headername, methods=None, responsecodes=None, invert=False):
    # main query
    q = Q("match", ** { 'response.headernames': headername })
    if not invert:
        q = ~q
    s.query = q

    # add filters
    ## method
    if methods:
        s = s.filter("terms", ** { 'request.method': methods })
    ## response codes
    if responsecodes:
        for rc in responsecodes:
            rcrange = rc.split("-")
            if len(rcrange) == 2:
                s = s.filter("range", ** { 'response.status': { "gte": int(rcrange[0]), "lte": int(rcrange[1]) } })
            else:
                s = s.filter("term", ** { 'response.status': rc })

    # aggregate
    a = A("terms", field="request.url.raw")
    s.aggs.bucket("urls", a)
    print_debug(s.to_dict())
    return s.execute()

def query_missingparam(s, paramname, invert=False):
    pass

### Main ###
argparser = argparse.ArgumentParser(description="WASE Query Tool")
argparser.add_argument("--server", "-s", action="append", default="localhost", help="ElasticSearch server")
argparser.add_argument("--index", "-i", default="wase-*", help="ElasticSearch index pattern to query")
argparser.add_argument("--fields", "-f", action="append", help="Add fields to output. Prints full result instead of aggregated URLs.")
argparser.add_argument("--debug", "-d", action="store_true", help="Debugging output")
subargparsers = argparser.add_subparsers(title="Query Commands", dest="cmd")

argparser_missingheader = subargparsers.add_parser("missingheader", help="Search for URLs which responses are missing a header")
argparser_missingheader.add_argument("header", help="Name of the header")
argparser_missingheader.add_argument("--invert", "-n", action="store_true", help="Invert result, list all URLs where header is set")
argparser_missingheader.add_argument("--method", "-m", action="append", help="Restrict search to given methods")
argparser_missingheader.add_argument("--responsecode", "-c", action="append", help="Restrict search to responses with the given codes. Can be a single code (e.g. 200) or a range (200-299)")

argparser_missingparam = subargparsers.add_parser("missingparameter", help="Search for URLs where the requests are missing a parameter with the given name")
argparser_missingparam.add_argument("parameter", help="Name of parameter to search")
argparser_missingparam.add_argument("--invert", "-n", action="store_true", help="Invert result, list all URLs where header is set")
argparser_missingparam.add_argument("--method", "-m", action="append", help="Restrict search to given methods")
argparser_missingparam.add_argument("--type", "-t", choices=["url", "body", "cookie", "xml", "xmlattr", "multipartattr", "json", "unknown"], help="Restrict search to given type")
argparser_missingparam.add_argument("--responsecode", "-c", action="append", help="Restrict search to responses with the given codes. Can be a single code (e.g. 200), a range (200-299) or wildcard (2*)")

argparser_all = subargparsers.add_parser("search", help="Make arbitrary queries")
argparser_missingparam.add_argument("query", nargs="*", default=["*"], help="Query string")

args = argparser.parse_args()
print_debug(args)

es = Elasticsearch(args.server)
s = Search(using=es).index(args.index)
r = None

if args.cmd == "missingheader":
    r = query_missingheader(s, args.header, args.method, args.responsecode, args.invert)
elif args.cmd == "missingparam":
    r = query_missingparam(s, args.parameter, args.invert)
else:
    print("This shouldn't happen!")
    sys.exit(1)

if not r:
    print("No matches!")
    sys.exit(0)

if args.fields:
    for d in r:
        print(d['request']['url'])
        for f in args.fields:
            print(f, end=": ")
            fl = f.split(".", 1)
            try:
                if len(fl) == 2:
                    print(d[fl[0]][fl[1]])
                else:
                    print(d[f])
            except KeyError:
                print("-")
        print()
else:
    for d in r.aggregations.urls.buckets:
        print(d['key'])
