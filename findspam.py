# -*- coding: utf-8 -*-
# noinspection PyCompatibility

import math
import regex
from difflib import SequenceMatcher
from urllib.parse import urlparse, unquote_plus
from itertools import chain
from collections import Counter
from datetime import datetime
import os.path as path

# noinspection PyPackageRequirements
import tld
# noinspection PyPackageRequirements
from tld.utils import TldDomainNotFound
import requests
import chatcommunicate

from helpers import unique_matches, log
from globalvars import GlobalVars
from blacklists import load_blacklists

def ml_rec_question(s, site, *args):
    try:
        r = requests.get("https://ml.erwaysoftware.com/", { 'body': s})
        prediction = r.json()
        return prediction["prediction"] == "Recommendation request", ''
    except:
        return False, ''

# noinspection PyClassHasNoInit
class FindSpam:
    rules = [
        # Sites in sites[] will be excluded if 'all' == True.  Whitelisted if 'all' == False.
        #
        # Category: Bad keywords
        # The big list of bad keywords, for titles and posts
        # Pattern-matching product name: three keywords in a row at least once, or two in a row at least twice
        {'method': ml_rec_question, 'all': True, 'sites': [], 'reason': "Recommendation request",
         'title': False, 'body': True, 'username': False, 'stripcodeblocks': False, 'body_summary': False,
         'answers': False, 'max_rep': 1000000, 'max_score': 10000},
    ]

    # Toxic content using Perspective
    if GlobalVars.perspective_key:  # don't bother if we don't have a key, since it's expensive
        rules.append({"method": toxic_check, "all": True, "sites": [],
                      "reason": "toxic {} detected", "whole_post": True,
                      "title": False, "body": False, "username": False, "body_summary": False,
                      "stripcodeblocks": False, "max_rep": 101, "max_score": 2})

    @staticmethod
    def test_post(post):
        result = []
        why = {'title': [], 'body': [], 'username': []}
        for rule in FindSpam.rules:
            if 'commented-out' in rule:
                continue
            title_to_check = post.title
            body_to_check = post.body.replace("&nsbp;", "").replace("\xAD", "") \
                                     .replace("\u200B", "").replace("\u200C", "")
            is_regex_check = 'regex' in rule
            check_if_answer = rule.get('answers', True)
            check_if_question = rule.get('questions', True)
            if rule['stripcodeblocks']:
                # use a placeholder to avoid triggering "few unique characters" when most of post is code
                body_to_check = regex.sub("(?s)<pre>.*?</pre>",
                                          u"<pre><code>placeholder for omitted code/код block</pre></code>",
                                          body_to_check)
                body_to_check = regex.sub("(?s)<code>.*?</code>",
                                          u"<pre><code>placeholder for omitted code/код block</pre></code>",
                                          body_to_check)
            if rule['reason'] == 'Phone number detected in {}':
                body_to_check = regex.sub("<img[^>]+>", "", body_to_check)
                body_to_check = regex.sub("<a[^>]+>", "", body_to_check)
            if rule['all'] != (post.post_site in rule['sites']) and post.owner_rep <= rule['max_rep'] and \
                    post.post_score <= rule['max_score']:
                matched_body = None
                compiled_regex = None
                if is_regex_check:
                    compiled_regex = regex.compile(rule['regex'], regex.UNICODE, city=FindSpam.city_list)
                    # using a named list \L in some regexes
                    matched_title = False if post.is_answer else compiled_regex.findall(title_to_check)
                    matched_username = compiled_regex.findall(post.user_name)
                    if (not post.body_is_summary or rule['body_summary']) and \
                            (not post.is_answer or check_if_answer) and \
                            (post.is_answer or check_if_question):
                        matched_body = compiled_regex.findall(body_to_check)
                else:
                    assert 'method' in rule

                    if 'whole_post' in rule and rule['whole_post']:
                        matched_title, matched_username, matched_body, why_post = rule['method'](post)

                        if matched_title:
                            why["title"].append(u"Title - {}".format(why_post))
                            result.append(rule['reason'].replace("{}", "title"))
                        if matched_username:
                            why["username"].append(u"Username - {}".format(why_post))
                            result.append(rule['reason'].replace("{}", "username"))
                        if matched_body:
                            why["body"].append(u"Post - {}".format(why_post))
                            result.append(rule['reason'].replace("{}", "answer" if post.is_answer else "body"))
                    else:
                        matched_title, why_title = rule['method'](title_to_check, post.post_site, post.user_name)
                        if matched_title and rule['title']:
                            why["title"].append(u"Title - {}".format(why_title))
                        matched_username, why_username = rule['method'](post.user_name, post.post_site, post.user_name)
                        if matched_username and rule['username']:
                            why["username"].append(u"Username - {}".format(why_username))
                        if (not post.body_is_summary or rule['body_summary']) and \
                                (not post.is_answer or check_if_answer) and \
                                (post.is_answer or check_if_question):
                            matched_body, why_body = rule['method'](body_to_check, post.post_site, post.user_name)
                            if matched_body and rule['body']:
                                why["body"].append(u"Post - {}".format(why_body))
                if matched_title and rule['title']:
                    why["title"].append(FindSpam.generate_why(compiled_regex, title_to_check, u"Title", is_regex_check))
                    result.append(rule['reason'].replace("{}", "title"))
                if matched_username and rule['username']:
                    why["username"].append(FindSpam.generate_why(compiled_regex, post.user_name, u"Username",
                                                                 is_regex_check))
                    result.append(rule['reason'].replace("{}", "username"))
                if matched_body and rule['body']:
                    why["body"].append(FindSpam.generate_why(compiled_regex, body_to_check, u"Body", is_regex_check))
                    type_of_post = "answer" if post.is_answer else "body"
                    result.append(rule['reason'].replace("{}", type_of_post))
        result = list(set(result))
        result.sort()
        why = "\n".join(chain(filter(None, why["title"]), filter(None, why["body"]),
                              filter(None, why["username"]))).strip()
        return result, why

    @staticmethod
    def generate_why(compiled_regex, matched_text, type_of_text, is_regex_check):
        if is_regex_check:
            matches = compiled_regex.finditer(matched_text)
            why_for_matches = []
            for match in matches:
                span = match.span()
                group = match.group().replace("\n", "")
                why_for_matches.append(u"Position {}-{}: {}".format(span[0] + 1, span[1] + 1, group))
            return type_of_text + u" - " + ", ".join(why_for_matches)
        return ""
