# -*- coding: ISO-8859-15 -*-
# Copyright (c) 2004 Nuxeo SARL <http://nuxeo.com>
# Author: Encolpe Degoute <edegoute@nuxeo.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# $Id$

from base64 import encodestring
from urllib import quote, unquote
from DateTime import DateTime
from types import ListType
from Globals import InitializeClass
from AccessControl import ClassSecurityInfo
from ZPublisher.HTTPRequest import HTTPRequest
from Products.CMFCore import CookieCrumbler
from Products.CMFCore.CookieCrumbler import ATTEMPT_NONE, ATTEMPT_RESUME, \
     ATTEMPT_DISABLED, ATTEMPT_LOGIN
from zLOG import LOG, DEBUG


class NTLMCookieCrumbler(CookieCrumbler.CookieCrumbler):
    meta_type = 'NTLM Cookie Crumbler'
    title = 'NTLM Cookie Crumbler'

    security = ClassSecurityInfo()

    # overloaded from CMFCore.CookieCrumbler
    security.declarePrivate('modifyRequest')
    def modifyRequest(self, req, resp):
        if req.__class__ is not HTTPRequest:
            return ATTEMPT_DISABLED

        if (req[ 'REQUEST_METHOD' ] not in ( 'HEAD', 'GET', 'PUT', 'POST' )
            and not req.has_key(self.auth_cookie)):
            return ATTEMPT_DISABLED

        if req.environ.has_key( 'WEBDAV_SOURCE_PORT' ):
            return ATTEMPT_DISABLED

        username = getattr(req, 'ntml_authenticated_user', None)
        if username is not None:
            pass
        elif req.get('QUERY_STRING') != '':
            qs = req.get('QUERY_STRING')
            if '&amp;' in qs:
                split_query = qs.split('&amp;')
                for parameter in split_query:
                    if '&' in parameter:
                        split_query.remove(parameter)
                        for e in parameter.split('&'):
                            split_query.append(e)
            else:
                split_query = qs.split('&')

            for parameter in split_query:
                if parameter.startswith('ntlm_remote_user='):
                    ## XXX len('ntlm_remote_user=') = 17
                    username = parameter[17:]
                    split_query.remove(parameter)

            setattr(req, 'ntml_authenticated_user', username)
            req.environ['QUERY_STRING'] = '&amp;'.join(split_query)
            # cleaning form, at least
            if req.form.get('ntlm_remote_user'):
                del req.form['ntlm_remote_user']

        elif hasattr(req.form, 'ntlm_remote_user'):
            username = req.form.get('ntlm_remote_user')
            setattr(req, 'ntml_authenticated_user', username)
            del req.form['ntlm_remote_user']

        else:
            username = False
            setattr(req, 'ntml_authenticated_user', None)

        if isinstance(username, ListType):
            username = username[0]

        ## condition for: username is not None and username != ''
        if username:
            user = self.acl_users.getUser(username)
            if user is None:
                # The user in the certificate does not exist
                LOG('NTLM Cookie Crumbler', DEBUG, "User '%s' did not exist\n" % username)
                return ATTEMPT_DISABLED

            ##user._getPassword return nothing usable from LDAPUserGroupsFolder
            #password = user._getPassword()
            #ac = encodestring('%s:%s' % (username, password))
            ac = encodestring('%s:%s' % (username, '__'+username+'__'))
            req._auth = 'Basic %s' % ac
            req._cookie_auth = 1
            resp._auth = 1
            return ATTEMPT_RESUME
        elif req._auth and not getattr(req, '_cookie_auth', 0):
            # Using basic auth.
            return ATTEMPT_DISABLED
        else:
            if req.has_key(self.pw_cookie) and req.has_key(self.name_cookie):
                # Attempt to log in and set cookies.
                name = req[self.name_cookie]
                pw = req[self.pw_cookie]
                ac = encodestring('%s:%s' % (name, pw))
                req._auth = 'Basic %s' % ac
                req._cookie_auth = 1
                resp._auth = 1
                if req.get(self.persist_cookie, 0):
                    # Persist the user name (but not the pw or session)
                    expires = (DateTime() + 365).toZone('GMT').rfc822()
                    resp.setCookie(self.name_cookie, name, path='/',
                                   expires=expires)
                else:
                    # Expire the user name
                    resp.expireCookie(self.name_cookie, path='/')
                method = self.getCookieMethod( 'setAuthCookie'
                                             , self.defaultSetAuthCookie )
                method( resp, self.auth_cookie, quote( ac ) )
                self.delRequestVar(req, self.name_cookie)
                self.delRequestVar(req, self.pw_cookie)
                return ATTEMPT_LOGIN
            elif req.has_key(self.auth_cookie):
                # Copy __ac to the auth header.
                ac = unquote(req[self.auth_cookie])
                req._auth = 'Basic %s' % ac
                req._cookie_auth = 1
                resp._auth = 1
                self.delRequestVar(req, self.auth_cookie)
                return ATTEMPT_RESUME
            return ATTEMPT_NONE


InitializeClass(NTLMCookieCrumbler)


manage_addCCForm = CookieCrumbler.manage_addCCForm

def manage_addCC(self, id, REQUEST=None):
    """ interface to add a NTML Cookie Crumbler """
    ob = NTLMCookieCrumbler()
    ob.id = id
    self._setObject(id, ob)
    if REQUEST is not None:
        return self.manage_main(self, REQUEST)
    return id
