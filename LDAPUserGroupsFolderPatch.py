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

from Products.LDAPUserGroupsFolder.LDAPUserFolder import LDAPUserFolder
from AccessControl.User import domainSpecMatch

#security.declarePrivate('authenticate')
def NTLM_authenticate(self, name, password, request):
    """Authenticate a user from a name and password.

    (Called by validate).

    Returns the user object, or None.
    """
    super = self._emergency_user
    ntlm_user = getattr(request, 'ntml_authenticated_user', None)

    if not name:
        return None

    if super and name == super.getUserName():
        user = super
    else:
        if ntlm_user is not None:
            user = self.getUserById(name)
        else:
            user = self.getUser(name, password)

    if user is not None:
        domains = user.getDomains()
        if domains:
            return (domainSpecMatch(domains, request) and user) or None

    return user


LDAPUserFolder.authenticate = NTLM_authenticate
