/*
 * Copyright (c) 2010 Gedial
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package com.gedial.gfrealm;

import java.util.Collections;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import com.sun.enterprise.security.auth.login.PasswordLoginModule;

/**
 *
 * @author Arnaud Rolly
 */
public class GfLoginModule extends PasswordLoginModule {

  /**
   * Class logger.
   */
  private static final Logger LOGGER
      = Logger.getLogger(GfRealm.class.getName());

  /**
   * Performs authentication of user.
   * @throws LoginException On authentication failure
   */
  @Override
  protected final void authenticate() throws LoginException {
    if (!(_currentRealm instanceof GfRealm)) {
      throw new LoginException("Realm not SampleRealm");
    }
    GfRealm gfRealm = (GfRealm) _currentRealm;
    if (!gfRealm.authenticate(_username, _password)) {
      LOGGER.log(Level.INFO, "Failed to authenticate user {0}", _username);
      throw new LoginException("Failed to authenticate " + _username);
    }
    try {
      Enumeration groupNames = gfRealm.getGroupNames(_username);
      Object [] gnArrayObj = Collections.list(groupNames).toArray();
      String [] gnArrayStr = new String [gnArrayObj.length];
      for (int i = 0; i < gnArrayObj.length; i++) {
        gnArrayStr[i] = gnArrayObj[i].toString();
      }
      if (groupNames == null) {
        LOGGER.log(Level.INFO, "Failed to get groups for user {0}", _username);
        throw new LoginException("Failed to get groups");
      }
      commitUserAuthentication(gnArrayStr);
    } catch (InvalidOperationException ex) {
      LOGGER.log(Level.INFO, "Failed to get groups for user {0}", _username);
      throw new LoginException(ex.getMessage());
    } catch (NoSuchUserException ex) {
      LOGGER.log(Level.INFO, "Failed to get groups for user {0}", _username);
      throw new LoginException(ex.getMessage());
    }
  }
}
