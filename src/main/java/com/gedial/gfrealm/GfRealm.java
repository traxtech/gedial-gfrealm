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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Enumeration;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Properties;
import javax.naming.NamingException;
import javax.sql.DataSource;
import com.sun.enterprise.connectors.ConnectorRuntime;
import com.sun.enterprise.security.auth.realm.IASRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import org.jasypt.util.password.StrongPasswordEncryptor;

/**
 * JDBC realm for Glassfishv3 that uses Jasypt.
 * @author Arnaud Rolly
 */
public class GfRealm extends IASRealm {

  /**
   * Class logger.
   */
  private static final Logger LOGGER
      = Logger.getLogger(GfRealm.class.getName());
  /**
   * Name of the property to configure the JAAS context name.
   */
  private static final String PARAM_JAAS_CONTEXT = "jaas-context";
  /**
   * Name of the property to configure the SQL datasource.
   */
  private static final String PARAM_SQL_JNDI = "sql-jndi";
  /**
   * Name of the property to configure the SQL query that gets a user password.
   */
  private static final String PARAM_SQL_PASSWORD = "sql-password";
  /**
   * Name of the property to configure the SQL query that gets a user's groups.
   */
  private static final String PARAM_SQL_GROUPS = "sql-groups";
  /**
   * Value of the property to configure the JAAS context name.
   */
  private String propJaasContext;
  /**
   * Value of the property to configure the SQL datasource.
   */
  private String propSqlJndi;
  /**
   * Value of the property to configure the SQL query that gets a user password.
   */
  private String propSqlPassword;
  /**
   * Value of the property to configure the SQL query that gets a user's groups.
   */
  private String propSqlGroups;

  @Override
  public void init(final Properties properties)
      throws BadRealmException, NoSuchRealmException {
    LOGGER.log(Level.INFO, "GfRealm : Init starting");
    propJaasContext = activateProperty(properties, PARAM_JAAS_CONTEXT);
    setProperty(PARAM_JAAS_CONTEXT, propJaasContext);
    propSqlJndi = activateProperty(properties, PARAM_SQL_JNDI);
    propSqlPassword = activateProperty(properties, PARAM_SQL_PASSWORD);
    propSqlGroups = activateProperty(properties, PARAM_SQL_GROUPS);
    LOGGER.log(Level.INFO, "GfRealm : Init finished");
  }

  @Override
  public String getAuthType() {
    return "GfRealm";
  }

  /**
   *
   * @param user
   * @return List of groups to which user belongs
   * @throws InvalidOperationException
   * @throws NoSuchUserException
   */
  @Override
  public Enumeration getGroupNames(String username)
      throws InvalidOperationException, NoSuchUserException {
    Vector groupNames = new Vector();
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet rs = null;
    try {
      conn = ((DataSource) ConnectorRuntime.getRuntime()
          .lookupNonTxResource(propSqlJndi, false)).getConnection();
      statement = conn.prepareStatement(propSqlGroups);
      statement.setString(1, username);
      LOGGER.log(Level.INFO, "GfRealm: Executing query {0} for user {1}",
          new Object[]{propSqlGroups, username});
      rs = statement.executeQuery();
      int groupsCount = 0;
      while(rs.next()) {
        String groupName = rs.getString(1);
        if(groupName != null) {
          groupNames.add(groupName);
          groupsCount++;
          LOGGER.log(Level.INFO, "GfRealm: Found group {0} for user {1}",
              new Object[]{groupName, username});
        }
        LOGGER.log(Level.INFO, "GfRealm: Found {0} group(s) for user {1}",
            new Object[]{groupsCount, username});
      }
    } catch (NamingException ex) {
      LOGGER.log(Level.SEVERE, null, ex);
    } catch (SQLException ex) {
      LOGGER.log(Level.SEVERE, null, ex);
    } finally {
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException ex) {
          LOGGER.log(Level.SEVERE, null, ex);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException ex) {
          LOGGER.log(Level.SEVERE, null, ex);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException ex) {
          LOGGER.log(Level.SEVERE, null, ex);
        }
      }
    }
    return groupNames.elements();
  }

  /**
   * Authenticates a user.
   * @param username user name
   * @param password User password
   * @return Authentication result
   */
  public boolean authenticate(String username, String password) {
    boolean authenticated = false;
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet rs = null;
    try {
      // Connects to the datastore
      conn = ((DataSource) ConnectorRuntime.getRuntime()
          .lookupNonTxResource(propSqlJndi, false)).getConnection();
      // Executes the Sql query to retreive the user password
      statement = conn.prepareStatement(propSqlPassword);
      statement.setString(1, username);
      LOGGER.log(Level.INFO, "GfRealm: Executing query {0} for user {1}",
          new Object[]{propSqlPassword, username});
      rs = statement.executeQuery();
      // Password found ?
      if(!rs.next()) {
        LOGGER.log(Level.INFO, "GfRealm: Found no password for user {0}",
            username);
        return false;
      }
      LOGGER.log(Level.INFO, "GfRealm: Found one password for user {0}",
          username);
      // Checks the provided password with the encrypted one using
      // Jasypt's StrongPasswordEncryptor
      String encodedPassword = rs.getString(1);
      authenticated = encodedPassword != null
          && new StrongPasswordEncryptor()
          .checkPassword(password, encodedPassword);
      if(authenticated) {
        LOGGER.log(Level.INFO, "GfRealm: Password for user {0} match",
            username);
      } else {
        LOGGER.log(Level.INFO, "GfRealm: Password for user {0}  does not match",
            username);
      }
    } catch (NamingException ex) {
      LOGGER.log(Level.SEVERE, null, ex);
      return false;
    } catch (SQLException ex) {
      LOGGER.log(Level.SEVERE, null, ex);
      return false;
    } finally {
      // JDBC cleanups
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException ex) {
          LOGGER.log(Level.SEVERE, null, ex);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException ex) {
          LOGGER.log(Level.SEVERE, null, ex);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException ex) {
          LOGGER.log(Level.SEVERE, null, ex);
        }
      }
    }
    return authenticated;
  }

  /**
   * Gets a realm configuration property.
   * @param properties Properties store
   * @param propName Property name
   * @return Property value
   * @throws BadRealmException Of the property is not found
   */
  public String activateProperty(Properties properties, String propName)
      throws BadRealmException {
    String propValue = properties.getProperty(propName);
    if (propValue == null) {
      throw new BadRealmException("Property '" + propName + "' not set");
    }
    LOGGER.log(Level.INFO, "GfRealm: {0}={1}",
          new Object[]{propName, propValue});
    return propValue;
  }
}
