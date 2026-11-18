package com.scalesec.vulnado;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Verifies that User.fetch binds the username as a bound parameter of a
 * PreparedStatement instead of concatenating it into the SQL text.
 * A fake JDBC driver replaces the PostgreSQL driver so no database is needed.
 */
public class UserTest {

  private static final List<Driver> removedDrivers = new ArrayList<>();
  private static FakeDriver fakeDriver;

  // State recorded by the fake JDBC objects
  private static final List<String> preparedSql = new ArrayList<>();
  private static final List<String> plainStatementSql = new ArrayList<>();
  private static final Map<Integer, Object> boundParams = new HashMap<>();
  private static boolean createStatementCalled;
  private static boolean resultHasRow;

  @BeforeClass
  public static void installFakeDriver() throws Exception {
    // Remove real PostgreSQL drivers so the fake one handles jdbc:postgresql URLs
    for (Driver d : Collections.list(DriverManager.getDrivers())) {
      if (d.getClass().getName().startsWith("org.postgresql")) {
        removedDrivers.add(d);
        DriverManager.deregisterDriver(d);
      }
    }
    fakeDriver = new FakeDriver();
    DriverManager.registerDriver(fakeDriver);
  }

  @AfterClass
  public static void restoreDrivers() throws Exception {
    DriverManager.deregisterDriver(fakeDriver);
    for (Driver d : removedDrivers) {
      DriverManager.registerDriver(d);
    }
  }

  @Before
  @After
  public void reset() {
    preparedSql.clear();
    plainStatementSql.clear();
    boundParams.clear();
    createStatementCalled = false;
    resultHasRow = false;
  }

  @Test
  public void fetchUsesParameterizedQuery() {
    User.fetch("alice");

    assertEquals(1, preparedSql.size());
    assertTrue(preparedSql.get(0).contains("username = ?"));
    assertEquals("alice", boundParams.get(1));
  }

  @Test
  public void fetchDoesNotConcatenateMaliciousInputIntoSql() {
    String payload = "' OR '1'='1' --";

    User.fetch(payload);

    // The SQL text must be the constant template; payload only appears as a bound value
    assertEquals(1, preparedSql.size());
    assertTrue(!preparedSql.get(0).contains(payload));
    assertTrue(!preparedSql.get(0).contains("OR '1'='1'"));
    assertEquals(payload, boundParams.get(1));
    // No unparameterized statement may be used
    assertTrue(!createStatementCalled);
    assertTrue(plainStatementSql.isEmpty());
  }

  @Test
  public void fetchHandlesStackedQueryPayloadAsData() {
    String payload = "x'; DROP TABLE users; --";

    User.fetch(payload);

    assertTrue(!preparedSql.get(0).contains("DROP TABLE"));
    assertEquals(payload, boundParams.get(1));
  }

  @Test
  public void fetchReturnsUserWhenRowFound() {
    resultHasRow = true;

    User user = User.fetch("alice");

    assertNotNull(user);
    assertEquals("1", user.id);
    assertEquals("alice", user.username);
    assertEquals("hash", user.hashedPassword);
  }

  @Test
  public void fetchReturnsNullWhenNoRow() {
    assertNull(User.fetch("nobody"));
  }

  // ---------------------------------------------------------------------
  // Fake JDBC implementation built from dynamic proxies
  // ---------------------------------------------------------------------

  private static class FakeDriver implements Driver {
    @Override
    public Connection connect(String url, Properties info) throws SQLException {
      if (!acceptsURL(url)) {
        return null;
      }
      return (Connection) Proxy.newProxyInstance(
          UserTest.class.getClassLoader(), new Class<?>[] {Connection.class}, new ConnectionHandler());
    }

    @Override
    public boolean acceptsURL(String url) {
      return url != null && url.startsWith("jdbc:postgresql:");
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
      return new DriverPropertyInfo[0];
    }

    @Override
    public int getMajorVersion() {
      return 1;
    }

    @Override
    public int getMinorVersion() {
      return 0;
    }

    @Override
    public boolean jdbcCompliant() {
      return false;
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
      throw new SQLFeatureNotSupportedException();
    }
  }

  private static class ConnectionHandler implements InvocationHandler {
    @Override
    public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) {
      switch (method.getName()) {
        case "prepareStatement":
          preparedSql.add((String) args[0]);
          return Proxy.newProxyInstance(
              UserTest.class.getClassLoader(),
              new Class<?>[] {PreparedStatement.class},
              new PreparedStatementHandler());
        case "createStatement":
          createStatementCalled = true;
          return null;
        default:
          return defaultValue(method.getReturnType());
      }
    }
  }

  private static class PreparedStatementHandler implements InvocationHandler {
    @Override
    public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) {
      switch (method.getName()) {
        case "setString":
          boundParams.put((Integer) args[0], args[1]);
          return null;
        case "executeQuery":
          if (args != null && args.length > 0) {
            plainStatementSql.add((String) args[0]);
          }
          return Proxy.newProxyInstance(
              UserTest.class.getClassLoader(),
              new Class<?>[] {ResultSet.class},
              new ResultSetHandler());
        default:
          return defaultValue(method.getReturnType());
      }
    }
  }

  private static class ResultSetHandler implements InvocationHandler {
    private boolean consumed = false;

    @Override
    public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) {
      switch (method.getName()) {
        case "next":
          if (resultHasRow && !consumed) {
            consumed = true;
            return true;
          }
          return false;
        case "getString":
          switch ((String) args[0]) {
            case "user_id":
              return "1";
            case "username":
              return "alice";
            case "password":
              return "hash";
            default:
              return null;
          }
        default:
          return defaultValue(method.getReturnType());
      }
    }
  }

  private static Object defaultValue(Class<?> type) {
    if (type == boolean.class) {
      return false;
    }
    if (type == int.class) {
      return 0;
    }
    if (type == long.class) {
      return 0L;
    }
    return null;
  }
}
