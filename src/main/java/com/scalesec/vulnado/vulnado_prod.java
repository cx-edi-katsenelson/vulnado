import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VulnerableExample {

    // Hardcoded credentials (CWE-798)
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "P@ssw0rd123";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/users";

    /**
     * SQL Injection (CWE-89)
     * User input is concatenated directly into the SQL query.
     */
    public ResultSet login(String username, String password) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        Statement stmt = conn.createStatement();

        String query = "SELECT * FROM accounts WHERE user = '" + username
                     + "' AND pass = '" + password + "'";

        return stmt.executeQuery(query); // tainted query
    }

    /**
     * Reflected Cross-Site Scripting / XSS (CWE-79)
     * Untrusted request parameter is written straight to the response.
     */
    public void greet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        response.getWriter().write("<h1>Hello, " + name + "!</h1>"); // unescaped output
    }

    /**
     * OS Command Injection (CWE-78) - FIXED
     * Use the array form of exec() so the OS invokes the binary directly
     * without a shell, preventing injection via shell metacharacters.
     * The host argument is passed as a discrete argv element; the shell
     * never sees it and cannot interpret semicolons, backticks, etc.
     */
    public void ping(String host) throws Exception {
        // Passing a String[] (argv list) bypasses shell interpretation entirely.
        // No shell metacharacters (;, |, &, $(), backtick, etc.) can be injected.
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
        pb.start();
    }
}
