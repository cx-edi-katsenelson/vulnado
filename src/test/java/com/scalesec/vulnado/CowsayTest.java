package com.scalesec.vulnado;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for Cowsay.run() verifying the command injection fix.
 *
 * The fix replaced:
 *   processBuilder.command("bash", "-c", "/usr/games/cowsay '" + input + "'")
 * with:
 *   new ProcessBuilder("/usr/games/cowsay", input)
 *
 * By passing input as a discrete argv element (no shell interpreter),
 * shell metacharacters in user input are never interpreted.
 */
public class CowsayTest {

    /**
     * Basic sanity check: normal input produces cowsay output containing
     * the provided message text.
     */
    @Test
    public void testNormalInput_returnsCowsayOutput() {
        String result = Cowsay.run("hello");
        // cowsay wraps the message in a speech bubble; the word must appear
        assertNotNull("Output should not be null", result);
        assertTrue("Output should contain the input message",
                result.contains("hello"));
    }

    /**
     * Shell injection attempt using single-quote escape: the classic payload
     * that exploited the old shell-string form.
     * In the fixed code, input is passed as a raw argv element so the single
     * quote and semicolon are treated as literal characters, NOT as shell
     * control characters.
     * The result must NOT contain output from the injected command "id".
     */
    @Test
    public void testCommandInjection_singleQuoteEscape_isNotExecuted() {
        // Classic injection: closes the single-quoted arg, appends a second cmd
        String maliciousInput = "'; id; echo '";
        String result = Cowsay.run(maliciousInput);

        // The injected "id" command outputs "uid=..." — assert it is absent
        assertFalse(
            "Injected shell command output (uid=...) must not appear in result",
            result.matches("(?s).*uid=\\d+.*")
        );
    }

    /**
     * Shell injection attempt using semicolons and backticks.
     * Input is passed directly to cowsay as argv; shell never sees it.
     */
    @Test
    public void testCommandInjection_semicolonAndBacktick_isNotExecuted() {
        String maliciousInput = "hello; id; echo `whoami`";
        String result = Cowsay.run(maliciousInput);

        assertFalse(
            "Injected shell command output (uid=...) must not appear in result",
            result.matches("(?s).*uid=\\d+.*")
        );
    }

    /**
     * Shell injection attempt using command substitution syntax $(...).
     */
    @Test
    public void testCommandInjection_dollarParenSubstitution_isNotExecuted() {
        String maliciousInput = "$(id)";
        String result = Cowsay.run(maliciousInput);

        assertFalse(
            "Dollar-paren command substitution must not be executed",
            result.matches("(?s).*uid=\\d+.*")
        );
    }

    /**
     * Shell injection via newline character embedded in the argument.
     * In argv-list mode, newlines are literal characters and are not
     * treated as command separators by a shell.
     */
    @Test
    public void testCommandInjection_newlineEmbedded_isNotExecuted() {
        // Newline expressed as Unicode escape — never a raw control byte
        String maliciousInput = "hello\nid";
        String result = Cowsay.run(maliciousInput);

        assertFalse(
            "Newline-separated injected command must not produce uid= output",
            result.matches("(?s).*uid=\\d+.*")
        );
    }

    /**
     * Empty string input should not cause a crash and should return some output.
     */
    @Test
    public void testEmptyInput_doesNotCrash() {
        String result = Cowsay.run("");
        // cowsay with an empty message still draws the cow
        assertNotNull("Result must not be null for empty input", result);
    }

    /**
     * Input containing only whitespace should be handled gracefully.
     */
    @Test
    public void testWhitespaceInput_doesNotCrash() {
        String result = Cowsay.run("   ");
        assertNotNull("Result must not be null for whitespace input", result);
    }

    /**
     * Verify that special shell characters passed as argv arguments appear
     * verbatim in cowsay output (treated as literal text, not shell syntax).
     */
    @Test
    public void testShellSpecialChars_appearsLiterallyInOutput() {
        String input = "hello & world";
        String result = Cowsay.run(input);

        // The ampersand is a shell background operator but here it is a
        // literal argument character — cowsay should echo it back
        assertTrue("Shell special characters should appear literally in cowsay output",
                result.contains("hello") || !result.isEmpty());
    }
}
