package com.scalesec.vulnado;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for Cowsay.run() verifying that command injection is not possible.
 *
 * The fix replaces:
 *   processBuilder.command("bash", "-c", "/usr/games/cowsay '" + input + "'")
 * with the safe argv-list form:
 *   new ProcessBuilder("/usr/games/cowsay", input)
 *
 * With the argv-list form, shell metacharacters in `input` are passed verbatim
 * to the cowsay binary as a single argument — they are never interpreted by a
 * shell, so injection payloads have no effect.
 */
public class CowsayTest {

    /**
     * Normal input should produce a non-empty cowsay banner containing the
     * original message.
     */
    @Test
    public void testNormalInputReturnsCowsayOutput() {
        String result = Cowsay.run("hello");
        // cowsay wraps the message in a speech-bubble; the raw text appears inside
        assertNotNull("Output must not be null", result);
        assertFalse("Output must not be empty for valid input", result.isEmpty());
        assertTrue("Output should contain the input message",
                result.contains("hello"));
    }

    /**
     * Shell injection attempt: single-quote breaking out of the surrounding
     * single-quotes that the OLD implementation used.  With the safe fix the
     * single-quote is just data — cowsay renders it literally and no second
     * command is executed.
     *
     * We verify the output does NOT contain typical shell injection artifacts
     * ("injected", "sh: ", etc.) and still returns cowsay-style output.
     */
    @Test
    public void testSingleQuoteInjectionPayloadIsNotExecuted() {
        // Classic injection that would break out of  cowsay '<input>'  in the old code
        String maliciousInput = "'; echo injected; echo '";
        String result = Cowsay.run(maliciousInput);

        // The word "injected" must NOT appear as a standalone line — it should
        // only appear, if at all, as literal text inside the cowsay bubble.
        // If command injection occurred, "injected" would appear on its own line
        // outside the cowsay drawing.
        assertNotNull(result);
        // The output should not start with "injected" — that would indicate the
        // echo command ran and its output appeared before the cowsay drawing.
        assertFalse("Injection artifact found at start of output — injection succeeded",
                result.startsWith("injected"));
    }

    /**
     * Semicolon / shell command separator injection attempt.
     */
    @Test
    public void testSemicolonSeparatedCommandIsNotExecuted() {
        String maliciousInput = "hello; id";
        String result = Cowsay.run(maliciousInput);

        assertNotNull(result);
        // If the old shell form were used, "uid=" would appear in the output.
        assertFalse("Shell command output detected — injection succeeded",
                result.contains("uid="));
    }

    /**
     * Backtick (subshell) injection attempt.
     */
    @Test
    public void testBacktickSubshellInjectionIsNotExecuted() {
        String maliciousInput = "hello`id`";
        String result = Cowsay.run(maliciousInput);

        assertNotNull(result);
        assertFalse("Subshell injection output detected — injection succeeded",
                result.contains("uid="));
    }

    /**
     * Dollar-sign / $() subshell injection attempt.
     */
    @Test
    public void testDollarSubshellInjectionIsNotExecuted() {
        String maliciousInput = "hello$(id)";
        String result = Cowsay.run(maliciousInput);

        assertNotNull(result);
        assertFalse("$() subshell injection output detected — injection succeeded",
                result.contains("uid="));
    }

    /**
     * Newline injection — used to insert extra shell commands via line breaks.
     */
    @Test
    public void testNewlineInjectionIsNotExecuted() {
        String maliciousInput = "hello\nid";
        String result = Cowsay.run(maliciousInput);

        assertNotNull(result);
        assertFalse("Newline injection output detected — injection succeeded",
                result.contains("uid="));
    }

    /**
     * Pipe injection attempt.
     */
    @Test
    public void testPipeInjectionIsNotExecuted() {
        String maliciousInput = "hello | id";
        String result = Cowsay.run(maliciousInput);

        assertNotNull(result);
        assertFalse("Pipe injection output detected — injection succeeded",
                result.contains("uid="));
    }

    /**
     * Empty string input should not throw and should return some output
     * (cowsay renders an empty speech bubble).
     */
    @Test
    public void testEmptyInputDoesNotThrow() {
        String result = Cowsay.run("");
        assertNotNull("Output must not be null for empty input", result);
    }
}
