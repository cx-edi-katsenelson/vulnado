package com.scalesec.vulnado;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.*;

/**
 * Tests for Cowsay.run() verifying that command injection is no longer possible
 * after replacing the shell-string invocation with a ProcessBuilder argument list.
 *
 * Because the /usr/games/cowsay binary may not be present in every CI environment,
 * each test gracefully handles an empty/null output while still asserting that
 * shell metacharacters are NOT interpreted as commands.
 */
@RunWith(JUnit4.class)
public class CowsayTest {

    /**
     * A benign input should either produce cowsay ASCII art (if binary is present)
     * or an empty string (if binary is absent).  It must never throw an exception
     * and must never return null.
     */
    @Test
    public void run_withBenignInput_returnsStringWithoutException() {
        String result = Cowsay.run("hello");
        assertNotNull("run() must never return null", result);
    }

    /**
     * Shell metacharacters that were previously exploitable via the bash -c invocation
     * must now be passed as literal arguments to cowsay and MUST NOT be executed.
     *
     * Attack pattern: injection via single-quote escape followed by a subcommand.
     * Old code:  bash -c "/usr/games/cowsay 'hello'; <injected>"
     * Fixed code: ProcessBuilder(["/usr/games/cowsay", "hello'; id"])  — no shell involved.
     *
     * We verify by checking that the output does not contain typical shell command output
     * patterns that an injected "id" or "echo" command would produce.
     */
    @Test
    public void run_withSingleQuoteInjectionAttempt_doesNotExecuteInjectedCommand() {
        // Attempt to break out of single quotes and run an injected command
        String maliciousInput = "' ; echo INJECTED_MARKER ; echo '";
        String result = Cowsay.run(maliciousInput);

        assertNotNull("run() must never return null", result);
        // The string "INJECTED_MARKER" should never appear in the output because
        // the shell was never invoked — cowsay receives the whole string as one argument.
        assertFalse(
            "Shell injection via single-quote escape must not execute",
            result.contains("INJECTED_MARKER")
        );
    }

    /**
     * Subshell injection attempt using $() syntax.
     * Without a shell, $(...) is just literal text passed to cowsay.
     */
    @Test
    public void run_withSubshellInjectionAttempt_doesNotExecuteInjectedCommand() {
        String maliciousInput = "$(echo SUBSHELL_INJECTED)";
        String result = Cowsay.run(maliciousInput);

        assertNotNull("run() must never return null", result);
        assertFalse(
            "Subshell injection $(...) must not be evaluated",
            result.contains("SUBSHELL_INJECTED")
        );
    }

    /**
     * Backtick command substitution injection attempt.
     * Without a shell, backticks are literal characters.
     */
    @Test
    public void run_withBacktickInjectionAttempt_doesNotExecuteInjectedCommand() {
        String maliciousInput = "`echo BACKTICK_INJECTED`";
        String result = Cowsay.run(maliciousInput);

        assertNotNull("run() must never return null", result);
        assertFalse(
            "Backtick command substitution must not be evaluated",
            result.contains("BACKTICK_INJECTED")
        );
    }

    /**
     * Semicolon command-chaining injection attempt.
     */
    @Test
    public void run_withSemicolonInjectionAttempt_doesNotExecuteInjectedCommand() {
        String maliciousInput = "hello; echo SEMICOLON_INJECTED";
        String result = Cowsay.run(maliciousInput);

        assertNotNull("run() must never return null", result);
        assertFalse(
            "Semicolon command chaining must not be evaluated",
            result.contains("SEMICOLON_INJECTED")
        );
    }

    /**
     * Pipe injection attempt.
     */
    @Test
    public void run_withPipeInjectionAttempt_doesNotExecuteInjectedCommand() {
        String maliciousInput = "hello | echo PIPE_INJECTED";
        String result = Cowsay.run(maliciousInput);

        assertNotNull("run() must never return null", result);
        assertFalse(
            "Pipe injection must not be evaluated",
            result.contains("PIPE_INJECTED")
        );
    }

    /**
     * Ampersand background-execution injection attempt.
     */
    @Test
    public void run_withAmpersandInjectionAttempt_doesNotExecuteInjectedCommand() {
        String maliciousInput = "hello & echo AMPERSAND_INJECTED";
        String result = Cowsay.run(maliciousInput);

        assertNotNull("run() must never return null", result);
        assertFalse(
            "Ampersand background injection must not be evaluated",
            result.contains("AMPERSAND_INJECTED")
        );
    }

    /**
     * Newline injection attempt (sometimes used to inject shell commands).
     */
    @Test
    public void run_withNewlineInjectionAttempt_doesNotExecuteInjectedCommand() {
        String maliciousInput = "hello\necho NEWLINE_INJECTED";
        String result = Cowsay.run(maliciousInput);

        assertNotNull("run() must never return null", result);
        assertFalse(
            "Newline injection must not be evaluated as a separate shell command",
            result.contains("NEWLINE_INJECTED")
        );
    }

    /**
     * Empty input should return a non-null string without throwing.
     */
    @Test
    public void run_withEmptyInput_returnsWithoutException() {
        String result = Cowsay.run("");
        assertNotNull("run() must never return null for empty input", result);
    }

    /**
     * Null input should not cause a NullPointerException that propagates to callers;
     * the method returns a string (possibly empty) or an empty string after the caught exception.
     */
    @Test
    public void run_withNullInput_doesNotThrowToCallers() {
        try {
            String result = Cowsay.run(null);
            // If it doesn't throw, result must be non-null (empty string from the catch block).
            assertNotNull("run() must not return null even for null input", result);
        } catch (Exception e) {
            fail("run() must not propagate exceptions to callers, but threw: " + e);
        }
    }
}
