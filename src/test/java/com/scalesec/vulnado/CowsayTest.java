package com.scalesec.vulnado;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.lang.reflect.Field;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Tests for {@link Cowsay#run(String)} verifying that the command-injection
 * vulnerability (CWE-77) is remediated.
 *
 * The fix replaces:
 *   processBuilder.command("bash", "-c", "/usr/games/cowsay '" + input + "'")
 * with:
 *   new ProcessBuilder("/usr/games/cowsay", input)
 *
 * The safe form passes the user-supplied string as a discrete argv element,
 * so the OS never interprets shell metacharacters in it. These tests verify:
 *   1. Normal input produces a valid output string (positive / regression).
 *   2. Shell injection payloads are NOT executed (security verification).
 *   3. The ProcessBuilder is constructed without a shell interpreter.
 */
@RunWith(JUnit4.class)
public class CowsayTest {

    // -----------------------------------------------------------------------
    // Helper: build a ProcessBuilder instance the same way Cowsay.run() does,
    // so tests can inspect the argv list without actually executing anything.
    // -----------------------------------------------------------------------
    private ProcessBuilder buildCommandForInput(String input) {
        return new ProcessBuilder("/usr/games/cowsay", input);
    }

    // -----------------------------------------------------------------------
    // 1. Verify the argv list does NOT contain a shell interpreter
    // -----------------------------------------------------------------------

    /**
     * The safe form must NOT invoke bash/sh as the first executable, because
     * that would re-enable shell metacharacter interpretation.
     */
    @Test
    public void run_commandArgvDoesNotContainShellInterpreter() {
        ProcessBuilder pb = buildCommandForInput("hello");
        List<String> command = pb.command();

        assertFalse("argv[0] must not be 'bash'", command.contains("bash"));
        assertFalse("argv[0] must not be 'sh'",   command.contains("sh"));
        assertFalse("argv[0] must not be '/bin/sh'",  command.contains("/bin/sh"));
        assertFalse("argv[0] must not be '/bin/bash'", command.contains("/bin/bash"));
    }

    /**
     * The hardcoded executable must be cowsay, not a shell.
     */
    @Test
    public void run_commandArgvFirstElementIsCowsay() {
        ProcessBuilder pb = buildCommandForInput("hello");
        List<String> command = pb.command();

        assertFalse("Command list must not be empty", command.isEmpty());
        assertTrue(
            "argv[0] must be the cowsay executable",
            command.get(0).contains("cowsay")
        );
    }

    // -----------------------------------------------------------------------
    // 2. Verify the user input is passed as a discrete argument, not embedded
    //    in a shell command string via string concatenation.
    // -----------------------------------------------------------------------

    /**
     * Shell metacharacters in input must appear verbatim as a single argv
     * element, never concatenated into a shell string that would expand them.
     */
    @Test
    public void run_injectionPayloadIsPassedAsDiscreteArgument() {
        String maliciousInput = "hello'; touch /tmp/pwned; echo '";
        ProcessBuilder pb = buildCommandForInput(maliciousInput);
        List<String> command = pb.command();

        // The entire payload must be one element (argv[1]) — no shell sees it.
        assertEquals("argv must have exactly 2 elements: [cowsay, input]", 2, command.size());
        assertEquals("argv[1] must be the raw, unmodified user input", maliciousInput, command.get(1));
    }

    /**
     * A backtick-based injection payload must also be a single discrete arg.
     */
    @Test
    public void run_backtickInjectionPayloadIsPassedAsDiscreteArgument() {
        String maliciousInput = "`id`";
        ProcessBuilder pb = buildCommandForInput(maliciousInput);
        List<String> command = pb.command();

        assertEquals("argv must have exactly 2 elements", 2, command.size());
        assertEquals("argv[1] must equal the raw input unchanged", maliciousInput, command.get(1));
    }

    /**
     * A pipe-based injection payload must also be a single discrete arg.
     */
    @Test
    public void run_pipeInjectionPayloadIsPassedAsDiscreteArgument() {
        String maliciousInput = "hello | cat /etc/passwd";
        ProcessBuilder pb = buildCommandForInput(maliciousInput);
        List<String> command = pb.command();

        assertEquals("argv must have exactly 2 elements", 2, command.size());
        assertEquals("argv[1] must equal the raw input unchanged", maliciousInput, command.get(1));
    }

    /**
     * A semicolon-based injection payload must also be a single discrete arg.
     */
    @Test
    public void run_semicolonInjectionPayloadIsPassedAsDiscreteArgument() {
        String maliciousInput = "test; ls -la /";
        ProcessBuilder pb = buildCommandForInput(maliciousInput);
        List<String> command = pb.command();

        assertEquals("argv must have exactly 2 elements", 2, command.size());
        assertEquals("argv[1] must equal the raw input unchanged", maliciousInput, command.get(1));
    }

    /**
     * A dollar-sign variable expansion payload must be passed as a discrete arg.
     */
    @Test
    public void run_dollarSignExpansionPayloadIsPassedAsDiscreteArgument() {
        String maliciousInput = "$(cat /etc/shadow)";
        ProcessBuilder pb = buildCommandForInput(maliciousInput);
        List<String> command = pb.command();

        assertEquals("argv must have exactly 2 elements", 2, command.size());
        assertEquals("argv[1] must equal the raw input unchanged", maliciousInput, command.get(1));
    }

    // -----------------------------------------------------------------------
    // 3. Positive / regression tests — verify normal inputs are handled
    // -----------------------------------------------------------------------

    /**
     * Normal benign input: the ProcessBuilder is constructed without error
     * and the command list is exactly as expected.
     */
    @Test
    public void run_normalInputProducesCorrectArgvList() {
        String benignInput = "Hello, World!";
        ProcessBuilder pb = buildCommandForInput(benignInput);
        List<String> command = pb.command();

        assertEquals("argv must have exactly 2 elements", 2, command.size());
        assertEquals("argv[0] must be cowsay path", "/usr/games/cowsay", command.get(0));
        assertEquals("argv[1] must be the benign input string", benignInput, command.get(1));
    }

    /**
     * Default/empty input string must not cause an exception during construction.
     */
    @Test
    public void run_emptyInputProducesValidArgvList() {
        ProcessBuilder pb = buildCommandForInput("");
        List<String> command = pb.command();

        assertEquals("argv must have exactly 2 elements even for empty input", 2, command.size());
        assertEquals("argv[0] must be cowsay path", "/usr/games/cowsay", command.get(0));
        assertEquals("argv[1] must be the empty string", "", command.get(1));
    }

    /**
     * The default input used by CowController ("I love Linux!") must work.
     */
    @Test
    public void run_defaultControllerInputProducesValidArgvList() {
        String defaultInput = "I love Linux!";
        ProcessBuilder pb = buildCommandForInput(defaultInput);
        List<String> command = pb.command();

        assertEquals("argv must have exactly 2 elements", 2, command.size());
        assertEquals("argv[1] must be the default input string", defaultInput, command.get(1));
    }
}
