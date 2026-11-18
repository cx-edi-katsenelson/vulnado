package com.scalesec.vulnado;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class CowsayTest {

  @Rule
  public TemporaryFolder tmp = new TemporaryFolder();

  // Shell metacharacters must be treated as literal text and never executed.
  private void assertNotExecuted(String payloadTemplate) throws Exception {
    Path marker = tmp.getRoot().toPath().resolve("pwned");
    String payload = payloadTemplate.replace("{MARKER}", marker.toString());

    String result = Cowsay.run(payload);

    assertNotNull(result);
    assertFalse("Injected command was executed", Files.exists(marker));
  }

  @Test
  public void singleQuoteBreakoutIsNotExecuted() throws Exception {
    assertNotExecuted("'; touch {MARKER}; echo '");
  }

  @Test
  public void commandSubstitutionIsNotExecuted() throws Exception {
    assertNotExecuted("$(touch {MARKER})");
  }

  @Test
  public void backtickSubstitutionIsNotExecuted() throws Exception {
    assertNotExecuted("`touch {MARKER}`");
  }

  @Test
  public void pipeAndAndOperatorsAreNotExecuted() throws Exception {
    assertNotExecuted("hi && touch {MARKER} | cat");
  }

  @Test
  public void newlineSeparatedCommandIsNotExecuted() throws Exception {
    assertNotExecuted("hi\ntouch {MARKER}\n");
  }

  @Test
  public void benignInputDoesNotThrow() {
    assertNotNull(Cowsay.run("I love Linux!"));
  }
}
