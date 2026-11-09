package com.scalesec.vulnado;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.nio.file.Files;
import org.junit.Test;

public class CowsayTest {

  @Test
  public void benignInputDoesNotFail() {
    assertNotNull(Cowsay.run("Hello"));
  }

  @Test
  public void shellMetacharactersAreNotExecuted() throws Exception {
    File marker = Files.createTempFile("cowsay-injection", ".marker").toFile();
    assertFalse(!marker.delete());

    // Would create the marker file if the input were interpreted by a shell.
    Cowsay.run("'; touch " + marker.getAbsolutePath() + "; echo '");
    Cowsay.run("$(touch " + marker.getAbsolutePath() + ")");
    Cowsay.run("`touch " + marker.getAbsolutePath() + "`");
    Cowsay.run("x | touch " + marker.getAbsolutePath());

    assertFalse("Injected command was executed", marker.exists());
  }

  @Test
  public void optionLikeInputIsTreatedAsData() {
    assertNotNull(Cowsay.run("-f /etc/passwd"));
    assertNotNull(Cowsay.run("--help"));
  }
}
