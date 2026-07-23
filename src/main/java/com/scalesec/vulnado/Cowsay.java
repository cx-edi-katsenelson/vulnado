package com.scalesec.vulnado;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

public class Cowsay {
  public static String run(String input) {
    // Use an argument list instead of a shell string to prevent command injection.
    // ProcessBuilder with a List<String> does not invoke a shell, so shell metacharacters
    // in 'input' are treated as literal data passed to cowsay, not as shell syntax.
    List<String> cmd = Arrays.asList("/usr/games/cowsay", input);
    ProcessBuilder processBuilder = new ProcessBuilder(cmd);

    StringBuilder output = new StringBuilder();

    try {
      Process process = processBuilder.start();
      BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

      String line;
      while ((line = reader.readLine()) != null) {
        output.append(line).append("\n");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return output.toString();
  }
}
